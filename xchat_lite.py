#!/usr/bin/env python3
"""Thin local crypto helper for XChat via X MCP + chatxdk.

Network stays on the X connector MCP. This process only unlocks Juicebox
keys (or loads a saved key) and encrypts/decrypts. Never print PIN, private
keys, or juicebox tokens.

Env:
  CHAT_PIN              Juicebox PIN (secret-request → env; never echo)
  XCHAT_USER_ID         numeric X user id (optional if --user-id)
  XCHAT_KEY_VERSION     public_key_version (optional if --key-version)
  XCHAT_JUICEBOX_JSON   path to juicebox_config JSON file, or inline JSON

CLI:
  --remember-key          # after a PIN unlock, save the private keys in the OS keyring, else in
                          # ~/.config/xchat-grokbot-helper/saved-key.json (mode 600). Later runs
                          # for the same user id and key version skip Juicebox and the PIN.
  unlock-check            # stdout adds key_source (saved | pin) and key_saved
  forget                  # delete the saved key
  decrypt                 # stdin: {"events":[...], "conversation_key_events":[...], "signing_keys":[...]}
                          #         or a bare list of event base64 strings
                          # events: data[].encoded_event strings (or the data[] objects)
                          # signing_keys: get_users_public_keys entries for every sender, as returned
                          # stdout: messages[] with status verified | unencrypted | unverified,
                          #         unverified_senders, skipped_signing_keys, errors
  prepare-keys            # stdin: {"public_keys":[...], "conversation_id"?}
                          # public_keys entries: user_id, public_key (identity), key_version
                          # stdout: add_conversation_keys body fields (+ optional _local_conversation_key)
  encrypt CONV_ID TEXT    # needs conversation key in cache OR pass --from-decrypt/--from-prepare
  session-encrypt         # stdin JSON: warm keys then encrypt in ONE process
                          # {
                          #   "conversation_id": "...",
                          #   "text": "...",
                          #   "events": [...],              # optional: decrypt to warm cache
                          #   "signing_keys": [...],        # with events
                          #   "prepare": {"public_keys":[...], "conversation_id"?}  # optional first-contact
                          # }
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

from chat_xdk import Chat


def _as_dict(obj: Any) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    try:
        return dict(obj)
    except Exception:
        return {}


def _b64(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode()
    return str(v)


def _load_juicebox_config(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise SystemExit("Set --juicebox or XCHAT_JUICEBOX_JSON to a file path or JSON string")
    path = Path(raw)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return raw


def _load_pin() -> str:
    pin = os.environ.get("CHAT_PIN", "").strip()
    if pin:
        return pin
    # Grok Bot secret card store (never print contents)
    for candidate in (
        Path("/home/box/agent-data/box-secrets.json"),
        Path.home() / "agent-data" / "box-secrets.json",
    ):
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            card = data.get("card") or {}
            pin = str(card.get("CHAT_PIN") or "").strip()
            if pin:
                return pin
        except Exception:
            continue
    raise SystemExit("CHAT_PIN is not set (env or box-secrets card)")


_SAVED_KEY_SERVICE = "xchat-grokbot-helper"
_SAVED_KEY_NAME = "saved-key"
_SAVED_KEY_FORMAT = 1
_OS_KEYRINGS = tuple(
    f"keyring.backends.{name}" for name in ("macOS", "Windows", "SecretService", "libsecret", "kwallet")
)


def _key_file() -> Path:
    config = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(config) / _SAVED_KEY_SERVICE / f"{_SAVED_KEY_NAME}.json"


def _keyring() -> Any:
    """The OS keyring backend, or None.

    Other keyring backends are skipped: they can store secrets in plain files
    or prompt for a password.
    """
    try:
        import keyring

        backend = keyring.get_keyring()
        candidates = [*getattr(backend, "backends", []), backend]
    except Exception:
        return None
    return next((b for b in candidates if type(b).__module__ in _OS_KEYRINGS), None)


def _read_saved_key() -> str | None:
    backend = _keyring()
    if backend is not None:
        try:
            saved = backend.get_password(_SAVED_KEY_SERVICE, _SAVED_KEY_NAME)
        except Exception:
            saved = None
        if saved:
            return saved
    try:
        return _key_file().read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None


def _forget_saved_key() -> bool:
    """Delete the saved key from the key file and the OS keyring. True when there was one."""
    forgotten = False
    try:
        _key_file().unlink()
        forgotten = True
    except FileNotFoundError:
        pass
    backend = _keyring()
    if backend is not None and backend.get_password(_SAVED_KEY_SERVICE, _SAVED_KEY_NAME) is not None:
        backend.delete_password(_SAVED_KEY_SERVICE, _SAVED_KEY_NAME)
        forgotten = True
    return forgotten


def _write_saved_key(saved: str) -> None:
    """Store in the OS keyring, or in a mode-600 file in a mode-700 directory when that fails."""
    _forget_saved_key()
    backend = _keyring()
    if backend is not None:
        try:
            backend.set_password(_SAVED_KEY_SERVICE, _SAVED_KEY_NAME, saved)
            return
        except Exception:
            pass
    path = _key_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    # mkstemp creates the file with mode 600.
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(saved)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _save_key(chat: Chat, user_id: str, version: str) -> bool:
    """Save the unlocked private keys for later runs. Warns and returns False when that fails."""
    keys = chat.export_keys()
    try:
        record = {
            "format": _SAVED_KEY_FORMAT,
            "user_id": user_id,
            "key_version": version,
            "private_keys": base64.b64encode(keys).decode(),
        }
        _write_saved_key(json.dumps(record))
        return True
    except Exception as e:
        print(f"Could not save the X Chat key on this computer ({type(e).__name__}).", file=sys.stderr)
        return False
    finally:
        if keys:
            keys[:] = bytes(len(keys))


def _load_saved_key(user_id: str, version: str) -> Chat | None:
    """A Chat holding the key saved for this user id and key version, or None.

    A saved key that is unreadable or was saved for another user id, key
    version or file format also gives None, so the caller unlocks with the PIN.
    """
    saved = _read_saved_key()
    if saved is None:
        return None
    try:
        record = json.loads(saved)
        expected = {"format": _SAVED_KEY_FORMAT, "user_id": user_id, "key_version": version}
        mismatched = [name for name, value in expected.items() if record.get(name) != value]
        if not mismatched:
            chat = Chat()
            chat.import_keys(base64.b64decode(record["private_keys"], validate=True), version=version)
            return chat
        reason = "different " + ", ".join(mismatched)
    except Exception:
        reason = "unreadable"
    print(f"Saved X Chat key not used ({reason}); the Chat PIN is needed.", file=sys.stderr)
    return None


def _open_session(args: argparse.Namespace) -> tuple[Chat, str, dict[str, Any]]:
    """Load the saved key, or unlock Juicebox with the PIN once and save the key on --remember-key."""
    user_id = args.user_id or os.environ.get("XCHAT_USER_ID", "")
    version = str(
        args.key_version
        or os.environ.get("XCHAT_KEY_VERSION", "")
        or "1"
    )
    if not user_id:
        raise SystemExit("Pass --user-id or set XCHAT_USER_ID")

    chat = _load_saved_key(user_id, version)
    if chat is not None:
        key_status = {"key_source": "saved", "key_saved": True}
    else:
        pin = _load_pin()
        juicebox = _load_juicebox_config(
            args.juicebox or os.environ.get("XCHAT_JUICEBOX_JSON", "")
        )
        chat = Chat(juicebox)
        chat.unlock(pin)
        saved = args.remember_key and _save_key(chat, user_id, version)
        key_status = {"key_source": "pin", "key_saved": saved}
    chat.set_identity(user_id, version)
    chat.set_cache_keys(True)
    return chat, user_id, key_status


def _session_from_env(args: argparse.Namespace) -> tuple[Chat, str]:
    chat, user_id, _ = _open_session(args)
    return chat, user_id


def _normalize_conversation_keys(raw: Any) -> dict[str, Any]:
    """SDK may return {keys: {ver: bytes}, latest_version: str} or a flat map."""
    if not isinstance(raw, dict):
        return {}
    if "keys" in raw and isinstance(raw.get("keys"), dict):
        return {
            "keys": {str(k): _b64(v) for k, v in raw["keys"].items()},
            "latest_version": raw.get("latest_version"),
        }
    return {str(k): _b64(v) for k, v in raw.items()}


def _prep_to_add_keys(prep: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "conversation_key_version": str(prep.get("conversation_key_version") or ""),
        "conversation_participant_keys": [
            {
                "user_id": str(pk["user_id"]),
                "encrypted_conversation_key": pk.get("encrypted_key")
                or pk.get("encrypted_conversation_key"),
                "public_key_version": str(pk["public_key_version"]),
            }
            for pk in (prep.get("participant_keys") or [])
        ],
        "action_signatures": [
            {
                "message_id": sig["message_id"],
                "encoded_message_event_detail": sig["encoded_message_event_detail"],
                "message_event_signature": {
                    "signature": sig["signature"],
                    "signature_version": str(sig["signature_version"]),
                    "public_key_version": str(sig["public_key_version"]),
                },
            }
            for sig in (prep.get("action_signatures") or [])
        ],
    }
    if prep.get("base64_encoded_key_rotation"):
        out["base64_encoded_key_rotation"] = prep["base64_encoded_key_rotation"]
    # Local-only hint for same-process encrypt; strip before MCP if you copy by hand
    if prep.get("conversation_key") is not None:
        out["_local_conversation_key_b64"] = _b64(prep["conversation_key"])
    return out


def _encrypt_payload(chat: Chat, conversation_id: str, text: str, **kwargs: Any) -> dict[str, str]:
    payload = chat.encrypt_message(conversation_id, text, **kwargs)
    return {
        "message_id": payload.message_id,
        "encoded_message_create_event": payload.encrypted_content,
        "encoded_message_event_signature": payload.encoded_event_signature,
    }


def _scalar(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace").strip()
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return str(value).strip()
    return ""


def _key_entries(raw: Any, owner: str = "") -> list[tuple[Any, str]]:
    """Flatten signing-key input into (entry, owner user id) pairs.

    Accepts a flat list of entries, the get_users_public_keys response
    ({"data": [...]}), per-user containers ({"user_id": ..., "public_keys": [...]})
    and maps of user id to entries.
    """
    if isinstance(raw, list):
        return [pair for item in raw for pair in _key_entries(item, owner)]
    if not isinstance(raw, dict):
        return [(raw, owner)]
    owner = _scalar(raw.get("user_id")) or _scalar(raw.get("id")) or owner
    for name in ("data", "public_keys"):
        if isinstance(raw.get(name), (list, dict)):
            return _key_entries(raw[name], owner)
    if raw and all(str(k).isdigit() and isinstance(v, (list, dict)) for k, v in raw.items()):
        return [pair for user_id, keys in raw.items() for pair in _key_entries(keys, str(user_id))]
    return [(raw, owner)]


def _signing_key_entry(entry: Any, owner: str) -> tuple[dict[str, str] | None, str, str]:
    """Map one key entry to the SDK signing-key shape: (key or None, user id, skip reason).

    MCP entries name the identity key `public_key` and the signing key
    `signing_public_key`; SDK entries name them `identity_public_key` and
    `public_key`. Backend entries nest both under `public_key_with_metadata`.
    """
    if not isinstance(entry, dict):
        return None, owner, "not an object"
    metadata = entry.get("public_key_with_metadata")
    if isinstance(metadata, dict):
        entry = {
            **entry,
            "public_key": metadata.get("public_key"),
            "public_key_version": entry.get("public_key_version") or metadata.get("version"),
        }
    if isinstance(entry.get("public_key"), dict):
        entry = {**entry, **entry["public_key"]}
    if "identity_public_key" in entry:
        identity, signing = entry.get("identity_public_key"), entry.get("public_key")
    else:
        identity, signing = entry.get("public_key"), entry.get("signing_public_key")
    user_id = _scalar(entry.get("user_id")) or owner
    key = {
        "user_id": user_id,
        "public_key_version": _scalar(entry.get("public_key_version")),
        "public_key": _scalar(signing),
        "identity_public_key": _scalar(identity),
        "identity_public_key_signature": _scalar(entry.get("identity_public_key_signature")),
    }
    labels = {"public_key": "signing key", "identity_public_key": "identity key"}
    missing = [labels.get(name, name) for name, value in key.items() if not value]
    if missing:
        return None, user_id, "missing " + ", ".join(missing)
    return key, user_id, ""


def _binding_verifies(chat: Chat, key: dict[str, str]) -> bool:
    try:
        return bool(
            chat.verify_key_binding(
                key["identity_public_key"], key["public_key"], key["identity_public_key_signature"]
            )
        )
    except Exception:
        return False


def _signing_keys(chat: Chat, raw: Any) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Normalize signing keys, skipping incomplete entries and ones whose identity binding fails."""
    keys: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for entry, owner in _key_entries(raw or []):
        key, user_id, reason = _signing_key_entry(entry, owner)
        if key is not None and not _binding_verifies(chat, key):
            key, reason = None, "identity binding does not verify"
        if key is None:
            skipped.append({"user_id": user_id, "reason": reason})
        elif key not in keys:
            keys.append(key)
    return keys, skipped


_THRIFT_FIXED_FORMATS = {2: ">?", 3: ">b", 4: ">d", 6: ">h", 8: ">i", 10: ">q"}
_THRIFT_STRING, _THRIFT_STRUCT, _THRIFT_MAP, _THRIFT_SET, _THRIFT_LIST = 11, 12, 13, 14, 15


def _thrift_value(buf: bytes, pos: int, ttype: int, depth: int = 0) -> tuple[Any, int]:
    """Read one Thrift binary value at `pos`.

    Structs come back as {field id: value} and strings as bytes.
    """
    if depth > 32:
        raise ValueError("Thrift value nested too deeply")
    if ttype == _THRIFT_STRUCT:
        fields: dict[int, Any] = {}
        while buf[pos] != 0:
            field_type = buf[pos]
            field_id = int.from_bytes(buf[pos + 1 : pos + 3], "big", signed=True)
            fields[field_id], pos = _thrift_value(buf, pos + 3, field_type, depth + 1)
        return fields, pos + 1
    if ttype in (_THRIFT_LIST, _THRIFT_SET):
        item_type, count = buf[pos], int.from_bytes(buf[pos + 1 : pos + 5], "big", signed=True)
        items, pos = [], pos + 5
        for _ in range(count):
            item, pos = _thrift_value(buf, pos, item_type, depth + 1)
            items.append(item)
        return items, pos
    if ttype == _THRIFT_MAP:
        key_type, value_type = buf[pos], buf[pos + 1]
        count = int.from_bytes(buf[pos + 2 : pos + 6], "big", signed=True)
        pos += 6
        for _ in range(count):
            _, pos = _thrift_value(buf, pos, key_type, depth + 1)
            _, pos = _thrift_value(buf, pos, value_type, depth + 1)
        return None, pos
    if ttype in _THRIFT_FIXED_FORMATS:
        fmt = _THRIFT_FIXED_FORMATS[ttype]
        return struct.unpack_from(fmt, buf, pos)[0], pos + struct.calcsize(fmt)
    if ttype != _THRIFT_STRING:
        raise ValueError(f"unknown Thrift type {ttype}")
    size = int.from_bytes(buf[pos : pos + 4], "big", signed=True)
    start, end = pos + 4, pos + 4 + size
    if end < start or end > len(buf):
        raise ValueError("truncated Thrift value")
    return buf[start:end], end


def _is_message_detail(detail: Any) -> bool:
    """True when a MessageEventDetail's first field is a message create."""
    if isinstance(detail, dict) and detail:
        field_id, value = next(iter(detail.items()))
        return field_id == 1 and isinstance(value, dict)
    return False


def _event_info(event_b64: str) -> dict[str, Any] | None:
    """Ids and sender of a base64 message event, or None when it doesn't decode.

    Filled in only for a message that cannot be decrypted, so the placeholder
    can still name it.
    """
    try:
        raw = base64.b64decode(event_b64 + "=" * (-len(event_b64) % 4), validate=True)
        event, _ = _thrift_value(raw, 0, _THRIFT_STRUCT)
    except (ValueError, IndexError, struct.error, binascii.Error):
        return None
    created_at = _scalar(event.get(6))
    return {
        "sequence_id": _scalar(event.get(1)),
        "id": _scalar(event.get(2)),
        "sender_id": _scalar(event.get(3)),
        "conversation_id": _scalar(event.get(4)),
        "created_at_msec": int(created_at) if created_at.isdigit() else None,
        "is_message": _is_message_detail(event.get(7)),
    }


def _event_b64(item: Any) -> str:
    if isinstance(item, dict):
        item = item.get("encoded_event")
    return item if isinstance(item, str) else ""


def _message_text(event: dict[str, Any]) -> str:
    if event.get("type") != "Message":
        return ""
    return str((event.get("content") or {}).get("text") or "")


def _message_status(event: dict[str, Any]) -> str:
    if event.get("type") == "Message" and event.get("key_version") is None:
        return "unencrypted"
    return "verified" if event.get("verified") else "unverified"


def _decrypt(chat: Chat, payload: Any) -> dict[str, Any]:
    """Decrypt every event, whether or not its signature can be verified.

    Each item has a status: verified, unencrypted (a message with no
    conversation key version), or unverified. Text is included whenever
    decryption succeeded, including for an unverified event. Only an event
    that cannot be decrypted at all comes back without text.
    """
    if isinstance(payload, list):
        payload = {"events": payload}
    raw_events = list(payload.get("conversation_key_events") or []) + list(
        payload.get("events") or payload.get("encoded_events") or []
    )
    signing_keys, skipped = _signing_keys(chat, payload.get("signing_keys"))
    if signing_keys:
        chat.set_signing_keys(signing_keys)

    events = [_event_b64(item) for item in raw_events]
    infos = [_event_info(event) if event else None for event in events]
    errors = {str(i): "not a base64 event" for i, event in enumerate(events) if not event}
    indices = [i for i, event in enumerate(events) if event]
    decoded: dict[int, dict[str, Any]] = {}
    conversation_keys: Any = {}
    if indices:
        chat.set_reject_unverified(False)
        try:
            result = chat.decrypt_events([events[i] for i in indices], signing_keys)
        finally:
            chat.set_reject_unverified(True)
        conversation_keys = result.get("conversation_keys")
        batch_errors = result.get("errors") or {}
        by_event: dict[str, list[dict[str, Any]]] = {}
        for item in result.get("messages") or []:
            by_event.setdefault(item.get("original_b64"), []).append(_as_dict(item.get("event")))
        for position, i in enumerate(indices):
            if str(position) in batch_errors:
                errors[str(i)] = batch_errors[str(position)]
            elif by_event.get(events[i]):
                decoded[i] = by_event[events[i]].pop(0)
            else:
                errors[str(i)] = "no decrypt result"

    messages: list[dict[str, Any]] = []
    unverified_senders: set[str] = set()
    for i, event_b64 in enumerate(events):
        event = decoded.get(i)
        if event is not None:
            status = _message_status(event)
            sender = str(event.get("sender_id") or "")
            if status == "unverified" and sender:
                unverified_senders.add(sender)
            messages.append(
                {
                    "event": event,
                    "text": _message_text(event),
                    "original_b64": event_b64,
                    "status": status,
                }
            )
            continue
        info = infos[i] or {}
        if not info.get("is_message"):
            continue
        meta = ("sequence_id", "id", "sender_id", "conversation_id", "created_at_msec")
        messages.append(
            {
                "event": {"type": "Message", **{name: info[name] for name in meta}},
                "text": "",
                "original_b64": event_b64,
                "status": "unverified",
                "error": errors.get(str(i), ""),
            }
        )
    return {
        "messages": messages,
        "conversation_keys": _normalize_conversation_keys(conversation_keys),
        "errors": dict(sorted(errors.items(), key=lambda item: int(item[0]))),
        "unverified_senders": sorted(unverified_senders),
        "skipped_signing_keys": skipped,
    }


def cmd_unlock_check(args: argparse.Namespace) -> None:
    chat, user_id, key_status = _open_session(args)
    print(
        json.dumps(
            {
                "ok": True,
                "unlocked": bool(chat.is_unlocked()),
                "user_id": user_id,
                "has_identity_key": bool(chat.has_identity_key()),
                **key_status,
            }
        )
    )


def cmd_forget(args: argparse.Namespace) -> None:
    print(json.dumps({"ok": True, "forgotten": _forget_saved_key()}))


def cmd_decrypt(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    print(json.dumps(_decrypt(chat, json.load(sys.stdin)), ensure_ascii=False))


def cmd_encrypt(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    kwargs: dict[str, Any] = {}
    if args.conversation_key_b64:
        kwargs["conversation_key"] = base64.b64decode(args.conversation_key_b64)
    if args.conversation_key_version:
        kwargs["conversation_key_version"] = str(args.conversation_key_version)
    try:
        print(json.dumps(_encrypt_payload(chat, args.conversation_id, args.text, **kwargs)))
    except Exception as e:
        raise SystemExit(
            f"encrypt failed: {e}. Warm keys first: decrypt recent events in the same "
            f"process (session-encrypt), or pass --conversation-key-b64 + --conversation-key-version "
            f"from prepare-keys / extract_conversation_keys."
        ) from e


def cmd_prepare_keys(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    body = json.load(sys.stdin)
    public_keys = body.get("public_keys") or []
    conversation_id = body.get("conversation_id")
    prep = chat.prepare_conversation_key_change(
        public_keys, conversation_id=conversation_id
    )
    if not isinstance(prep, dict):
        prep = _as_dict(prep)
    if "participant_keys" in prep:
        print(json.dumps(_prep_to_add_keys(prep)))
        return
    print(json.dumps(prep))


def cmd_session_encrypt(args: argparse.Namespace) -> None:
    """Warm conversation keys then encrypt in one Chat session (preferred for send)."""
    chat, _ = _session_from_env(args)
    body = json.load(sys.stdin)
    conversation_id = body.get("conversation_id") or body.get("id")
    text = body.get("text")
    if not conversation_id or text is None:
        raise SystemExit("stdin needs conversation_id and text")

    # Optional: first-contact / empty thread key init (local only until MCP add_conversation_keys)
    prepare_body = body.get("prepare")
    prepared_add = None
    enc_kwargs: dict[str, Any] = {}
    if prepare_body:
        public_keys = prepare_body.get("public_keys") or []
        prep = chat.prepare_conversation_key_change(
            public_keys,
            conversation_id=prepare_body.get("conversation_id") or conversation_id,
        )
        if not isinstance(prep, dict):
            prep = _as_dict(prep)
        prepared_add = _prep_to_add_keys(prep)
        if prep.get("conversation_key") is not None:
            enc_kwargs["conversation_key"] = (
                prep["conversation_key"]
                if isinstance(prep["conversation_key"], (bytes, bytearray))
                else base64.b64decode(prep["conversation_key"])
            )
        if prep.get("conversation_key_version") is not None:
            enc_kwargs["conversation_key_version"] = str(prep["conversation_key_version"])

    # Optional: decrypt to warm set_cache_keys for existing threads
    decrypt_summary = None
    if body.get("events") or body.get("encoded_events") or body.get("conversation_key_events"):
        result = _decrypt(chat, body)
        decrypt_summary = {
            "message_count": len(result["messages"]),
            "types": [m["event"].get("type") for m in result["messages"][:20]],
            "error_count": len(result["errors"]),
        }

    try:
        send_fields = _encrypt_payload(chat, conversation_id, text, **enc_kwargs)
    except Exception as e:
        raise SystemExit(
            f"session-encrypt failed: {e}. For empty threads, or threads with only "
            f"unencrypted messages, use prepare + MCP add_conversation_keys first. For "
            f"encrypted threads include conversation_key_events + encoded_event list and the "
            f"senders' signing_keys so decrypt can warm keys."
        ) from e

    out: dict[str, Any] = {
        "id": conversation_id,
        **send_fields,
    }
    if prepared_add is not None:
        # Caller must POST add_conversation_keys BEFORE send_chat_message for first contact
        add_for_mcp = {
            k: v for k, v in prepared_add.items() if not k.startswith("_local_")
        }
        out["add_conversation_keys"] = add_for_mcp
        out["needs_add_conversation_keys_before_send"] = True
    if decrypt_summary is not None:
        out["decrypt_summary"] = decrypt_summary
    print(json.dumps(out, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="XChat local crypto helper")
    parser.add_argument("--user-id", default="")
    parser.add_argument("--key-version", default="")
    parser.add_argument(
        "--juicebox",
        default="",
        help="Path to juicebox_config JSON, or inline JSON",
    )
    parser.add_argument(
        "--remember-key",
        action="store_true",
        help="After a PIN unlock, save the private keys on this computer so later runs skip the PIN",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("unlock-check", help="Verify the saved key or PIN unlocks the keys")
    sub.add_parser("forget", help="Delete the key saved by --remember-key")
    sub.add_parser("decrypt", help="Decrypt event blobs from stdin JSON")
    p_enc = sub.add_parser(
        "encrypt",
        help="Encrypt text for send_chat_message (keys must already be warm)",
    )
    p_enc.add_argument("conversation_id")
    p_enc.add_argument("text")
    p_enc.add_argument("--conversation-key-b64", default="")
    p_enc.add_argument("--conversation-key-version", default="")
    sub.add_parser(
        "prepare-keys",
        help="Build add_conversation_keys payload from stdin public_keys",
    )
    sub.add_parser(
        "session-encrypt",
        help="Decrypt/prepare then encrypt in one process (preferred for send)",
    )

    args = parser.parse_args()
    if args.cmd == "unlock-check":
        cmd_unlock_check(args)
    elif args.cmd == "forget":
        cmd_forget(args)
    elif args.cmd == "decrypt":
        cmd_decrypt(args)
    elif args.cmd == "encrypt":
        cmd_encrypt(args)
    elif args.cmd == "prepare-keys":
        cmd_prepare_keys(args)
    elif args.cmd == "session-encrypt":
        cmd_session_encrypt(args)
    else:
        raise SystemExit(f"unknown command: {args.cmd}")


if __name__ == "__main__":
    main()
