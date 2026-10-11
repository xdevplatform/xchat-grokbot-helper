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
                          # stdout: messages[], one per event, with display text and status
                          #         verified | unencrypted | unverified (placeholder text and
                          #         an error when an event can't be decoded),
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
import hmac
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


# conversation_key_version field id for each MessageEventDetail variant that
# carries one: message create, key change, Grok message, pin.
_DETAIL_KEY_VERSION_FIELDS = {1: 101, 3: 1, 15: 5, 17: 3}
# conversation_key_version field id for each GroupChange variant, under a group
# change event (detail variant 4), that carries one: create, title, avatar,
# member add, description.
_GROUP_CHANGE_KEY_VERSION_FIELDS = {1: 5, 2: 2, 3: 2, 5: 6, 14: 2}
_DETAIL_TYPES = {
    1: "Message",
    3: "KeyChange",
    4: "GroupChange",
    5: "Failure",
    6: "Typing",
    7: "MessageDeleted",
    8: "ConversationDeleted",
    9: "SettingsChange",
    10: "GrokSearchResponse",
    11: "EncryptedResendRequest",
    12: "ReadReceipt",
    13: "MarkedUnread",
    14: "MemberDeleted",
    15: "GrokMessage",
    16: "GrokResponse",
    17: "PinMessage",
    18: "UnpinMessage",
    19: "PinKeysUpdate",
}


def _union_variant(union: Any) -> tuple[int | None, dict[int, Any]]:
    """Field id and value of a union's first field, when that field is a struct."""
    if isinstance(union, dict) and union:
        field_id, value = next(iter(union.items()))
        if isinstance(value, dict):
            return field_id, value
    return None, {}


def _detail_key_version(detail: Any) -> str | None:
    """conversation_key_version carried by a MessageEventDetail, or None.

    Only a string field counts, and an empty version still counts as present,
    matching how the X API decides whether an event is encrypted.
    """
    variant, event = _union_variant(detail)
    if variant == 4:
        variant, event = _union_variant(event.get(1))
        field = _GROUP_CHANGE_KEY_VERSION_FIELDS.get(variant)
    else:
        field = _DETAIL_KEY_VERSION_FIELDS.get(variant)
    version = event.get(field)
    return version.decode("utf-8", "replace") if isinstance(version, bytes) else None


def _event_info(event_b64: str) -> dict[str, Any] | None:
    """Ids, sender, type, parsed detail and conversation key version of a base64 message event.

    None when the payload doesn't decode.
    """
    try:
        raw = base64.b64decode(event_b64 + "=" * (-len(event_b64) % 4), validate=True)
        event, _ = _thrift_value(raw, 0, _THRIFT_STRUCT)
    except (ValueError, IndexError, struct.error, binascii.Error):
        return None
    created_at = _scalar(event.get(6))
    variant, _ = _union_variant(event.get(7))
    return {
        "sequence_id": _scalar(event.get(1)),
        "id": _scalar(event.get(2)),
        "sender_id": _scalar(event.get(3)),
        "conversation_id": _scalar(event.get(4)),
        "created_at_msec": int(created_at) if created_at.isdigit() else None,
        "type": _DETAIL_TYPES.get(variant, "Unknown"),
        "detail": event.get(7),
        "key_version": _detail_key_version(event.get(7)),
    }


def _event_b64(item: Any) -> str:
    if isinstance(item, dict):
        item = item.get("encoded_event")
    return item if isinstance(item, str) else ""


def _rotl32(value: int, shift: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _salsa20_rounds(state: list[int]) -> list[int]:
    x = list(state)
    for _ in range(10):
        # A column round, then a row round.
        for a, b, c, d in (
            (0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
            (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14),
        ):
            x[b] ^= _rotl32(x[a] + x[d], 7)
            x[c] ^= _rotl32(x[b] + x[a], 9)
            x[d] ^= _rotl32(x[c] + x[b], 13)
            x[a] ^= _rotl32(x[d] + x[c], 18)
    return x


def _salsa20_state(key: bytes, block: bytes) -> list[int]:
    k, n = struct.unpack("<8I", key), struct.unpack("<4I", block)
    return [0x61707865, *k[:4], 0x3320646E, *n, 0x79622D32, *k[4:], 0x6B206574]


def _xsalsa20_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    # HSalsa20 turns the key and the first 16 nonce bytes into the Salsa20 key.
    x = _salsa20_rounds(_salsa20_state(key, nonce[:16]))
    subkey = struct.pack("<8I", *(x[i] for i in (0, 5, 10, 15, 6, 7, 8, 9)))
    stream = bytearray()
    for counter in range((length + 63) // 64):
        state = _salsa20_state(subkey, nonce[16:] + struct.pack("<Q", counter))
        rounds = _salsa20_rounds(state)
        stream += struct.pack("<16I", *((a + b) & 0xFFFFFFFF for a, b in zip(rounds, state)))
    return bytes(stream[:length])


def _poly1305(key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    h, p = 0, (1 << 130) - 5
    for i in range(0, len(message), 16):
        h = (h + int.from_bytes(message[i : i + 16] + b"\x01", "little")) * r % p
    return ((h + int.from_bytes(key[16:], "little")) % (1 << 128)).to_bytes(16, "little")


def _open_box(key: bytes, box: bytes) -> bytes | None:
    """Open an XSalsa20-Poly1305 box laid out as nonce (24), tag (16), ciphertext.

    Message contents are binary Thrift, which Chat.decrypt() can't return
    because it decodes the plaintext as UTF-8. None when the tag doesn't verify.
    """
    if len(key) != 32 or len(box) < 40:
        return None
    nonce, tag, ciphertext = box[:24], box[24:40], box[40:]
    stream = _xsalsa20_stream(key, nonce, 32 + len(ciphertext))
    if not hmac.compare_digest(_poly1305(stream[:32], ciphertext), tag):
        return None
    return bytes(c ^ k for c, k in zip(ciphertext, stream[32:]))


_MEDIA_TYPES = {1: "image", 2: "gif", 3: "video", 4: "audio", 5: "file", 6: "svg"}
_MEDIA_LABELS = {"image": "photo", "gif": "GIF", "video": "video", "audio": "audio", "svg": "image"}
_ATTACHMENT_TYPES = {
    1: "Media",
    2: "Post",
    3: "Url",
    4: "UnifiedCard",
    5: "Money",
    6: "Jetfuel",
    7: "PaymentReceipt",
    8: "BotMessage",
}
# Field ids of the labeled MessageAttachment variants, keyed by attachment field name.
_ATTACHMENT_FIELDS = {
    1: {"filename": 6},
    2: {"rest_id": 1, "post_url": 2},
    3: {"url": 1},
    4: {"url": 1},
    5: {"fallback_text": 1},
}
_ATTACHMENT_LABELS = {
    "Jetfuel": "[interactive card]",
    "PaymentReceipt": "[payment receipt]",
    "BotMessage": "[bot message]",
}


def _attachment_from_thrift(attachment: Any) -> dict[str, Any]:
    """A MessageAttachment union in the SDK's flattened attachment shape."""
    variant, fields = _union_variant(attachment)
    names = _ATTACHMENT_FIELDS.get(variant, {})
    info: dict[str, Any] = {name: _scalar(fields.get(field_id)) for name, field_id in names.items()}
    info["attachment_type"] = _ATTACHMENT_TYPES.get(variant, "Unknown")
    if variant == 1:
        info["media_type"] = _MEDIA_TYPES.get(fields.get(3))
    return info


def _attachment_label(attachment: dict[str, Any], text: str) -> str:
    """Label such as "[photo]" for one attachment, or "" for a link the text already shows."""
    kind = attachment.get("attachment_type")
    if kind == "Media":
        media = attachment.get("media_type")
        if media == "file":
            return f"[file: {attachment['filename']}]" if attachment.get("filename") else "[file]"
        return f"[{_MEDIA_LABELS.get(media, 'media')}]"
    if kind == "Post":
        post = attachment.get("post_url") or attachment.get("rest_id")
        return f"[post: {post}]" if post else "[post]"
    if kind in ("Url", "UnifiedCard"):
        url = attachment.get("url") or ""
        if url and url in text:
            return ""
        return f"[link: {url}]" if url else "[link]"
    if kind == "Money":
        return f"[payment: {attachment['fallback_text']}]" if attachment.get("fallback_text") else "[payment]"
    return _ATTACHMENT_LABELS.get(kind, "[attachment]")


def _with_labels(text: str, attachments: list[dict[str, Any]]) -> str:
    """Text after one label per attachment, such as "[photo] caption"."""
    labels = [label for label in (_attachment_label(a, text) for a in attachments) if label]
    return " ".join([*labels, text]) if text.strip() else " ".join(labels)


# content_type for each MessageEntryContents variant the SDK returns as Unknown.
_ENTRY_TYPES = {
    7: "ConversationPinned",
    8: "ConversationUnpinned",
    9: "ScreenCapture",
    10: "CallEnded",
    11: "CallMissed",
    12: "Draft",
    13: "MessageRequestAccepted",
    14: "Nickname",
    15: "VerifiedStatus",
    16: "CallStarted",
}
# is_audio_only field id of each call variant.
_AUDIO_ONLY_FIELDS = {10: 3, 11: 2, 16: 1}


def _entry_content(holder: dict[int, Any]) -> dict[str, Any]:
    """Content dict for a MessageEntryHolder, for entry types the SDK returns as Unknown."""
    variant, fields = _union_variant(holder.get(1))
    content: dict[str, Any] = {"content_type": _ENTRY_TYPES.get(variant, "Unknown")}
    if variant in _AUDIO_ONLY_FIELDS:
        content["audio_only"] = fields.get(_AUDIO_ONLY_FIELDS[variant]) is True
    if variant == 10 and isinstance(fields.get(2), int):
        content["duration_seconds"] = fields[2]
    elif variant == 9:
        content["recording"] = fields.get(1) == 2
    elif variant == 12:
        content["text"] = _scalar(fields.get(2))
    elif variant == 14:
        content.update(user_id=_scalar(fields.get(1)), nickname=_scalar(fields.get(2)))
    elif variant == 15:
        content.update(user_id=_scalar(fields.get(1)), verified=fields.get(2) is True)
    elif variant not in _ENTRY_TYPES:
        content["type_id"] = variant
    return content


def _fallback_content(info: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any] | None:
    """Content of a message whose entry type the SDK returns as Unknown, or None.

    Encrypted contents are opened again with the conversation key named by the event.
    """
    _, create = _union_variant(info.get("detail"))
    contents = create.get(100)
    version = info.get("key_version")
    if isinstance(contents, bytes) and version is not None:
        key = keys.get(version)
        contents = _open_box(key, contents) if isinstance(key, bytes) else None
    if not isinstance(contents, bytes):
        return None
    try:
        holder, _ = _thrift_value(contents, 0, _THRIFT_STRUCT)
    except (ValueError, IndexError, struct.error):
        return None
    return _entry_content(holder)


def _duration(seconds: int) -> str:
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = [f"{n}{unit}" for n, unit in ((hours, "h"), (minutes, "m"), (seconds, "s")) if n]
    return " ".join(parts) or "0s"


_CONTENT_TEXT = {
    "MarkRead": "[marked as read]",
    "MarkUnread": "[marked as unread]",
    "ConversationPinned": "[pinned the conversation]",
    "ConversationUnpinned": "[unpinned the conversation]",
    "MessageRequestAccepted": "[accepted the message request]",
}


def _content_text(content: dict[str, Any], attachments: list[dict[str, Any]]) -> str:
    """Display text for a message's content. Never empty."""
    kind = content.get("content_type")
    target = content.get("target_message_id") or "a message"
    if kind == "Text":
        text = str(content.get("text") or "")
        forwarded = str((content.get("forwarded_message") or {}).get("message_text") or "")
        if forwarded and not text.strip():
            text = f"[forwarded] {forwarded}"
        return _with_labels(text, attachments) or "[empty message]"
    if kind == "Reaction":
        return f"reacted {content.get('emoji') or ''} to {target}"
    if kind == "ReactionRemoved":
        return f"removed reaction {content.get('emoji') or ''} from {target}"
    if kind == "Edit":
        return f"edited {target}: {content.get('new_text') or ''}"
    if kind in ("CallStarted", "CallEnded", "CallMissed"):
        call = "audio call" if content.get("audio_only") else "call"
        if kind == "CallStarted":
            return f"[{call} started]"
        if kind == "CallMissed":
            return f"[missed {call}]"
        duration = content.get("duration_seconds")
        return f"[{call} ended, {_duration(duration)}]" if duration else f"[{call} ended]"
    if kind == "ScreenCapture":
        return "[recorded the screen]" if content.get("recording") else "[took a screenshot]"
    if kind == "Draft":
        return f"[draft] {content.get('text') or ''}".strip()
    if kind == "Nickname":
        return f"[set a nickname for {content.get('user_id')}: {content.get('nickname')}]"
    if kind == "VerifiedStatus":
        return f"[changed the verified status of {content.get('user_id')}]"
    return _CONTENT_TEXT.get(kind, "[unsupported message]")


_EVENT_TEXT = {
    "GrokSearchResponse": "[Grok search results]",
    "EncryptedResendRequest": "[asked to resend messages encrypted]",
    "GrokMessage": "[message to Grok]",
    "PinKeysUpdate": "[pinned message keys updated]",
}


def _grok_attachments(encoded: Any) -> list[dict[str, Any]]:
    if not isinstance(encoded, bytes):
        return []
    try:
        holder, _ = _thrift_value(encoded, 0, _THRIFT_STRUCT)
    except (ValueError, IndexError, struct.error):
        return []
    items = holder.get(1)
    return [_attachment_from_thrift(item) for item in items] if isinstance(items, list) else []


def _fallback_event(info: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Fields and display text for an event whose detail type the SDK returns as Unknown."""
    variant, fields = _union_variant(info.get("detail"))
    kind = info.get("type")
    if kind not in (*_EVENT_TEXT, "GrokResponse", "PinMessage", "UnpinMessage"):
        return {"type": "Unknown", "event_type_id": variant}, "[unsupported event]"
    event: dict[str, Any] = {"type": kind, "event_type_id": variant}
    if kind == "GrokResponse":
        reply = fields.get(6)
        text = reply.decode("utf-8", "replace") if isinstance(reply, bytes) else ""
        attachments = _grok_attachments(fields.get(7))
        event.update(attachments=attachments, replying_to_sequence_id=_scalar(fields.get(10)) or None)
        return event, _with_labels(text, attachments) or "[encrypted Grok reply]"
    if kind == "PinMessage":
        pinned = _scalar(fields.get(4))
        event["message_sequence_id"] = pinned or None
        return event, f"pinned message {pinned}" if pinned else "pinned a message"
    if kind == "UnpinMessage":
        entries = fields.get(3) if isinstance(fields.get(3), list) else [fields]
        ids = [_scalar(entry.get(2)) for entry in entries if isinstance(entry, dict)]
        event["message_sequence_ids"] = [i for i in ids if i]
        unpinned = ", ".join(event["message_sequence_ids"])
        return event, f"unpinned message {unpinned}" if unpinned else "unpinned a message"
    return event, _EVENT_TEXT[kind]


def _readable_event(
    event: dict[str, Any], info: dict[str, Any], keys: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """The event with what the SDK left Unknown filled in, and its display text.

    Text is empty only for decoded events that aren't messages, such as key
    changes and read receipts.
    """
    if event.get("type") == "Message":
        content = event.get("content") or {}
        if content.get("content_type") == "Unknown":
            content = _fallback_content(info, keys) or content
            event = {**event, "content": content}
        return event, _content_text(content, event.get("attachments") or [])
    if event.get("type") == "Unknown":
        fields, text = _fallback_event(info)
        return {**event, **fields}, text
    return event, ""


def _placeholder(event_b64: str, info: dict[str, Any], error: str) -> dict[str, Any]:
    """Row for an event that couldn't be decoded."""
    kind = info.get("type", "Unknown")
    meta = ("sequence_id", "id", "sender_id", "conversation_id", "created_at_msec")
    return {
        "event": {"type": kind, **{name: info.get(name) for name in meta}},
        "text": "[could not decrypt this message]" if kind == "Message" else "[could not read this event]",
        "original_b64": event_b64,
        "status": "unverified",
        "error": error,
    }


def _message_status(event: dict[str, Any], info: dict[str, Any] | None) -> str:
    if info is not None:
        unencrypted = info["key_version"] is None
    else:
        unencrypted = event.get("type") == "Message" and event.get("key_version") is None
    if unencrypted:
        return "unencrypted"
    return "verified" if event.get("verified") else "unverified"


def _decrypt(chat: Chat, payload: Any) -> dict[str, Any]:
    """Decrypt every event, whether or not its signature can be verified.

    Each item has a status: verified, unencrypted (an event with no
    conversation key version), or unverified, and display text that is never
    empty for a message. Event and entry types the SDK returns as Unknown,
    such as Grok replies, pins and calls, are decoded here. Every event that
    can't be decoded still gets a row, with placeholder text and an error.
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

    keys = conversation_keys.get("keys") if isinstance(conversation_keys, dict) else None
    messages: list[dict[str, Any]] = []
    unverified_senders: set[str] = set()
    for i, event_b64 in enumerate(events):
        if i not in decoded:
            messages.append(_placeholder(event_b64, infos[i] or {}, errors.get(str(i), "")))
            continue
        event, text = _readable_event(decoded[i], infos[i] or {}, keys or {})
        status = _message_status(event, infos[i])
        sender = str(event.get("sender_id") or "")
        if status == "unverified" and sender:
            unverified_senders.add(sender)
        messages.append(
            {
                "event": event,
                "text": text,
                "original_b64": event_b64,
                "status": status,
            }
        )
    texts = {
        m["event"].get("sequence_id"): m["text"] for m in messages if m["event"].get("type") == "Message"
    }
    for message in messages:
        event = message["event"]
        pinned = event.get("type") == "PinMessage" and texts.get(event.get("message_sequence_id"))
        if pinned:
            message["text"] += f": {pinned}"
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
