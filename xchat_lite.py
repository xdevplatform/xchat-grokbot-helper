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
                          # notice: system events (group, settings, deletes, key changes) add one; encrypted
                          #         group titles/avatars/descriptions are opened into new fields
                          # stdout: messages[], one per event, with display text and status
                          #         verified | unencrypted | unverified (placeholder text and
                          #         an error when an event can't be decoded),
                          #         unverified_senders, skipped_signing_keys, errors
  decrypt-media           # stdin: decrypt's input (the media's message event, conversation_key_events,
                          #        signing_keys) plus "media": [{"media_hash_key": "...", "input": PATH}]
                          # input: a saved chat_media_download result, or the raw downloaded bytes
                          # --out-dir: where decrypted files go (default
                          #            ~/.cache/xchat-grokbot-helper/media, mode 700)
                          # stdout: media[] with each decrypted file's path (mode 600), mime_type and
                          #         size_bytes, and errors keyed by media index
  encrypt-media           # stdin: session-encrypt's conversation_id, events, conversation_key_events and
                          #        signing_keys, plus "media": [{"input": PATH, "filename"?}]
                          # input: a PNG, JPEG, GIF or WebP image of at most 5 MiB
                          # --out-dir: where part files go (default ~/.cache/xchat-grokbot-helper/media)
                          # --part-bytes: encrypted bytes per part, 65536 to 4194304 (the default)
                          # stdout: upload_dir, and media[] with total_bytes (chat_media_upload_initialize),
                          #         num_parts (finalize), parts[] (segment_index and a mode-600 file holding
                          #         the base64 media for chat_media_upload_append), width, height and
                          #         conversation_key_version; errors keyed by media index
  prepare-keys            # stdin: {"public_keys":[...], "conversation_id"?}
                          # public_keys entries: user_id, public_key (identity), key_version
                          # stdout: add_conversation_keys body fields (+ optional _local_conversation_key)
  encrypt CONV_ID TEXT    # needs conversation key in cache OR pass --from-decrypt/--from-prepare
                          # encrypt and session-encrypt mark URLs, emails, @mentions, #hashtags and
                          # $cashtags as rich-text entities
  session-encrypt         # stdin JSON: warm keys then encrypt in ONE process
                          # {
                          #   "conversation_id": "...",
                          #   "text": "...",
                          #   "events": [...],              # optional: decrypt to warm cache
                          #   "signing_keys": [...],        # with events
                          #   "prepare": {"public_keys":[...], "conversation_id"?}  # optional first-contact
                          #   "reply_to": "SEQ_OR_MESSAGE_ID",   # optional: reply to a message in events
                          #   "edit": "SEQ_OR_MESSAGE_ID",       # optional: text replaces that message's text
                          #   "reaction": {"target": "SEQ_OR_MESSAGE_ID", "emoji": "👍", "remove"?: true},
                          #   "attachments": [...], "ttl_msec": N, "should_notify": false  # optional, chat-xdk shapes
                          #   "media": [{"media_hash_key": "...", "input": PATH, "filename"?,
                          #              "conversation_key_version"?}]  # optional: images uploaded from
                          #            encrypt-media's parts (pass its result); text may then be left out
                          # }
                          # stdout adds "action": message | reply | reaction | reaction_removed | edit
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

from chat_xdk import Chat, detect_image_dimensions, detect_mime_type


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


_URL = re.compile(r"https?://[^\s<>\"'`]+")
_URL_TRAILING = ".,;:!?'\")]}*_"


def _url_entities(text: str) -> list[tuple[int, int, str]]:
    """(start, end, "url") for each http(s) URL, in UTF-16 code units, as the X apps mark links.

    Trailing punctuation isn't part of the link; a closing parenthesis is when it balances one
    in the URL.
    """
    spans = []
    for match in _URL.finditer(text):
        url = match.group(0)
        while url and url[-1] in _URL_TRAILING:
            if url[-1] == ")" and url.count("(") >= url.count(")"):
                break
            url = url[:-1]
        if len(url) <= len("https://"):
            continue
        start = len(text[: match.start()].encode("utf-16-le")) // 2
        spans.append((start, start + len(url.encode("utf-16-le")) // 2, "url"))
    return spans


# Mentions, hashtags and cashtags as twitter-text finds them, and emails with x-android's regex.
_EMAIL = re.compile(r"[a-zA-Z0-9+._%-]{1,256}@[a-zA-Z0-9][a-zA-Z0-9-]{0,64}(\.[a-zA-Z0-9][a-zA-Z0-9-]{1,63})+")
# twitter-text's LATIN_ACCENTS: a mention that runs into one isn't a mention.
_LATIN_ACCENTS = (
    r"\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u00ff\u0100-\u024f\u0253\u0254\u0256\u0257\u0259\u025b\u0263"
    r"\u0268\u026f\u0272\u0289\u028b\u02bb\u0300-\u036f\u1e00-\u1eff"
)
_MENTION = re.compile(
    r"(?:(?<![A-Za-z0-9_!@＠#$%&*])|(?<=(?<![A-Za-z0-9_+~.-])[Rr][Tt]))"
    r"[@＠][A-Za-z0-9_]{1,20}(?![A-Za-z0-9_@＠" + _LATIN_ACCENTS + r"]|://)"
)
# twitter-text's other hashtag characters: underscore, ZWNJ, ZWJ and some in-word punctuation.
_HASHTAG_EXTRAS = "_\u200c\u200d\ua67e\u05be\u05f3\u05f4\uff5e\u301c\u309b\u309c\u30a0\u30fb\u3003\u0f0b\u0f0c\u00b7"
_CASHTAG = re.compile(r"(?:^|(?<=\s))\$[A-Za-z]{1,6}(?:[._][A-Za-z]{1,2})?(?=$|\s|[!-/:-@\[-`{-~])")


def _hashtag_pattern(text: str) -> re.Pattern[str]:
    """twitter-text's hashtag regex, with classes built from this text's characters.

    re has no \\p{L}, \\p{M} or \\p{Nd}, and classifying all of Unicode with unicodedata takes
    about 0.25s, so the classes hold ASCII plus the text's letters, Mn/Mc marks and digits.
    """
    letters, digits = "A-Za-z", "0-9"
    for ch in sorted(set(text)):
        if ch > "\x7f":
            category = unicodedata.category(ch)
            if category[0] == "L" or category in ("Mn", "Mc"):
                letters += ch
            elif category == "Nd":
                digits += ch
    chars = letters + digits + _HASHTAG_EXTRAS
    # Hashtag characters in the end check keep the regex from backtracking to a shorter tag.
    return re.compile(
        rf"(?:(?<=[\ufe0e\ufe0f])|(?<![&{chars}]))[#＃](?![\ufe0f\u20e3])"
        rf"[{chars}]*[{letters}][{chars}]*(?![#＃{chars}]|://)"
    )


def _utf16_offset(text: str, index: int) -> int:
    return len(text[:index].encode("utf-16-le")) // 2


def _text_entities(text: str) -> list[tuple[int, int, str]]:
    """URL, email, mention, hashtag and cashtag entities, in UTF-16 code units, as the X apps send them.

    URLs win over anything inside them; otherwise the earlier kind in the list wins an overlap.
    """
    spans = list(_url_entities(text))
    patterns = (("email", _EMAIL), ("mention", _MENTION), ("hashtag", _hashtag_pattern(text)), ("cashtag", _CASHTAG))
    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            start, end = _utf16_offset(text, match.start()), _utf16_offset(text, match.end())
            if all(end <= s or start >= e for s, e, _ in spans):
                spans.append((start, end, kind))
    return sorted(spans)


def _encrypt_payload(chat: Chat, conversation_id: str, text: str, **kwargs: Any) -> dict[str, str]:
    # Without entities X Chat shows links, mentions and tags as plain text.
    if "entities" not in kwargs:
        kwargs["entities"] = _text_entities(text) or None
    return _send_fields(chat.encrypt_message(conversation_id, text, **kwargs))


def _send_fields(payload: Any) -> dict[str, str]:
    return {
        "message_id": payload.message_id,
        "encoded_message_create_event": payload.encrypted_content,
        "encoded_message_event_signature": payload.encoded_event_signature,
    }


# session-encrypt options for a message or a reply. All but media pass straight to
# encrypt_message / encrypt_reply.
_MESSAGE_OPTIONS = ("attachments", "media", "ttl_msec", "should_notify")


def _target_message(decrypted: dict[str, Any] | None, target: str) -> dict[str, Any]:
    """The decrypted row of the message with this sequence id or message id."""
    for message in (decrypted or {}).get("messages") or []:
        event = message.get("event") or {}
        if event.get("type") == "Message" and target in (event.get("sequence_id"), event.get("id")):
            if "error" not in message:
                return message
    raise SystemExit(f"message {target} isn't among the decrypted events; include its event to reply, react or edit")


def _reply_key_events(body: dict[str, Any], decrypted: dict[str, Any], target: dict[str, Any]) -> list[str]:
    """Key change events for the target's key version, when the conversation has rotated keys."""
    keys = (decrypted.get("conversation_keys") or {}).get("keys") or {}
    version = target["event"].get("key_version")
    if not version or len(keys) < 2:
        return []
    events = [_event_b64(item) for item in body.get("conversation_key_events") or []]
    return [e for e in events if e and (_event_info(e) or {}).get("key_version") == version]


def _encrypt_action(
    chat: Chat, body: dict[str, Any], conversation_id: str, decrypted: dict[str, Any] | None, enc_kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Send fields for session-encrypt's message, reply, reaction or edit, with "action" added."""
    text = body.get("text")
    reaction = body.get("reaction")
    reply_to, edit = _scalar(body.get("reply_to")), _scalar(body.get("edit"))
    if sum(1 for option in (reaction, reply_to, edit) if option) > 1:
        raise SystemExit("pass only one of reply_to, reaction and edit")
    options = {name: body[name] for name in _MESSAGE_OPTIONS if body.get(name) is not None}
    if options and (reaction or edit):
        raise SystemExit(f"{', '.join(options)} only apply to a message or a reply")
    if isinstance(reaction, dict):
        target = _target_message(decrypted, _scalar(reaction.get("target")))
        emoji = _scalar(reaction.get("emoji"))
        if not emoji:
            raise SystemExit("reaction needs target and emoji")
        remove = reaction.get("remove") is True
        encrypt = chat.encrypt_remove_reaction if remove else chat.encrypt_add_reaction
        fields = _send_fields(encrypt(target["original_b64"], emoji, **enc_kwargs))
        return {**fields, "action": "reaction_removed" if remove else "reaction",
                "target_sequence_id": target["event"].get("sequence_id")}
    if reaction is not None:
        raise SystemExit("reaction must be an object with target and emoji")
    if text is None and options.get("media"):
        text = ""
    if not isinstance(text, str):
        raise SystemExit("stdin needs conversation_id and text")
    entities = _text_entities(text) or None
    if edit:
        target = _target_message(decrypted, edit)
        fields = _send_fields(chat.encrypt_edit(target["original_b64"], text, entities=entities, **enc_kwargs))
        return {**fields, "action": "edit", "target_sequence_id": target["event"].get("sequence_id")}
    media = options.pop("media", None) or []
    if media:
        options["attachments"] = [*(options.get("attachments") or []), *map(_media_attachment, media)]
    if reply_to:
        target = _target_message(decrypted, reply_to)
        ckces = _reply_key_events(body, decrypted or {}, target)
        payload = chat.encrypt_reply(
            conversation_id, text, target["original_b64"],
            reply_to_ckces=ckces or None, entities=entities, **options, **enc_kwargs,
        )
        action = {"action": "reply", "target_sequence_id": target["event"].get("sequence_id")}
    else:
        payload = chat.encrypt_message(conversation_id, text, entities=entities, **options, **enc_kwargs)
        action = {"action": "message"}
    for entry in media:
        version = _scalar(entry.get("conversation_key_version"))
        if version and version != payload.conversation_key_version:
            raise SystemExit(
                f"the image was encrypted under conversation key {version}, but the message is under "
                f"{payload.conversation_key_version}; run encrypt-media again with the same events"
            )
    return {**_send_fields(payload), **action}


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


def _dedupe_events(items: list[Any]) -> list[Any]:
    """Keep the first item for each sequence id.

    An event with no sequence id is kept once per exact encoded string.
    """
    seen: set[tuple[str, str]] = set()
    kept: list[Any] = []
    for item in items:
        event_b64 = _event_b64(item)
        info = _event_info(event_b64) if event_b64 else None
        sequence_id = info["sequence_id"] if info else ""
        key = ("sequence", sequence_id) if sequence_id else ("event", event_b64)
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    return kept


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
    17: "XNumberUsed",
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
    "XNumberUsed": "[used an X Number]",
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


def _message_key(conversation_key: bytes, sender_id: str, message_id: str) -> bytes:
    """Per-message key for contents_encryption_version >= 1, as x-android derives it.

    HKDF-SHA256 of the conversation key, salt "xchat-message-key", info "sender:message_id".
    """
    prk = hmac.new(b"xchat-message-key", conversation_key, hashlib.sha256).digest()
    return hmac.new(prk, f"{sender_id}:{message_id}".encode() + b"\x01", hashlib.sha256).digest()


def _text_of(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else ""


def _holder_message(holder: dict[int, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Content and attachments of a MessageEntryHolder, in the SDK's shapes."""
    variant, fields = _union_variant(holder.get(1))
    if variant == 1:
        content: dict[str, Any] = {"content_type": "Text", "text": _text_of(fields.get(1))}
        forwarded = fields.get(6)
        if isinstance(forwarded, dict):
            content["forwarded_message"] = {"message_text": _text_of(forwarded.get(1))}
        preview = fields.get(4)
        if isinstance(preview, dict):
            content["replying_to_preview"] = {
                "sender_id": str(preview[1]) if isinstance(preview.get(1), int) else None,
                "message_text": _text_of(preview.get(2)),
                "replying_to_message_sequence_id": _scalar(preview.get(6)) or None,
            }
        items = fields.get(3) if isinstance(fields.get(3), list) else []
        return content, [_attachment_from_thrift(item) for item in items]
    if variant in (2, 3):
        kind = "Reaction" if variant == 2 else "ReactionRemoved"
        return {"content_type": kind, "emoji": _text_of(fields.get(2)), "target_message_id": _scalar(fields.get(1))}, []
    if variant == 4:
        return {"content_type": "Edit", "target_message_id": _scalar(fields.get(1)), "new_text": _text_of(fields.get(2))}, []
    if variant in (5, 6):
        return {"content_type": "MarkRead" if variant == 5 else "MarkUnread"}, []
    return _entry_content(holder), []


def _message_key_event(info: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any] | None:
    """A message sent with a per-message key (contents_encryption_version >= 1), which
    chatxdk 0.5.0 can't open, decrypted here; None when it isn't one or doesn't open.
    Its signature isn't checked, so it comes back unverified.
    """
    variant, create = _union_variant(info.get("detail"))
    version, contents = create.get(112), create.get(100)
    key = keys.get(info.get("key_version") or "")
    if variant != 1 or not isinstance(version, int) or version < 1 or not isinstance(contents, bytes):
        return None
    if not isinstance(key, bytes) or not info.get("sender_id") or not info.get("id"):
        return None
    opened = _open_box(_message_key(key, info["sender_id"], info["id"]), contents)
    if opened is None:
        return None
    try:
        holder, _ = _thrift_value(opened, 0, _THRIFT_STRUCT)
    except (ValueError, IndexError, struct.error):
        return None
    content, attachments = _holder_message(holder)
    meta = ("sequence_id", "id", "sender_id", "conversation_id", "created_at_msec", "key_version")
    return {
        "type": "Message",
        **{name: info.get(name) for name in meta},
        "content": content,
        "attachments": attachments,
        "verified": False,
        "contents_encryption_version": version,
    }


def _metadata_text(value: Any, key: Any) -> str | None:
    """A group title, avatar url or description encrypted under the conversation key, opened."""
    if not isinstance(key, bytes) or not isinstance(value, (str, bytes)):
        return None
    try:
        box = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    opened = _open_box(key, box)
    return opened.decode("utf-8", "replace") if opened is not None else None


# Encrypted fields of each GroupChange the SDK returns, and the field each opens into.
_ENCRYPTED_GROUP_FIELDS = {
    "Created": {"title": "decrypted_title", "avatar_url": "decrypted_avatar_url"},
    "TitleChanged": {"new_title": "decrypted_title"},
    "AvatarChanged": {"new_avatar_url": "decrypted_avatar_url"},
}


def _group_change(event: dict[str, Any], info: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any]:
    """The change with encrypted titles, avatars and descriptions opened, added as new fields."""
    change = dict(event.get("change") or {})
    key = keys.get(info.get("key_version") or "")
    for name, opened_name in _ENCRYPTED_GROUP_FIELDS.get(change.get("change_type"), {}).items():
        opened = _metadata_text(change.get(name), key)
        if opened is not None:
            change[opened_name] = opened
    _, group_event = _union_variant(info.get("detail"))
    variant, fields = _union_variant(group_event.get(1))
    if variant == 14 and change.get("change_type") == "Unknown":
        description = _scalar(fields.get(1))
        change["change_type"] = "DescriptionChanged"
        change["description"] = _metadata_text(description, key) if info.get("key_version") else description
    return change


def _ids(values: Any) -> str:
    return ", ".join(str(v) for v in values) if isinstance(values, list) else ""


def _group_notice(change: dict[str, Any]) -> str:
    kind = change.get("change_type")
    title = change.get("decrypted_title")
    if kind == "Created":
        return f"[created the group {title}]" if title else "[created the group]"
    if kind == "TitleChanged":
        return f"[renamed the group to {title}]" if title else "[renamed the group]"
    if kind == "DescriptionChanged":
        description = change.get("description")
        return f"[changed the group description: {description}]" if description else "[changed the group description]"
    labels = {
        "AvatarChanged": "[changed the group photo]",
        "AdminsAdded": f"[made {_ids(change.get('admin_ids'))} admin]",
        "AdminsRemoved": f"[removed {_ids(change.get('admin_ids'))} as admin]",
        "MembersAdded": f"[added {_ids(change.get('member_ids'))}]",
        "MembersRemoved": f"[removed {_ids(change.get('member_ids'))}]",
        "InviteEnabled": "[turned on the invite link]",
        "InviteDisabled": "[turned off the invite link]",
        "JoinRequested": f"[{change.get('user_id')} asked to join]",
        "JoinRejected": f"[declined join requests from {_ids(change.get('user_ids'))}]",
    }
    return labels.get(kind, "[changed the group]")


_SETTING_NOTICES = {
    "MessageDurationRemoved": "[turned off disappearing messages]",
    "Muted": "[muted the conversation]",
    "Unmuted": "[unmuted the conversation]",
    "ScreenCaptureDetectionEnabled": "[turned on screenshot alerts]",
    "ScreenCaptureDetectionDisabled": "[turned off screenshot alerts]",
    "ScreenCaptureBlockingEnabled": "[turned on screenshot blocking]",
    "ScreenCaptureBlockingDisabled": "[turned off screenshot blocking]",
}


def _notice(event: dict[str, Any]) -> str | None:
    """One-line description of a system event (group, settings, deletes, key changes), or None."""
    kind = event.get("type")
    if kind == "GroupChange":
        return _group_notice(event.get("change") or {})
    if kind == "SettingsChange":
        change = event.get("change") or {}
        if change.get("setting") == "MessageDuration" and isinstance(change.get("ttl_msec"), int):
            return f"[set disappearing messages to {_duration(change['ttl_msec'] // 1000)}]"
        return _SETTING_NOTICES.get(change.get("setting"), "[changed a conversation setting]")
    if kind == "MessageDeleted":
        count = len(event.get("message_ids") or [])
        scope = " for everyone" if event.get("delete_for_all") else ""
        return f"[deleted {count} message{'s' if count != 1 else ''}{scope}]"
    if kind == "ConversationDeleted":
        return "[deleted the conversation]"
    if kind == "MemberDeleted":
        return f"[the account of {event.get('member_id')} was deleted]"
    if kind == "KeyChange":
        return "[conversation key changed]"
    if kind == "Failure":
        return f"[message failed: {event.get('failure')}]"
    return None


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
    if event.get("type") == "GroupChange":
        return {**event, "change": _group_change(event, info, keys)}, ""
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
    Each sequence id is kept once, the first copy, for key events and for
    messages. An event with no sequence id is kept once per exact encoded string.
    """
    if isinstance(payload, list):
        payload = {"events": payload}
    raw_events = _dedupe_events(list(payload.get("conversation_key_events") or [])) + _dedupe_events(
        list(payload.get("events") or payload.get("encoded_events") or [])
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
        if i not in decoded and infos[i]:
            fallback = _message_key_event(infos[i], keys or {})
            if fallback is not None:
                decoded[i] = fallback
                errors.pop(str(i), None)
        if i not in decoded:
            messages.append(_placeholder(event_b64, infos[i] or {}, errors.get(str(i), "")))
            continue
        event, text = _readable_event(decoded[i], infos[i] or {}, keys or {})
        status = _message_status(event, infos[i])
        sender = str(event.get("sender_id") or "")
        if status == "unverified" and sender:
            unverified_senders.add(sender)
        row = {"event": event, "text": text, "original_b64": event_b64, "status": status}
        notice = _notice(event)
        if notice:
            row["notice"] = notice
        messages.append(row)
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


_MEDIA_EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "video/mp4": ".mp4",
}


def _media_from_result(doc: Any) -> bytes:
    """Downloaded bytes from a chat_media_download result.

    Takes the tool's text ({"encoding": "base64", "data": ...}) or the MCP tool
    result or JSON-RPC response around it. A failed download raises with the
    tool's error.
    """
    if isinstance(doc, dict) and isinstance(doc.get("result"), dict):
        return _media_from_result(doc["result"])
    if isinstance(doc, dict) and isinstance(doc.get("error"), dict):
        raise ValueError(f"download failed: {doc['error'].get('message')}")
    if isinstance(doc, dict) and isinstance(doc.get("content"), list):
        texts = [i.get("text") for i in doc["content"] if isinstance(i, dict) and i.get("type") == "text"]
        if texts and isinstance(texts[0], str):
            try:
                inner = json.loads(texts[0])
            except ValueError:
                if doc.get("isError"):
                    raise ValueError(f"download failed: {texts[0][:200]}") from None
                raise ValueError("not a chat_media_download result") from None
            return _media_from_result(inner)
    if isinstance(doc, dict) and doc.get("encoding") == "base64" and isinstance(doc.get("data"), str):
        data = base64.b64decode(doc["data"], validate=True)
        if doc.get("size_bytes") not in (None, len(data)):
            raise ValueError(f"download holds {len(data)} bytes, not {doc['size_bytes']}")
        return data
    if isinstance(doc, dict) and (doc.get("detail") or doc.get("title")):
        raise ValueError(f"download failed: {doc.get('detail') or doc.get('title')}")
    raise ValueError("not a chat_media_download result")


def _downloaded_media(path: str) -> bytes:
    """Bytes from a file holding a chat_media_download result, or the raw bytes themselves."""
    raw = Path(path).read_bytes()
    try:
        doc = json.loads(raw)
    except ValueError:
        return raw
    return _media_from_result(doc)


def _media_message(
    messages: list[dict[str, Any]], media_hash_key: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """The decrypted event that references this media, with its media attachment ({} for a link image)."""
    for message in messages:
        event = message.get("event") or {}
        attachment = next(
            (
                a
                for a in event.get("attachments") or []
                if isinstance(a, dict) and a.get("media_hash_key") == media_hash_key
            ),
            None,
        )
        referenced = any(
            isinstance(h, dict) and h.get("media_hash_key") == media_hash_key
            for h in event.get("media_hashes") or []
        )
        if attachment is not None or referenced:
            return event, attachment or {}
    return None


def _media_extension(attachment: dict[str, Any], plaintext: bytes) -> str:
    """The attachment's filename extension, else one for the detected type, else .bin."""
    suffix = Path(str(attachment.get("filename") or "")).suffix.lower()
    if 1 < len(suffix) <= 6 and suffix[1:].isalnum():
        return suffix
    extension = _MEDIA_EXTENSIONS.get(detect_mime_type(plaintext) or "")
    if extension:
        return extension
    return ".gif" if attachment.get("media_type") == "gif" else ".bin"


def _media_dir(out_dir: str) -> Path:
    """The --out-dir as given, or the default cache directory with mode 700."""
    if out_dir:
        path = Path(out_dir)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path
    cache = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    path = Path(cache) / _SAVED_KEY_SERVICE / "media"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write_private(path: Path, data: bytes) -> None:
    # mkstemp creates the file with mode 600.
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _decrypt_media(chat: Chat, payload: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Decrypt each downloaded media with the conversation key of the message that references it.

    Media of a message without a conversation key version is stored unencrypted
    and is written as downloaded.
    """
    decrypted = _decrypt(chat, payload)
    keys = decrypted["conversation_keys"]
    if "keys" in keys:
        keys = keys.get("keys") or {}
    media: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for i, request in enumerate(payload.get("media") or []):
        media_hash_key = str(request.get("media_hash_key") or "")
        try:
            found = _media_message(decrypted["messages"], media_hash_key)
            if found is None:
                failed = len(decrypted["errors"])
                hint = f" ({failed} event(s) could not be decrypted)" if failed else ""
                raise ValueError(f"no decrypted message references this media_hash_key; include its event{hint}")
            event, attachment = found
            downloaded = _downloaded_media(str(request.get("input") or ""))
            version = event.get("key_version")
            if version is None:
                plaintext = downloaded
            elif version in keys:
                plaintext = chat.decrypt_stream(downloaded, base64.b64decode(keys[version]))
            else:
                raise ValueError(f"no conversation key {version}; include meta.conversation_key_events")
            name = "".join(c for c in media_hash_key if c.isalnum()) or f"media-{i}"
            path = out_dir / f"{name}{_media_extension(attachment, plaintext)}"
            _write_private(path, plaintext)
        except (OSError, ValueError) as e:
            errors[str(i)] = str(e)
            continue
        media.append(
            {
                "media_hash_key": media_hash_key,
                "path": str(path),
                "mime_type": detect_mime_type(plaintext),
                "size_bytes": len(plaintext),
                "media_type": attachment.get("media_type"),
                "sequence_id": event.get("sequence_id"),
                "sender_id": event.get("sender_id"),
            }
        )
    return {"media": media, "errors": errors}


_IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")
_MAX_IMAGE_BYTES = 5 * 1024 * 1024
_MAX_PART_BYTES = 4 * 1024 * 1024
# chat_media_upload_append takes segment_index 0-999; parts this big keep the largest image under that.
_MIN_PART_BYTES = 64 * 1024


def _read_image(path: str) -> tuple[bytes, str, int, int]:
    """An image's bytes, MIME type, width and height.

    Raises ValueError for anything but a PNG, JPEG, GIF or WebP image of at most 5 MiB.
    """
    if not path:
        raise ValueError("needs input, the image's path")
    size = Path(path).stat().st_size
    if size > _MAX_IMAGE_BYTES:
        raise ValueError(f"image is {size} bytes, over the {_MAX_IMAGE_BYTES}-byte limit")
    image = Path(path).read_bytes()
    mime_type = detect_mime_type(image)
    if mime_type not in _IMAGE_TYPES:
        raise ValueError(f"not a PNG, JPEG, GIF or WebP image ({mime_type or 'unknown type'})")
    dimensions = detect_image_dimensions(image)
    if not dimensions:
        raise ValueError(f"can't read the width and height of this {mime_type} image")
    return image, mime_type, *dimensions


def _encrypted_size(size: int) -> int:
    """Bytes encrypt_stream makes of `size` bytes: a 24-byte header plus 17 per 1024-byte chunk."""
    return 24 + size + 17 * -(-size // 1024)


def _media_attachment(entry: Any) -> dict[str, Any]:
    """chat-xdk attachment for a session-encrypt media entry: an image uploaded under its media_hash_key."""
    if not isinstance(entry, dict):
        raise SystemExit("each media entry needs media_hash_key and input")
    media_hash_key = _scalar(entry.get("media_hash_key"))
    if not media_hash_key:
        raise SystemExit("each media entry needs the media_hash_key from chat_media_upload_initialize")
    path = str(entry.get("input") or "")
    try:
        image, _, width, height = _read_image(path)
    except (OSError, ValueError) as e:
        raise SystemExit(f"media {media_hash_key}: {e}") from e
    return {
        "attachment_type": "media",
        "media_hash_key": media_hash_key,
        "width": width,
        "height": height,
        # Receivers take filesize_bytes as the size of the encrypted download.
        "filesize_bytes": _encrypted_size(len(image)),
        "filename": str(entry.get("filename") or Path(path).name),
        "media_type": 1,  # image
    }


def _current_conversation_key(chat: Chat, conversation_id: str, decrypted: dict[str, Any]) -> tuple[str, bytes]:
    """Version and bytes of the key a new message in this conversation is encrypted under.

    That is the SDK's cached key, which it only takes from a key change whose signature
    verifies. Encrypting an empty message, which is never sent, names its version.
    """
    try:
        version = chat.encrypt_message(conversation_id, "").conversation_key_version
    except Exception as e:
        raise SystemExit(
            f"encrypt-media failed: {e}. Include the conversation's events, conversation_key_events and "
            f"the senders' signing_keys, as for session-encrypt. A new conversation needs its first "
            f"message (session-encrypt with prepare, then add_conversation_keys) before an image."
        ) from e
    keys = decrypted["conversation_keys"]
    if "keys" in keys:
        keys = keys.get("keys") or {}
    if version not in keys:
        raise SystemExit(f"no conversation key {version}; include meta.conversation_key_events")
    return version, base64.b64decode(keys[version])


def _encrypt_media(chat: Chat, payload: dict[str, Any], out_dir: Path, part_bytes: int) -> dict[str, Any]:
    """Encrypt each image with the conversation key, as decrypt-media reverses, into upload parts.

    Each part is a mode-600 file holding the base64 media for one chat_media_upload_append,
    in a new mode-700 directory under out_dir.
    """
    conversation_id = _scalar(payload.get("conversation_id") or payload.get("id"))
    if not conversation_id or not payload.get("media"):
        raise SystemExit('stdin needs conversation_id and "media": [{"input": PATH}]')
    version, key = _current_conversation_key(chat, conversation_id, _decrypt(chat, payload))
    upload_dir: Path | None = None
    media: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for i, request in enumerate(payload["media"]):
        path = str(request.get("input") or "")
        try:
            image, mime_type, width, height = _read_image(path)
            encrypted = chat.encrypt_stream(image, key)
            upload_dir = upload_dir or Path(tempfile.mkdtemp(prefix="upload-", dir=out_dir))
            parts = []
            for segment_index, start in enumerate(range(0, len(encrypted), part_bytes)):
                part = upload_dir / f"image{i}-part{segment_index}.b64"
                _write_private(part, base64.b64encode(encrypted[start : start + part_bytes]))
                parts.append({"segment_index": segment_index, "path": str(part)})
        except (OSError, ValueError) as e:
            errors[str(i)] = str(e)
            continue
        media.append(
            {
                "input": path,
                "filename": str(request.get("filename") or Path(path).name),
                "mime_type": mime_type,
                "width": width,
                "height": height,
                "size_bytes": len(image),
                "total_bytes": len(encrypted),
                "num_parts": len(parts),
                "parts": parts,
                "conversation_key_version": version,
            }
        )
    return {"upload_dir": str(upload_dir) if upload_dir else None, "media": media, "errors": errors}


def _part_bytes(value: str) -> int:
    size = int(value)
    if not _MIN_PART_BYTES <= size <= _MAX_PART_BYTES:
        raise argparse.ArgumentTypeError(f"must be {_MIN_PART_BYTES} to {_MAX_PART_BYTES}")
    return size


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


def cmd_decrypt_media(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    result = _decrypt_media(chat, json.load(sys.stdin), _media_dir(args.out_dir))
    print(json.dumps(result, ensure_ascii=False))


def cmd_encrypt_media(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    result = _encrypt_media(chat, json.load(sys.stdin), _media_dir(args.out_dir), args.part_bytes)
    print(json.dumps(result, ensure_ascii=False))


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
    if not conversation_id or (text is None and not body.get("reaction") and not body.get("media")):
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
    result = None
    if body.get("events") or body.get("encoded_events") or body.get("conversation_key_events"):
        result = _decrypt(chat, body)
        decrypt_summary = {
            "message_count": len(result["messages"]),
            "types": [m["event"].get("type") for m in result["messages"][:20]],
            "error_count": len(result["errors"]),
        }

    try:
        send_fields = _encrypt_action(chat, body, conversation_id, result, enc_kwargs)
    except SystemExit:
        raise
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
    p_media = sub.add_parser(
        "decrypt-media",
        help="Decrypt saved chat_media_download results into files",
    )
    p_media.add_argument("--out-dir", default="")
    p_upload = sub.add_parser(
        "encrypt-media",
        help="Encrypt images into chat_media_upload_append parts",
    )
    p_upload.add_argument("--out-dir", default="")
    p_upload.add_argument("--part-bytes", type=_part_bytes, default=_MAX_PART_BYTES)
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
    elif args.cmd == "decrypt-media":
        cmd_decrypt_media(args)
    elif args.cmd == "encrypt-media":
        cmd_encrypt_media(args)
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
