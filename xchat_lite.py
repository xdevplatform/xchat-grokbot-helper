#!/usr/bin/env python3
"""Thin local crypto helper for XChat via X MCP + chatxdk.

Network stays on the X connector MCP. This process only unlocks Juicebox
keys and encrypts/decrypts. Never print PIN, private keys, or juicebox tokens.

Env:
  CHAT_PIN              Juicebox PIN (secret-request → env; never echo)
  XCHAT_USER_ID         numeric X user id (optional if --user-id)
  XCHAT_KEY_VERSION     public_key_version (optional if --key-version)
  XCHAT_JUICEBOX_JSON   path to juicebox_config JSON file, or inline JSON

CLI:
  unlock-check
  decrypt                 # stdin: {"events":[...], "signing_keys":[...]}
                          #         or a bare list of event base64 strings
                          # Prefer events = meta.conversation_key_events + data[].encoded_event
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
import json
import os
import sys
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


def _session_from_env(args: argparse.Namespace) -> tuple[Chat, str]:
    pin = _load_pin()
    juicebox = _load_juicebox_config(
        args.juicebox or os.environ.get("XCHAT_JUICEBOX_JSON", "")
    )
    user_id = args.user_id or os.environ.get("XCHAT_USER_ID", "")
    version = str(
        args.key_version
        or os.environ.get("XCHAT_KEY_VERSION", "")
        or "1"
    )
    if not user_id:
        raise SystemExit("Pass --user-id or set XCHAT_USER_ID")

    chat = Chat(juicebox)
    chat.unlock(pin)
    chat.set_identity(user_id, version)
    chat.set_cache_keys(True)
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


def cmd_unlock_check(args: argparse.Namespace) -> None:
    chat, user_id = _session_from_env(args)
    print(
        json.dumps(
            {
                "ok": True,
                "unlocked": bool(chat.is_unlocked()),
                "user_id": user_id,
                "has_identity_key": bool(chat.has_identity_key()),
            }
        )
    )


def cmd_decrypt(args: argparse.Namespace) -> None:
    chat, _ = _session_from_env(args)
    payload = json.load(sys.stdin)
    if isinstance(payload, list):
        events = payload
        signing_keys = None
    else:
        events = payload.get("events") or payload.get("encoded_events") or []
        # Include key-change blobs when callers pass them separately
        key_events = payload.get("conversation_key_events") or []
        if key_events:
            events = list(key_events) + list(events)
        signing_keys = payload.get("signing_keys")
    if signing_keys:
        chat.set_signing_keys(signing_keys)
    result = chat.decrypt_events(events, signing_keys)
    messages = []
    for item in result.get("messages", []):
        event = _as_dict(item.get("event"))
        text = ""
        if event.get("type") == "Message":
            content = event.get("content") or {}
            text = str(content.get("text") or "")
        messages.append(
            {
                "event": event,
                "text": text,
                "original_b64": item.get("original_b64"),
            }
        )
    print(
        json.dumps(
            {
                "messages": messages,
                "conversation_keys": _normalize_conversation_keys(
                    result.get("conversation_keys")
                ),
                "errors": result.get("errors") or {},
            },
            ensure_ascii=False,
        )
    )


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
    events = body.get("events") or body.get("encoded_events") or []
    key_events = body.get("conversation_key_events") or []
    if key_events:
        events = list(key_events) + list(events)
    signing_keys = body.get("signing_keys")
    decrypt_summary = None
    if events:
        if signing_keys:
            chat.set_signing_keys(signing_keys)
        result = chat.decrypt_events(events, signing_keys)
        msgs = result.get("messages") or []
        decrypt_summary = {
            "message_count": len(msgs),
            "types": [
                (_as_dict(m.get("event")).get("type") if isinstance(m, dict) else None)
                for m in msgs[:20]
            ],
            "error_count": len(result.get("errors") or {}),
        }

    try:
        send_fields = _encrypt_payload(chat, conversation_id, text, **enc_kwargs)
    except Exception as e:
        raise SystemExit(
            f"session-encrypt failed: {e}. For empty threads use prepare + MCP "
            f"add_conversation_keys first. For existing threads include conversation_key_events "
            f"+ encoded_event list so decrypt can warm keys. Classic (unencrypted) DMs are "
            f"out of scope for this helper."
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
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("unlock-check", help="Verify PIN unlocks Juicebox keys")
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
