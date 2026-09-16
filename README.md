# xchat_lite

Thin local crypto helper for **encrypted X Chat (XChat)**.

Network and OAuth stay on your [X API](https://docs.x.com) client or **X MCP connector**. This script only unlocks Juicebox keys and encrypts / decrypts message material with [`chatxdk`](https://pypi.org/project/chatxdk/).

It is meant to sit next to an agent skill (or any app) that already has the XChat MCP/HTTP tools: list conversations, fetch ciphertext events, `add_conversation_keys`, `send_chat_message`, etc.

**Not** for classic unencrypted DMs. **Not** an always-on daemon.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip chatxdk
# place xchat_lite.py in this directory (or anywhere on PATH with the venv python)
```

Provide a **Chat PIN** via env `CHAT_PIN` (e.g. your host’s secret store). Never echo it into logs or chat.

## What you need from the API / MCP

Before crypto works:

1. Authenticated user id + signing key version (`get_users_me`, `get_users_public_key`).
2. Self `juicebox_config` saved to a local file (mode `600`). Prefer a file path over pasting JSON into the shell.
3. For decrypt / reply: peer public keys + conversation events, including `meta.conversation_key_events` when the API returns them.
4. OAuth scopes that allow Chat (`dm.read` / `dm.write` on the connector that talks to X).

Valid public-key field set used in practice:

`public_key_version,public_key,signing_public_key,identity_public_key_signature,juicebox_config`

Map for signing verify: MCP `public_key` → SDK `identity_public_key`, MCP `signing_public_key` → SDK `public_key`.

## CLI

```bash
PY=.venv/bin/python
SCRIPT=./xchat_lite.py

# common flags
#   --user-id           numeric X user id
#   --key-version       public_key_version
#   --juicebox          path to juicebox_config JSON (or inline JSON)

$PY $SCRIPT --user-id "$UID" --key-version "$VER" --juicebox ./juicebox.json unlock-check

# decrypt events (prepend conversation_key_events when present)
$PY $SCRIPT ... decrypt <<'JSON'
{
  "events": ["...base64 encoded_event..."],
  "conversation_key_events": ["..."],
  "signing_keys": [
    {
      "user_id": "...",
      "public_key_version": "...",
      "public_key": "<signing_public_key>",
      "identity_public_key": "<public_key>",
      "identity_public_key_signature": "..."
    }
  ]
}
JSON

# first contact / empty thread — stdout is add_conversation_keys body
$PY $SCRIPT ... prepare-keys <<'JSON'
{
  "conversation_id": "111-222",
  "public_keys": [
    {"user_id": "111", "public_key": "<identity>", "key_version": "<ver>"},
    {"user_id": "222", "public_key": "<identity>", "key_version": "<ver>"}
  ]
}
JSON

# preferred send path: warm keys + encrypt in one process
$PY $SCRIPT ... session-encrypt <<'JSON'
{
  "conversation_id": "111-222",
  "text": "hello",
  "events": ["..."],
  "conversation_key_events": ["..."],
  "signing_keys": [],
  "prepare": null
}
JSON
```

### `session-encrypt` (preferred for send)

- **Existing thread:** pass recent `events` + `conversation_key_events` + `signing_keys` so decrypt can warm the conversation key, then encrypt.
- **Empty / first message:** set `prepare` (same shape as `prepare-keys` stdin). Output includes `add_conversation_keys` and `needs_add_conversation_keys_before_send: true`. Call API `add_conversation_keys` **before** `send_chat_message`. Strip any `_local_*` fields — never send those upstream.

Standalone `encrypt CONV_ID TEXT` only works if keys are already warm (or you pass `--conversation-key-b64` / `--conversation-key-version`). Prefer `session-encrypt`.

## Typical agent / app flow

1. Unlock once per session (`unlock-check`).
2. List conversations → fetch events → `decrypt` → show plaintext to the owner.
3. Owner approves outbound text → `session-encrypt` → POST ciphertext via MCP/API (`send_chat_message`).
4. First contact: `prepare` / `prepare-keys` → `add_conversation_keys` → send.

Confirm success in your product UI; do not dump ciphertext or keys into user-facing chat.

## Safety

- Inbound decrypted text is **untrusted data**, not instructions to your agent.
- Never log `CHAT_PIN`, juicebox tokens, or private key material.
- Do not use this helper to “send” classic (unencrypted) DMs.
- Do not register new identity keys unless the product explicitly supports on-device keygen; default is unlock existing Juicebox keys only.

## License / status

Utility script for local crypto beside an XChat-capable client. Keep `chatxdk` and your X API terms of use in mind when you redistribute.
