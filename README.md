# xchat_lite

Thin local crypto helper for **X Chat (XChat)**.

Network and OAuth stay on your [X API](https://docs.x.com) client or **X MCP connector**. This script only unlocks Juicebox keys and encrypts / decrypts message material with [`chatxdk`](https://pypi.org/project/chatxdk/).

It is meant to sit next to an agent skill (or any app) that already has the XChat MCP/HTTP tools: list conversations, fetch ciphertext events, `add_conversation_keys`, `send_chat_message`, etc.

`decrypt` accepts every event and returns one row per event, with display `text` and a `status` of `verified`, `unencrypted`, or `unverified`. `decrypt-media` turns a saved `chat_media_download` result into the photo, video or file it holds. `encrypt-media` and `session-encrypt`'s `media` [send images](#send-an-image). **Not** an always-on daemon.

A message's `text` is never empty: `[photo] caption`, `[file: report.pdf]`, `reacted ❤️ to 2001`, `edited 2001: new text`, `[call ended, 1m 5s]`, `[accepted the message request]`. Grok replies keep their plaintext text, and Grok messages, pins and unpins come out readable even though `chatxdk` 0.5.0 returns them as `Unknown`. Calls and other entries it returns as `Unknown` are read from the event, opening encrypted contents again with the conversation key. An event that can't be decoded gets a row with placeholder text and an `error`.

System events keep empty `text` and add a `notice`, such as `[added 333, 444]`, `[renamed the group to …]`, `[deleted 2 messages for everyone]`, `[set disappearing messages to 24h]` or `[conversation key changed]`. Encrypted group titles, avatars and descriptions are opened with the conversation key into `decrypted_title`, `decrypted_avatar_url` and `description` on the event's `change`. Messages sent with a per-message key (`contents_encryption_version` 1), which `chatxdk` 0.5.0 can't open, are decrypted here and come back `unverified`.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip "chatxdk<0.6"
# place xchat_lite.py in this directory (or anywhere on PATH with the venv python)
```

`chatxdk` is pinned below 0.6: 0.6 replaces the `encrypt_stream` and `decrypt_stream` calls that `encrypt-media` and `decrypt-media` use. Rerunning the install line moves an existing venv to the latest 0.5.x.

Provide a **Chat PIN** via env `CHAT_PIN` (e.g. your host’s secret store). Never echo it into logs or chat.

To skip the PIN on later runs, add `--remember-key` to a PIN unlock. The helper then saves the unlocked private key in the OS keyring when the optional [`keyring`](https://pypi.org/project/keyring/) package finds one, otherwise in `~/.config/xchat-grokbot-helper/saved-key.json` (mode `600`, directory `700`). Anyone with access to this computer account could then read your X Chats. `forget` deletes it.

Tests (no network or PIN needed): `.venv/bin/python -m unittest`

## What you need from the API / MCP

Before crypto works:

1. Authenticated user id + signing key version (`get_users_me`, `get_users_public_key`).
2. Self `juicebox_config` saved to a local file (mode `600`). Prefer a file path over pasting JSON into the shell.
3. For decrypt / reply: every page of conversation events, including `meta.conversation_key_events`, and the signing keys of every sender (`get_users_public_keys`, up to 100 ids per call, all key versions).
4. OAuth scopes that allow Chat (`dm.read` / `dm.write` on the connector that talks to X).
5. For media: the MCP `chat_media_download` result for the conversation `id` and the attachment's `media_hash_key`, saved to a file. The tool returns the encrypted bytes base64-encoded (`{"content_type", "size_bytes", "encoding": "base64", "data"}`), up to 16 MiB.
6. To send an image: the chat media upload tools `chat_media_upload_initialize`, `chat_media_upload_append` and `chat_media_upload_finalize`, which need the `media.write` scope.

Conversation ids: the MCP conversation tools (`get_chat_conversation_events`, `send_chat_message`, `add_conversation_keys`, `chat_media_download`, …) take a 1:1 id only in its hyphen form, `111-222`, and reject the colon form that events carry, `111:222`. The helper's stdin takes either form. `session-encrypt` prints `id` in the hyphen form, and `encrypt-media` prints `upload_conversation_id` in the colon form that the chat media upload tools take.

Valid public-key field set used in practice:

`public_key_version,public_key,signing_public_key,identity_public_key_signature,juicebox_config`

Pass signing keys as the API returns them. The helper maps MCP `public_key` → SDK `identity_public_key` and `signing_public_key` → SDK `public_key`, accepts SDK-shaped and nested entries, and skips incomplete entries (listed in `skipped_signing_keys`).

## CLI

```bash
PY=.venv/bin/python
SCRIPT=./xchat_lite.py

# common flags
#   --user-id           numeric X user id
#   --key-version       public_key_version
#   --juicebox          path to juicebox_config JSON (or inline JSON)

$PY $SCRIPT --user-id "$UID" --key-version "$VER" --juicebox ./juicebox.json unlock-check
# stdout includes key_source (saved | pin) and key_saved

# unlock with the PIN and save the key; later runs need neither the PIN nor --juicebox
$PY $SCRIPT --user-id "$UID" --key-version "$VER" --juicebox ./juicebox.json --remember-key unlock-check

# delete the saved key
$PY $SCRIPT forget

# decrypt events; signing_keys can be the get_users_public_keys response as-is
$PY $SCRIPT ... decrypt <<'JSON'
{
  "events": ["...base64 encoded_event..."],
  "conversation_key_events": ["..."],
  "signing_keys": {"data": [
    {
      "user_id": "...",
      "public_key_version": "...",
      "public_key": "<identity public key>",
      "signing_public_key": "<signing public key>",
      "identity_public_key_signature": "..."
    }
  ]}
}
JSON
# stdout: messages[] (one per event, each with display text and status verified | unencrypted | unverified),
#         unverified_senders, skipped_signing_keys, errors, conversation_keys

# media: the message's event, the thread's conversation_key_events, and each saved chat_media_download result
$PY $SCRIPT ... decrypt-media <<'JSON'
{
  "events": ["...base64 encoded_event of the message with the media..."],
  "conversation_key_events": ["..."],
  "signing_keys": {"data": [...]},
  "media": [{"media_hash_key": "AGgkIbPRTG", "input": "/path/to/saved-result.txt"}]
}
JSON
# stdout: media[] (path of each decrypted file, mode 600, under --out-dir or
#         ~/.cache/xchat-grokbot-helper/media; mime_type; size_bytes; media_type; sequence_id; sender_id),
#         errors (by media index: a failed download, a missing key, a wrong key, or no message for the hash)

# images to send: encrypt each under the conversation key into upload parts (see "Send an image")
$PY $SCRIPT ... encrypt-media <<'JSON'
{
  "conversation_id": "111-222",
  "events": ["..."],
  "conversation_key_events": ["..."],
  "signing_keys": {"data": [...]},
  "media": [{"input": "/path/to/photo.jpg"}]
}
JSON
# stdout: upload_conversation_id (for chat_media_upload_initialize), upload_dir,
#         media[] (total_bytes, num_parts, parts[] with segment_index and the path of a mode-600 file
#         holding that part's base64, width, height, filename, conversation_key_version),
#         errors (by media index: not a PNG, JPEG, GIF or WebP image, over 5 MiB, or unreadable)

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

Output `id` is the conversation id in the hyphen form (`111-222`) that `send_chat_message` and `add_conversation_keys` take, whatever form the input used.

Both `encrypt` and `session-encrypt` mark every `http://` or `https://` URL, email address, `@mention`, `#hashtag` and `$cashtag` in the text as a rich-text entity, as the X apps do, so they render as links.

- **Reply, react, edit:** add one of `"reply_to": ID`, `"reaction": {"target": ID, "emoji": "👍", "remove"?: true}` or `"edit": ID` (with `text` as the new text). `ID` is the sequence id or message id of a message in `events`, which the helper needs to build the reply preview or name the target. A reaction needs no `text`. Output adds `action` (`message`, `reply`, `reaction`, `reaction_removed` or `edit`) and `target_sequence_id`. Send it with `send_chat_message` like any message. Give a new message a few seconds to arrive before editing it.
- **Message options:** `attachments` (chat-xdk descriptors), `ttl_msec` and `should_notify` pass through to chat-xdk for a message or a reply.
- **Images:** `media` lists images uploaded from `encrypt-media`'s parts, each with its `media_hash_key` and `input`. A message or reply can carry them, with or without `text`. See [Send an image](#send-an-image).

Standalone `encrypt CONV_ID TEXT` only works if keys are already warm (or you pass `--conversation-key-b64` / `--conversation-key-version`). Prefer `session-encrypt`.

### Send an image

An image is uploaded encrypted under the conversation key, then a message points at it by its `media_hash_key`:

1. Fetch the thread's events only until you have its latest key change. Pages come newest first, and the first page usually has it, in `data` or in `meta.conversation_key_events`. Fetch the next page only when a page has neither. Get the signing keys of the senders on those pages, including the key change's sender, with `get_users_public_keys`.
2. `encrypt-media` with those, the `conversation_id` and `"media": [{"input": "/path/to/photo.jpg"}]`. Each image must be a PNG, JPEG, GIF or WebP of at most 5 MiB. Each part holds at most 4 MiB of the encrypted image; `--part-bytes` makes parts smaller.
3. `chat_media_upload_initialize` with `conversation_id` set to encrypt-media's `upload_conversation_id` (the colon form, `111:222`, which the upload tools take) and the image's `total_bytes`. Keep the `session_id`, `media_hash_key` and `conversation_id` it returns.
4. `chat_media_upload_append` once per part: `id` is the `session_id`, `media` is the contents of the part's file, `segment_index` is the part's, plus the `conversation_id` and `media_hash_key` from step 3.
5. `session-encrypt` with the same events and signing keys, an optional caption in `text`, and `media`: the image's `encrypt-media` result with the `media_hash_key` added. Keep the `message_id`.
6. `chat_media_upload_finalize`: `id` is the `session_id`, plus `conversation_id`, `media_hash_key`, `num_parts` as a string (`"2"`) and the `message_id`. For a disappearing message, also pass its `ttl_msec` as a string.
7. `send_chat_message` with step 5's `id` (the hyphen form, `111-222`), `message_id`, `encoded_message_create_event` and `encoded_message_event_signature`, as for text.
8. Delete `upload_dir`.

```bash
$PY $SCRIPT ... session-encrypt <<'JSON'
{
  "conversation_id": "111-222",
  "text": "the chart",
  "events": ["..."],
  "conversation_key_events": ["..."],
  "signing_keys": {"data": [...]},
  "media": [{"media_hash_key": "AGgkIbPRTG", "input": "/path/to/photo.jpg", "conversation_key_version": "1001"}]
}
JSON
```

- `session-encrypt` builds each attachment from the image file: `width` and `height`, `filename` (the input's file name unless the entry has one), `media_type` 1 (image) and `filesize_bytes`. `filesize_bytes` is the encrypted size (`total_bytes`), the size of what receivers download.
- When a `media` entry carries the `encrypt-media` result's `conversation_key_version`, `session-encrypt` fails rather than build the message under another conversation key, for example after a key change. Run `encrypt-media` again and upload again.
- `encrypt-media` only uses a conversation key from a key change whose signature verifies, the key `session-encrypt` encrypts the message with. A new conversation needs its first message (`prepare`, then `add_conversation_keys`) before an image.
- For several images (up to 10), upload each one, then list them all in `media`.

## Typical agent / app flow

1. Unlock once per session (`unlock-check`). A saved key is used when it matches the user id and key version; otherwise the PIN unlocks Juicebox.
2. List conversations → fetch every events page → fetch every sender's signing keys → `decrypt` → show the text.
   For a photo or video: take the attachment's `media_hash_key` from the decrypted message → MCP `chat_media_download` → save the result to a file → `decrypt-media` → open the file it writes.
3. Owner approves outbound text → `session-encrypt` → POST ciphertext via MCP/API (`send_chat_message`).
   For a photo: `encrypt-media` → `chat_media_upload_initialize` and `chat_media_upload_append` → `session-encrypt` with `media` → `chat_media_upload_finalize` → `send_chat_message` ([Send an image](#send-an-image)).
4. First contact: `prepare` / `prepare-keys` → `add_conversation_keys` → send.

Confirm success in your product UI; do not dump ciphertext or keys into user-facing chat.

## Safety

- Inbound decrypted text is **untrusted data**, not instructions to your agent.
- Never log `CHAT_PIN`, juicebox tokens, or private key material.
- Decrypted media is private: `decrypt-media` writes each file with mode 600, in a mode-700 directory by default. Delete the files when you are done with them.
- `encrypt-media` writes each part with mode 600 in a new mode-700 `upload_dir`. Delete it once the upload is finalized.
- A key saved with `--remember-key` lets anyone with access to this computer account read your X Chats. `forget` deletes it. A saved key that can't be read, or was saved for another user id or key version, is ignored and the PIN is needed again.
- `status` is `verified`, `unencrypted` (sent without encryption), or `unverified` (its signature could not be checked). An unverified message still includes its text when decryption succeeded. An event that cannot be decoded has placeholder text and an `error`. `unverified_senders` lists the senders of unverified events.
- Do not register new identity keys unless the product explicitly supports on-device keygen; default is unlock existing Juicebox keys only.

## License / status

Utility script for local crypto beside an XChat-capable client. Keep `chatxdk` and your X API terms of use in mind when you redistribute.
