# xchat_lite

Thin local crypto helper for **X Chat (XChat)**.

Network and OAuth stay on your [X API](https://docs.x.com) client or **X MCP connector**. This script only unlocks Juicebox keys and encrypts / decrypts message material with [`chatxdk`](https://pypi.org/project/chatxdk/).

It is meant to sit next to an agent skill (or any app) that already has the XChat MCP/HTTP tools: list conversations, fetch ciphertext events, `add_conversation_keys`, `send_chat_message`, etc.

`decrypt` accepts every event and returns one row per event, with display `text` and a `status` of `verified`, `unencrypted`, or `unverified`. `decrypt-media` turns a saved `chat_media_download` result into the photo, video or file it holds. `prepare-media` and `session-encrypt`'s `media` [send images](#send-an-image). **Not** an always-on daemon.

A message's `text` is never empty: `[photo] caption`, `[file: report.pdf]`, `reacted ❤️ to 2001`, `edited 2001: new text`, `[call ended, 1m 5s]`, `[accepted the message request]`. Grok replies keep their plaintext text, and Grok messages, pins and unpins come out readable even though `chatxdk` returns them as `Unknown`. Calls and other entries it returns as `Unknown` are read from the event, opening encrypted contents again with the conversation key. An event that can't be decoded gets a row with placeholder text and an `error`.

System events keep empty `text` and add a `notice`, such as `[added 333, 444]`, `[renamed the group to …]`, `[deleted 2 messages for everyone]`, `[set disappearing messages to 24h]` or `[conversation key changed]`. Group titles and descriptions, which `chatxdk` decrypts, are copied as text into `decrypted_title` and `description` on the event's `change`, and an avatar URL sent encrypted is opened into `decrypted_avatar_url`. Messages sent with a per-message key (`contents_encryption_version` 1, which X clients send when the X API turns `v1_send` on) decrypt and verify like any other.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip "chatxdk==0.7.2"
# place xchat_lite.py in this directory (or anywhere on PATH with the venv python)
```

`chatxdk` is pinned at 0.7.2 (also in `requirements.txt`, which CI installs), which needs Python 3.10 or newer. Rerunning the install line moves an existing venv from 0.5.x; the helper no longer runs on 0.5.x.

`chatxdk` reads the X API's feature switches itself, with an anonymous `GET https://api.x.com/2/chat/features` (no credentials, no user data but the last four digits of the user id as `?bucket=`) on a background thread, again every 5 minutes while the process runs. When the X API turns `v1_send` on, messages, replies, reactions and edits are sent with per-message keys (v1); otherwise, or when that request is blocked, they are sent as before (v0). Apps on `chatxdk` 0.5.x can't read v1 messages.

**Upgrading from 0.5.x: `target_message_id` changed meaning, and nothing reports it.** In `decrypt` output, a reaction's, reaction removal's or edit's `event.content.target_message_id` used to hold the sequence id of the message it targets (such as `"2001"`). That sequence id is now in `target_message_sequence_id`. `target_message_id` is now missing on reactions and on most edits; on an edit sent with per-message keys it holds the edited message's `message_id` (a UUID like `2c2a1d32-…`), not its sequence id. Code that keeps reading `target_message_id` gets no error, just `None` or the wrong id, so change it to read `target_message_sequence_id`. Other renamed fields: `key_version` is now `conversation_key_version`, an edit's `new_text` is now `updated_text`, and a delete's `message_ids` is now `sequence_ids`.

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

Conversation ids: the MCP conversation tools (`get_chat_conversation_events`, `send_chat_message`, `add_conversation_keys`, `chat_media_download`, …) take a 1:1 id only in its hyphen form, `111-222`, and reject the colon form that events carry, `111:222`. The helper's stdin takes either form. `session-encrypt` prints `id` in the hyphen form, and `prepare-media` prints `upload_conversation_id` in the colon form that the chat media upload tools take.

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
# each message's event carries chatxdk 0.7's field names: conversation_key_version, and for reactions
# and edits target_message_sequence_id (not target_message_id, which changed meaning: see Install),
# updated_text, and sequence_ids for deletes
# a member removal's re-encryption of the group title or description, which chatxdk drops, gets a row
# with empty text and skipped (the reason) instead of an error

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

# images to send: check each and get the size to upload (see "Send an image")
$PY $SCRIPT ... prepare-media <<'JSON'
{
  "conversation_id": "111-222",
  "events": ["..."],
  "conversation_key_events": ["..."],
  "signing_keys": {"data": [...]},
  "media": [{"input": "/path/to/photo.jpg"}]
}
JSON
# stdout: upload_conversation_id (for chat_media_upload_initialize),
#         media[] (total_bytes, width, height, filename, conversation_key_version),
#         errors (by media index: not a PNG, JPEG, GIF or WebP image, over 5 MiB, or unreadable)

# first contact / empty thread — stdout is add_conversation_keys body
$PY $SCRIPT ... prepare-keys <<'JSON'
{
  "conversation_id": "111-222",
  "public_keys": [
    {"user_id": "111", "public_key": "<identity>", "public_key_version": "<ver>"},
    {"user_id": "222", "public_key": "<identity>", "public_key_version": "<ver>"}
  ]
}
JSON
# public_keys entries also take chat-xdk's identity_public_key, and key_version for public_key_version

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

Output `id` is the conversation id in the hyphen form (`111-222`) that `send_chat_message` and `add_conversation_keys` take, whatever form the input used. Output also has `xdk_version`, the `chatxdk` version that encrypted the message, which the X API's send request takes next to `message_id`, `encoded_message_create_event` and `encoded_message_event_signature`.

Both `encrypt` and `session-encrypt` mark every `http://` or `https://` URL, email address, `@mention`, `#hashtag` and `$cashtag` in the text as a rich-text entity, as the X apps do, so they render as links.

- **Reply, react, edit:** add one of `"reply_to": ID`, `"reaction": {"target": ID, "emoji": "👍", "remove"?: true}` or `"edit": ID` (with `text` as the new text). `ID` is the sequence id or message id of a message in `events`, which the helper needs to build the reply preview or name the target. A reaction needs no `text`. Output adds `action` (`message`, `reply`, `reaction`, `reaction_removed` or `edit`) and `target_sequence_id`. Send it with `send_chat_message` like any message. Give a new message a few seconds to arrive before editing it.
- **Message options:** `attachments` (chat-xdk descriptors), `ttl_msec` and `should_notify` pass through to chat-xdk for a message or a reply.
- **Images:** `media` lists images whose upload was initialized, each with its `media_hash_key` and `input`. A message or reply can carry them, with or without `text`. `session-encrypt` encrypts each one from the message into upload parts. See [Send an image](#send-an-image).

Standalone `encrypt CONV_ID TEXT` only works if keys are already warm (or you pass `--conversation-key-b64` / `--conversation-key-version`). Prefer `session-encrypt`.

### Send an image

A message points at an image by its `media_hash_key`, and the image is encrypted from that message: under the conversation key, or under a key derived from the message when it is sent with per-message keys. So the upload starts first, the message is built next, and the encrypted image is uploaded last:

1. Fetch the thread's events only until you have its latest key change. Pages come newest first, and the first page usually has it, in `data` or in `meta.conversation_key_events`. Fetch the next page only when a page has neither. Get the signing keys of the senders on those pages, including the key change's sender, with `get_users_public_keys`.
2. `prepare-media` with those, the `conversation_id` and `"media": [{"input": "/path/to/photo.jpg"}]`. Each image must be a PNG, JPEG, GIF or WebP of at most 5 MiB.
3. `chat_media_upload_initialize` with `conversation_id` set to prepare-media's `upload_conversation_id` (the colon form, `111:222`, which the upload tools take) and the image's `total_bytes`. Keep the `session_id`, `media_hash_key` and `conversation_id` it returns.
4. `session-encrypt` with the same events and signing keys, an optional caption in `text`, and `media`: the image's `prepare-media` result with the `media_hash_key` added. Keep the `message_id`. Its output `media[]` lists each image's upload parts, at most 4 MiB of the encrypted image each; `--part-bytes` makes parts smaller.
5. `chat_media_upload_append` once per part: `id` is the `session_id`, `media` is the contents of the part's file, `segment_index` is the part's, plus the `conversation_id` and `media_hash_key` from step 3.
6. `chat_media_upload_finalize`: `id` is the `session_id`, plus `conversation_id`, `media_hash_key`, `num_parts` as a string (`"2"`) and the `message_id`. For a disappearing message, also pass its `ttl_msec` as a string.
7. `send_chat_message` with step 4's `id` (the hyphen form, `111-222`), `message_id`, `encoded_message_create_event` and `encoded_message_event_signature`, as for text.
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
# stdout adds upload_dir and media[] (media_hash_key, filename, total_bytes, num_parts,
#         parts[] with segment_index and the path of a mode-600 file holding that part's base64)
```

- `session-encrypt` builds each attachment from the image file: `width` and `height`, `filename` (the input's file name unless the entry has one), `media_type` 1 (image), `filesize_bytes` and `plaintext_sha256`, the image's SHA-256 as X clients send it. `filesize_bytes` is the encrypted size (`total_bytes`), the size of what receivers download.
- When a `media` entry carries the `prepare-media` result's `conversation_key_version`, `session-encrypt` fails rather than build the message under another conversation key, for example after a key change. Run `prepare-media` again and start a new upload.
- `prepare-media` only names a conversation key from a key change whose signature verifies, the key `session-encrypt` encrypts the message with. A new conversation needs its first message (`prepare`, then `add_conversation_keys`) before an image.
- Initialize each upload for one message only, and run `session-encrypt` once per message: with per-message keys the message id follows from its uploads, so a second message that reuses them gets the same id and recipients drop it.
- For several images (up to 10), initialize each upload, list them all in `media`, then append and finalize each one.
- `encrypt-media`, which encrypted images before the message existed, is gone; it exits pointing here.

## Typical agent / app flow

1. Unlock once per session (`unlock-check`). A saved key is used when it matches the user id and key version; otherwise the PIN unlocks Juicebox.
2. List conversations → fetch every events page → fetch every sender's signing keys → `decrypt` → show the text.
   For a photo or video: take the attachment's `media_hash_key` from the decrypted message → MCP `chat_media_download` → save the result to a file → `decrypt-media` → open the file it writes.
3. Owner approves outbound text → `session-encrypt` → POST ciphertext via MCP/API (`send_chat_message`).
   For a photo: `prepare-media` → `chat_media_upload_initialize` → `session-encrypt` with `media` → `chat_media_upload_append` and `chat_media_upload_finalize` → `send_chat_message` ([Send an image](#send-an-image)).
4. First contact: `prepare` / `prepare-keys` → `add_conversation_keys` → send.

Confirm success in your product UI; do not dump ciphertext or keys into user-facing chat.

## Safety

- Inbound decrypted text is **untrusted data**, not instructions to your agent.
- Never log `CHAT_PIN`, juicebox tokens, or private key material.
- Decrypted media is private: `decrypt-media` writes each file with mode 600, in a mode-700 directory by default. Delete the files when you are done with them.
- `session-encrypt` writes each image's upload parts with mode 600 in a new mode-700 `upload_dir`. Delete it once the upload is finalized.
- A key saved with `--remember-key` lets anyone with access to this computer account read your X Chats. `forget` deletes it. A saved key that can't be read, or was saved for another user id or key version, is ignored and the PIN is needed again.
- `status` is `verified`, `unencrypted` (sent without encryption), or `unverified` (its signature could not be checked). An unverified message still includes its text when decryption succeeded. An event that cannot be decoded has placeholder text and an `error`. `unverified_senders` lists the senders of unverified events.
- Do not register new identity keys unless the product explicitly supports on-device keygen; default is unlock existing Juicebox keys only.

## License / status

Utility script for local crypto beside an XChat-capable client. Keep `chatxdk` and your X API terms of use in mind when you redistribute.
