import argparse
import base64
import io
import json
import os
import stat
import struct
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import chat_xdk

import xchat_lite

real_keyring_lookup = xchat_lite._keyring

STOP, BOOL, I32, I64, STRING, STRUCT, LIST = 0, 2, 8, 10, 11, 12, 15

# chatxdk SDK test vectors: test-only keys for user 1111, a signed self key
# change for conversation 1111:2222 (key version 1001), and a message
# encrypted and signed under it.
VECTORS = {
    "private_keys": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg==",
    "identity_public_key": "BGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=",
    "signing_public_key": "BHzyexiNA09+ilI4AwS1GsPAiWnid/IbNaYLSPxHZpl4B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E=",
    "identity_public_key_signature": "lwqF3bFJN47NLoYzSyTTCaA+eGe3g2rbDzWc120eJYV3ClHqD1NI79WKL60ciN0fBjhmuAnIq/Beq/GhPUu52A==",
    "conversation_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=",
    "key_change_event": (
        "CwABAAAAATELAAIAAAAIa2MtbXNnLTELAAMAAAAEMTExMQsABAAAAAkxMTExOjIyMjILAAYAAAANMTcwMDAwMDAwMDAw"
        "MAwABwwAAwsAAQAAAAQxMDAxDwACDAAAAAELAAEAAAAEMTExMQsAAgAAAJhCR0hGdmgzaUw3VitCbGZJRnpFM0E2VDBo"
        "RjNCbVM1RHhJaWp5R3Z0NEVVbVdKK2FFdWQweGZXSHNXcFJyOVBwU3hZSS9wNHNScGlkS3pkbXFXUmpZOFlVK3pQMFlI"
        "eFZidldMNWQ4MERtbEN2TmlBUFV1Ryszbldsdmx2Z3k2VFN5UnlaakZHb3JxUzArbitGVTd6cEU0PQsAAwAAAAExAAAA"
        "DAAJCwABAAAAVmVpSkx2V1V0cDY1bkxVdWVEaUJDc01FSjJmQWY1c0d4T25aQ050ZHVEaUQxWWZ1UlQzSzhTTjFBcC9y"
        "N05YamZ6cEVWaXJCaTc5Q1N2WnE5a3dKaW1nCwACAAAAATELAAMAAAABNwAA"
    ),
    "message_event": (
        "CwABAAAAATELAAIAAAAkMmMyYTFkMzItOTg4Yi00YjBlLTllNjMtYzNiYWFiMzAwM2ZkCwADAAAABDExMTELAAQAAAAJ"
        "MTExMToyMjIyCwAGAAAADTE3MDAwMDAwMDAwMDAMAAcMAAELAGQAAABNyju49fSvP23md4h8MxYDM7/yP5czAJioJV+X"
        "I7e3bBM4gzkCp4+5iBBX4Jyee/0tULcB8Tkkl6qNbcRN9lWROcUxPyPGVVRp7WSqgVoLAGUAAAAEMTAwMQIAZgEAAAwA"
        "CQsAAQAAAFZ4Rkk3NnA2VzZLY09jN0JGL0NLSjg4Sk5ZYnRvSitaS1VqdFFsTTNzYTRFdUdJZ1F2eHlLSG1tUkxqa0tl"
        "RUdMZkNEbU1EZDZTdlFMSTdiZVg0SFhZQQsAAgAAAAExCwADAAAAATcAAA=="
    ),
}
SENDER_ID = "1111"
MESSAGE_TEXT = "fixture event message"

SDK_KEY = {
    "user_id": SENDER_ID,
    "public_key_version": "1",
    "public_key": VECTORS["signing_public_key"],
    "identity_public_key": VECTORS["identity_public_key"],
    "identity_public_key_signature": VECTORS["identity_public_key_signature"],
}


def _field(ftype: int, fid: int, payload: bytes) -> bytes:
    return struct.pack(">bh", ftype, fid) + payload


def _string(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode()
    return struct.pack(">i", len(raw)) + raw


def _struct(*fields: bytes) -> bytes:
    return b"".join(fields) + bytes([STOP])


def _text(fid: int, value: str) -> bytes:
    return _field(STRING, fid, _string(value))


def _i32(fid: int, value: int) -> bytes:
    return _field(I32, fid, struct.pack(">i", value))


def _i64(fid: int, value: int) -> bytes:
    return _field(I64, fid, struct.pack(">q", value))


def _bool(fid: int, value: bool) -> bytes:
    return _field(BOOL, fid, b"\x01" if value else b"\x00")


def _list(fid: int, *items: bytes) -> bytes:
    return _field(LIST, fid, struct.pack(">bi", STRUCT, len(items)) + b"".join(items))


def _variant(fid: int, *fields: bytes) -> bytes:
    """A union whose variant `fid` is a struct with these fields."""
    return _struct(_field(STRUCT, fid, _struct(*fields)))


def _group_change(change: int, *fields: bytes) -> bytes:
    """A group change event detail holding GroupChange variant `change`."""
    return _variant(4, _field(STRUCT, 1, _variant(change, *fields)))


def _fresh_event_id() -> str:
    _fresh_event_id.n += 1
    return f"evt-{_fresh_event_id.n}"


_fresh_event_id.n = 0


def _fresh_sequence_id() -> str:
    _fresh_sequence_id.n += 1
    return str(3000 + _fresh_sequence_id.n)


_fresh_sequence_id.n = 0


def _event(
    detail: bytes,
    sender_id: str = "222",
    conversation_id: str = "111-222",
    event_id: str | None = None,
    sequence_id: str | None = None,
) -> str:
    """Base64 Thrift MessageEvent with this detail union, without a signature.

    Each call gets its own sequence id and message id unless one is passed.
    An empty id is left off.
    """
    if event_id is None:
        event_id = _fresh_event_id()
    if sequence_id is None:
        sequence_id = _fresh_sequence_id()
    fields = [
        _field(STRING, 3, _string(sender_id)),
        _field(STRING, 4, _string(conversation_id)),
        _field(STRING, 6, _string("1700000000001")),
        _field(STRUCT, 7, detail),
    ]
    if sequence_id:
        fields.insert(0, _field(STRING, 1, _string(sequence_id)))
    if event_id:
        fields.insert(1 if sequence_id else 0, _field(STRING, 2, _string(event_id)))
    event = _struct(*fields)
    return base64.b64encode(event).decode()


def _message_event(
    create_event: bytes,
    sender_id: str,
    conversation_id: str,
    event_id: str | None = None,
    sequence_id: str | None = None,
) -> str:
    return _event(
        _struct(_field(STRUCT, 1, create_event)),
        sender_id,
        conversation_id,
        event_id,
        sequence_id,
    )


def unencrypted_message_event(
    text: str,
    sender_id: str = "222",
    event_id: str | None = None,
    sequence_id: str | None = None,
) -> str:
    """A message with plaintext contents and no conversation key version."""
    message_contents = _struct(_field(STRING, 1, _string(text)))
    entry_holder = _struct(_field(STRUCT, 1, _struct(_field(STRUCT, 1, message_contents))))
    create_event = _struct(
        _field(STRING, 100, _string(entry_holder)),
        _field(BOOL, 102, b"\x01"),
    )
    return _message_event(create_event, sender_id, "111-222", event_id, sequence_id)


def unsigned_encrypted_message_event(text: str) -> str:
    """A message encrypted under the vector conversation key, with its signature left out."""
    chat = chat_xdk.Chat()
    chat.import_keys(base64.b64decode(VECTORS["private_keys"]), version="1")
    payload = chat.encrypt_message(
        "1111:2222",
        text,
        sender_id=SENDER_ID,
        signing_key_version="1",
        conversation_key=base64.b64decode(VECTORS["conversation_key"]),
        conversation_key_version="1001",
    )
    return _message_event(base64.b64decode(payload.encrypted_content), SENDER_ID, "1111:2222")


def entry_holder(variant: int, *fields: bytes) -> bytes:
    """A MessageEntryHolder whose contents are MessageEntryContents variant `variant`."""
    return _struct(_field(STRUCT, 1, _variant(variant, *fields)))


def plain_entry_event(variant: int, *fields: bytes) -> str:
    """An unencrypted message holding MessageEntryContents variant `variant`."""
    create = _struct(_field(STRING, 100, _string(entry_holder(variant, *fields))))
    return _message_event(create, "222", "111-222")


def seal(key: bytes, plaintext: bytes) -> bytes:
    """An XSalsa20-Poly1305 box: nonce, tag, ciphertext."""
    nonce = bytes(range(24))
    stream = xchat_lite._xsalsa20_stream(key, nonce, 32 + len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, stream[32:]))
    return nonce + xchat_lite._poly1305(stream[:32], ciphertext) + ciphertext


def encrypted_entry_thread(variant: int, *fields: bytes) -> dict:
    """The vector key change and an unsigned message whose entry is sealed under its key."""
    contents = seal(base64.b64decode(VECTORS["conversation_key"]), entry_holder(variant, *fields))
    create = _struct(_field(STRING, 100, _string(contents)), _text(101, "1001"))
    return {
        "conversation_key_events": [VECTORS["key_change_event"]],
        "events": [_message_event(create, SENDER_ID, "1111:2222")],
    }


def media(media_type: int, *fields: bytes) -> bytes:
    """A MessageAttachment holding a media attachment of this MediaType."""
    return _variant(1, _text(1, "hash-key"), _i32(3, media_type), *fields)


def mcp_key(**overrides) -> dict:
    """A get_users_public_keys entry for the vector sender, shaped as the MCP returns it."""
    key = {
        "user_id": SENDER_ID,
        "public_key_version": "1",
        "public_key": VECTORS["identity_public_key"],
        "signing_public_key": VECTORS["signing_public_key"],
        "identity_public_key_signature": VECTORS["identity_public_key_signature"],
        "juicebox_config": {"max_guess_count": 5, "token_map": []},
    }
    key.update(overrides)
    return key


def encrypted_thread(signing_keys) -> dict:
    return {
        "conversation_key_events": [VECTORS["key_change_event"]],
        "events": [VECTORS["message_event"]],
        "signing_keys": signing_keys,
    }


class OfflineChat:
    """A real chat_xdk.Chat whose unlock() loads the vector keys instead of calling Juicebox."""

    def __init__(self, juicebox_config: str = "") -> None:
        self._chat = chat_xdk.Chat()

    def unlock(self, pin: str) -> None:
        self._chat.import_keys(base64.b64decode(VECTORS["private_keys"]), version="1")

    def __getattr__(self, name: str):
        return getattr(self._chat, name)


class NoUnlockChat(OfflineChat):
    def unlock(self, pin: str) -> None:
        raise AssertionError("unlock should not run")


class RecordingChat(OfflineChat):
    """Records each decrypt_events batch and whether unverified events were rejected."""

    def __init__(self, juicebox_config: str) -> None:
        super().__init__(juicebox_config)
        self.reject = True
        self.batches: list[tuple[bool, list[str]]] = []

    def set_reject_unverified(self, reject: bool) -> None:
        self.reject = reject
        self._chat.set_reject_unverified(reject)

    def decrypt_events(self, events, signing_keys=None):
        self.batches.append((self.reject, list(events)))
        return self._chat.decrypt_events(events, signing_keys)


def run_decrypt(payload) -> dict:
    args = argparse.Namespace(user_id="2222", key_version="1", juicebox="{}", remember_key=False)
    out = io.StringIO()
    with (
        mock.patch.object(xchat_lite, "Chat", OfflineChat),
        mock.patch.dict(os.environ, {"CHAT_PIN": "test-pin"}),
        mock.patch("sys.stdin", io.StringIO(json.dumps(payload))),
        redirect_stdout(out),
    ):
        xchat_lite.cmd_decrypt(args)
    return json.loads(out.getvalue())


def summary(result: dict) -> list[tuple[str, str, str]]:
    return [(m["event"]["type"], m["status"], m["text"]) for m in result["messages"]]


def texts(result: dict) -> list[str]:
    return [m["text"] for m in result["messages"]]


PIN = "test-pin"


def run_cli(*argv: str, pin: str = "", chat=OfflineChat, stdin=None) -> dict:
    """Run the CLI as user 2222 with key version 1 and return its JSON output.

    Fails if the PIN or the private keys reach stdout or stderr.
    """
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(xchat_lite, "Chat", chat),
        mock.patch.dict(os.environ, {"CHAT_PIN": pin}),
        mock.patch("sys.argv", ["xchat_lite.py", "--user-id", "2222", "--key-version", "1", *argv]),
        mock.patch("sys.stdin", io.StringIO(json.dumps(stdin))),
        redirect_stdout(out),
        redirect_stderr(err),
    ):
        xchat_lite.main()
    if any(secret in out.getvalue() + err.getvalue() for secret in (PIN, VECTORS["private_keys"])):
        raise AssertionError("the PIN or private keys reached the output")
    return json.loads(out.getvalue())


class FakeKeyring:
    def __init__(self) -> None:
        self.passwords: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, name: str) -> str | None:
        return self.passwords.get((service, name))

    def set_password(self, service: str, name: str, password: str) -> None:
        self.passwords[service, name] = password

    def delete_password(self, service: str, name: str) -> None:
        del self.passwords[service, name]


def setUpModule() -> None:
    """Keep every test away from the real keyring and ~/.config."""
    config = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(config.cleanup)
    for patch in (
        mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config.name}),
        mock.patch.object(xchat_lite, "_keyring", lambda: None),
    ):
        patch.start()
        unittest.addModuleCleanup(patch.stop)


class SigningKeyNormalizationTest(unittest.TestCase):
    def normalize(self, raw):
        return xchat_lite._signing_keys(chat_xdk.Chat(), raw)

    def test_mcp_entry_maps_identity_and_signing_keys(self):
        self.assertEqual(self.normalize([mcp_key()]), ([SDK_KEY], []))

    def test_nested_and_raw_shapes_normalize_to_the_same_key(self):
        bare = {k: v for k, v in mcp_key().items() if k != "user_id"}
        backend = {
            "public_key_with_metadata": {
                "public_key": {
                    name: bare[name]
                    for name in ("public_key", "signing_public_key", "identity_public_key_signature")
                },
                "version": "1",
            },
            "token_map": {},
        }
        shapes = {
            "response": {"data": [mcp_key()]},
            "per-user container": {"user_id": SENDER_ID, "public_keys": [bare]},
            "map of user id to keys": {SENDER_ID: [bare]},
            "backend nesting": {"user_id": SENDER_ID, "public_keys": [backend]},
            "sdk entry": [SDK_KEY],
            "numeric version": [mcp_key(public_key_version=1)],
        }
        for name, raw in shapes.items():
            with self.subTest(name):
                self.assertEqual(self.normalize(raw), ([SDK_KEY], []))

    def test_duplicate_entries_collapse(self):
        keys, _ = self.normalize([mcp_key(), SDK_KEY, {"data": [mcp_key()]}])
        self.assertEqual(keys, [SDK_KEY])


class SkippedSigningKeyTest(unittest.TestCase):
    def test_incomplete_entries_are_skipped_with_a_reason(self):
        no_signature = {k: v for k, v in mcp_key().items() if k != "identity_public_key_signature"}
        raw = [
            no_signature,
            mcp_key(signing_public_key=None),
            mcp_key(public_key_version={"version": 1}),
            {"user_id": "333"},
            "garbage",
            None,
            mcp_key(),
        ]
        keys, skipped = xchat_lite._signing_keys(chat_xdk.Chat(), raw)
        self.assertEqual(keys, [SDK_KEY])
        self.assertEqual(
            [(s["user_id"], s["reason"]) for s in skipped],
            [
                (SENDER_ID, "missing identity_public_key_signature"),
                (SENDER_ID, "missing signing key"),
                (SENDER_ID, "missing public_key_version"),
                ("333", "missing public_key_version, signing key, identity key, identity_public_key_signature"),
                ("", "not an object"),
                ("", "not an object"),
            ],
        )

    def test_bad_entries_do_not_break_the_batch(self):
        result = run_decrypt(encrypted_thread([{"user_id": SENDER_ID}, "garbage", mcp_key()]))

        self.assertEqual(summary(result)[-1], ("Message", "verified", MESSAGE_TEXT))
        self.assertEqual(len(result["skipped_signing_keys"]), 2)
        self.assertEqual(result["unverified_senders"], [])

    def test_entry_whose_identity_binding_fails_is_skipped(self):
        swapped = mcp_key(
            public_key=VECTORS["signing_public_key"],
            signing_public_key=VECTORS["identity_public_key"],
        )
        result = run_decrypt(encrypted_thread([swapped]))

        self.assertEqual(
            result["skipped_signing_keys"],
            [{"user_id": SENDER_ID, "reason": "identity binding does not verify"}],
        )
        self.assertEqual(result["unverified_senders"], [SENDER_ID])


class VerificationPolicyTest(unittest.TestCase):
    def test_distinct_events_sharing_a_message_id_all_stay(self):
        shared = "client-request"
        result = run_decrypt(
            {
                "conversation_key_events": [
                    unencrypted_message_event("key-a", event_id=shared, sequence_id="20"),
                    unencrypted_message_event("key-b", event_id=shared, sequence_id="21"),
                ],
                "events": [
                    unencrypted_message_event("one", event_id=shared, sequence_id="10"),
                    unencrypted_message_event("two", event_id=shared, sequence_id="11"),
                    unencrypted_message_event("three", event_id=shared, sequence_id="12"),
                ],
            }
        )

        self.assertEqual(texts(result), ["key-a", "key-b", "one", "two", "three"])

    def test_same_sequence_id_collapses_to_the_first(self):
        result = run_decrypt(
            {
                "conversation_key_events": [
                    VECTORS["key_change_event"],
                    VECTORS["key_change_event"],
                ],
                "events": [
                    unencrypted_message_event("first", event_id="a", sequence_id="7"),
                    unencrypted_message_event("later", event_id="b", sequence_id="7"),
                    VECTORS["message_event"],
                    {"encoded_event": VECTORS["message_event"]},
                ],
                "signing_keys": {"data": [mcp_key()]},
            }
        )

        self.assertEqual(
            summary(result),
            [
                ("KeyChange", "verified", ""),
                ("Message", "unencrypted", "first"),
                ("Message", "verified", MESSAGE_TEXT),
            ],
        )

    def test_events_without_a_sequence_id_dedupe_on_the_encoded_event(self):
        one = unencrypted_message_event("alpha", event_id="m1", sequence_id="")
        other = unencrypted_message_event("beta", event_id="m1", sequence_id="")
        result = run_decrypt(
            {
                "conversation_key_events": [one, one, other],
                "events": [one, other, other],
            }
        )

        self.assertEqual(texts(result), ["alpha", "beta", "alpha", "beta"])

    def test_every_event_is_accepted_in_one_pass(self):
        events = [
            VECTORS["message_event"],
            unencrypted_message_event("plain"),
        ]
        chat = RecordingChat("{}")
        xchat_lite._decrypt(
            chat,
            {"conversation_key_events": [VECTORS["key_change_event"]], "events": events},
        )

        self.assertEqual(chat.batches, [(False, [VECTORS["key_change_event"], *events])])

    def test_unsigned_group_description_change_is_returned(self):
        event = _event(_group_change(14, _text(1, "about"), _text(2, "1007")))
        result = run_decrypt({"events": [event]})

        self.assertEqual(result["errors"], {})
        self.assertEqual(summary(result), [("GroupChange", "unverified", "")])

    def test_unsigned_group_change_without_a_key_version_is_unencrypted(self):
        event = _event(_group_change(2, _text(1, "renamed")), sender_id="333")
        result = run_decrypt({"events": [event]})

        self.assertEqual(result["errors"], {})
        self.assertEqual(summary(result), [("GroupChange", "unencrypted", "")])
        self.assertEqual(result["unverified_senders"], [])

    def test_unencrypted_message_is_readable_and_marked(self):
        result = run_decrypt({"events": [unencrypted_message_event("sent before encryption")]})

        self.assertEqual(result["errors"], {})
        self.assertEqual(summary(result), [("Message", "unencrypted", "sent before encryption")])
        self.assertIsNone(result["messages"][0]["event"]["key_version"])
        self.assertEqual(result["unverified_senders"], [])

    def test_encrypted_message_verifies_with_the_sender_key(self):
        result = run_decrypt(encrypted_thread({"data": [mcp_key()]}))

        self.assertEqual(
            summary(result),
            [("KeyChange", "verified", ""), ("Message", "verified", MESSAGE_TEXT)],
        )
        self.assertEqual(result["unverified_senders"], [])

    def test_encrypted_message_without_a_signing_key_returns_text(self):
        result = run_decrypt(encrypted_thread([]))

        self.assertEqual(
            summary(result),
            [("KeyChange", "unverified", ""), ("Message", "unverified", MESSAGE_TEXT)],
        )
        self.assertNotIn("error", result["messages"][1])
        self.assertEqual(result["unverified_senders"], [SENDER_ID])

    def test_unsigned_encrypted_message_returns_its_text(self):
        payload = encrypted_thread([mcp_key()])
        payload["events"] = [unsigned_encrypted_message_event("forged without a signature")]
        result = run_decrypt(payload)

        self.assertEqual(
            summary(result),
            [("KeyChange", "verified", ""), ("Message", "unverified", "forged without a signature")],
        )
        self.assertEqual(result["unverified_senders"], [SENDER_ID])

    def test_message_that_cannot_be_decrypted_gets_placeholder_text(self):
        text = "needs a conversation key"
        result = run_decrypt({"events": [unsigned_encrypted_message_event(text)]})

        self.assertNotIn(text, json.dumps(result))
        [message] = result["messages"]
        self.assertEqual(message["text"], "[could not decrypt this message]")
        self.assertEqual(message["status"], "unverified")
        self.assertEqual(message["event"]["sender_id"], SENDER_ID)
        self.assertTrue(message["error"])
        self.assertEqual(result["unverified_senders"], [])

    def test_unencrypted_and_unverified_messages_share_one_pass(self):
        payload = encrypted_thread([])
        payload["events"].append({"encoded_event": unencrypted_message_event("plain", "222")})
        result = run_decrypt(payload)

        self.assertEqual(
            summary(result),
            [
                ("KeyChange", "unverified", ""),
                ("Message", "unverified", MESSAGE_TEXT),
                ("Message", "unencrypted", "plain"),
            ],
        )
        self.assertEqual(result["unverified_senders"], [SENDER_ID])


class DisplayTextTest(unittest.TestCase):
    def test_attachments_are_labeled_before_the_caption(self):
        cases = {
            "[photo] look": (_text(1, "look"), _list(3, media(1))),
            "[video]": (_list(3, media(3)),),
            "[file: report.pdf]": (_text(1, ""), _list(3, media(5, _text(6, "report.pdf")))),
            "[post: https://x.com/a/status/1]": (
                _list(3, _variant(2, _text(1, "1"), _text(2, "https://x.com/a/status/1"))),
            ),
            "see https://ex.com": (_text(1, "see https://ex.com"), _list(3, _variant(3, _text(1, "https://ex.com")))),
            "[payment: Sent $5]": (_list(3, _variant(5, _text(1, "Sent $5"))),),
            "[forwarded] hello": (_field(STRUCT, 6, _struct(_text(1, "hello"))),),
            "[empty message]": (),
        }
        for expected, fields in cases.items():
            with self.subTest(expected):
                self.assertEqual(texts(run_decrypt({"events": [plain_entry_event(1, *fields)]})), [expected])

    def test_reactions_and_edits_name_the_message(self):
        result = run_decrypt(
            {
                "events": [
                    plain_entry_event(2, _text(1, "2001"), _text(2, "❤️")),
                    plain_entry_event(3, _text(1, "2001"), _text(2, "❤️")),
                    plain_entry_event(4, _text(1, "2001"), _text(2, "see you at 6")),
                ]
            }
        )

        self.assertEqual(
            texts(result),
            ["reacted ❤️ to 2001", "removed reaction ❤️ from 2001", "edited 2001: see you at 6"],
        )

    def test_calls_and_accepted_requests_are_readable(self):
        sent_at = _i64(1, 1_760_140_800_000)
        result = run_decrypt(
            {
                "events": [
                    plain_entry_event(16, _bool(1, False)),
                    plain_entry_event(16, _bool(1, True)),
                    plain_entry_event(10, sent_at, _i64(2, 65), _bool(3, False)),
                    plain_entry_event(11, sent_at, _bool(2, True)),
                    plain_entry_event(13),
                ]
            }
        )

        self.assertEqual(
            texts(result),
            [
                "[call started]",
                "[audio call started]",
                "[call ended, 1m 5s]",
                "[missed audio call]",
                "[accepted the message request]",
            ],
        )
        self.assertEqual(result["messages"][2]["event"]["content"]["content_type"], "CallEnded")

    def test_encrypted_call_and_request_entries_are_opened_again(self):
        call = encrypted_entry_thread(10, _i64(1, 1_760_140_800_000), _i64(2, 3725), _bool(3, True))
        [_, message] = run_decrypt(call)["messages"]

        self.assertEqual(message["text"], "[audio call ended, 1h 2m 5s]")
        self.assertEqual(
            message["event"]["content"],
            {"content_type": "CallEnded", "audio_only": True, "duration_seconds": 3725},
        )
        self.assertEqual(texts(run_decrypt(encrypted_entry_thread(13)))[-1], "[accepted the message request]")

    def test_grok_messages_and_replies_are_readable(self):
        photo = _string(_struct(_list(1, media(1))))
        result = run_decrypt(
            {
                "events": [
                    _event(_variant(15, _field(STRING, 1, _string(b"\x00sealed")), _text(5, "1001"))),
                    _event(_variant(16, _text(6, "Here is the summary.\n"), _text(10, "2001"))),
                    _event(_variant(16, _text(6, "Look"), _field(STRING, 7, photo))),
                    _event(_variant(16, _field(STRING, 1, _string(b"\x01sealed")))),
                ]
            }
        )

        self.assertEqual(
            [(m["event"]["type"], m["text"]) for m in result["messages"]],
            [
                ("GrokMessage", "[message to Grok]"),
                ("GrokResponse", "Here is the summary.\n"),
                ("GrokResponse", "[photo] Look"),
                ("GrokResponse", "[encrypted Grok reply]"),
            ],
        )
        self.assertEqual(result["messages"][1]["event"]["replying_to_sequence_id"], "2001")

    def test_pins_and_unpins_name_the_message(self):
        result = run_decrypt(
            {
                "events": [
                    unencrypted_message_event("meet at 5", sequence_id="2001"),
                    _event(_variant(17, _field(STRING, 1, _string(b"sealed")), _text(3, "1001"), _i64(4, 2001))),
                    _event(_variant(18, _list(3, _struct(_i64(1, 2002), _i64(2, 2001))))),
                    _event(_variant(18, _i64(1, 2002), _i64(2, 2001))),
                    _event(_variant(19)),
                ]
            }
        )

        self.assertEqual(
            summary(result)[1:],
            [
                ("PinMessage", "unverified", "pinned message 2001: meet at 5"),
                ("UnpinMessage", "unencrypted", "unpinned message 2001"),
                ("UnpinMessage", "unencrypted", "unpinned message 2001"),
                ("PinKeysUpdate", "unencrypted", "[pinned message keys updated]"),
            ],
        )


class PlaceholderTest(unittest.TestCase):
    def test_every_event_that_cannot_be_decoded_gets_a_row(self):
        mistyped_settings = _event(_variant(9, _field(STRUCT, 1, _variant(1, _text(1, "not a duration")))))
        truncated = base64.b64encode(base64.b64decode(unencrypted_message_event("cut"))[:-5]).decode()
        result = run_decrypt({"events": [mistyped_settings, truncated, {"encoded_event": None}]})

        self.assertEqual(
            [(m["event"]["type"], m["text"], m["status"]) for m in result["messages"]],
            [
                ("SettingsChange", "[could not read this event]", "unverified"),
                ("Unknown", "[could not read this event]", "unverified"),
                ("Unknown", "[could not read this event]", "unverified"),
            ],
        )
        self.assertEqual([m["error"] for m in result["messages"]], [result["errors"][i] for i in ("0", "1", "2")])
        self.assertEqual(result["errors"]["2"], "not a base64 event")


class OpenBoxTest(unittest.TestCase):
    def test_opens_what_the_sdk_encrypts(self):
        key = bytes(range(32))
        for text in ("", "a", "x" * 63, "y" * 64, "✓ " * 100):
            with self.subTest(length=len(text)):
                box = base64.b64decode(chat_xdk.Chat().encrypt(text, key))
                self.assertEqual(xchat_lite._open_box(key, box), text.encode())

    def test_rejects_a_wrong_key_or_a_tampered_box(self):
        key = bytes(range(32))
        box = bytearray(base64.b64decode(chat_xdk.Chat().encrypt("hello", key)))

        self.assertIsNone(xchat_lite._open_box(bytes(32), bytes(box)))
        box[-1] ^= 1
        self.assertIsNone(xchat_lite._open_box(key, bytes(box)))


def sent_entities(fields: dict) -> list[tuple[int, int, int]]:
    """(start, end, content variant) for each entity in an encrypt payload's message contents."""
    key = base64.b64decode(VECTORS["conversation_key"])
    event, _ = xchat_lite._thrift_value(base64.b64decode(fields["encoded_message_create_event"]), 0, STRUCT)
    contents, _ = xchat_lite._thrift_value(xchat_lite._open_box(key, event[100]), 0, STRUCT)
    contents = contents[1][1]
    return [(e[1], e[2], next(iter(e[3]))) for e in contents.get(2, [])]


def encrypt(text: str) -> dict:
    chat = chat_xdk.Chat()
    chat.import_keys(base64.b64decode(VECTORS["private_keys"]), version="1")
    chat.set_identity("1111", "1")
    key = base64.b64decode(VECTORS["conversation_key"])
    return xchat_lite._encrypt_payload(chat, "1111-2222", text, conversation_key=key, conversation_key_version="1001")


class UrlEntityTest(unittest.TestCase):
    def test_urls_are_found_in_utf16_units(self):
        self.assertEqual(xchat_lite._url_entities("see https://x.com/a."), [(4, 19, "url")])
        self.assertEqual(xchat_lite._url_entities("𝕏 https://x.com"), [(3, 16, "url")])
        self.assertEqual(xchat_lite._url_entities("[docs](https://docs.x.com)"), [(7, 25, "url")])
        self.assertEqual(xchat_lite._url_entities("(https://en.wikipedia.org/wiki/A_(b))"), [(1, 36, "url")])
        self.assertEqual(xchat_lite._url_entities("no links, just https:// and x.com"), [])

    def test_encrypt_marks_urls_as_link_entities(self):
        text = "Ship it: https://github.com/x/y/pull/1 and 𝕏 https://docs.x.com"
        fields = encrypt(text)
        # 4 is RichTextContent.url.
        self.assertEqual(sent_entities(fields), [(9, 38, 4), (46, 64, 4)])

    def test_text_without_urls_has_no_entities(self):
        fields = encrypt("hello")
        self.assertEqual(sent_entities(fields), [])


class SavedKeyTest(unittest.TestCase):
    def setUp(self):
        config = tempfile.TemporaryDirectory()
        self.addCleanup(config.cleanup)
        patch = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config.name})
        patch.start()
        self.addCleanup(patch.stop)
        self.key_file = Path(config.name, "xchat-grokbot-helper", "saved-key.json")

    def remember(self) -> dict:
        return run_cli("--juicebox", "{}", "--remember-key", "unlock-check", pin=PIN)

    def test_remember_key_saves_the_unlocked_key(self):
        result = self.remember()

        self.assertEqual((result["key_source"], result["key_saved"]), ("pin", True))
        self.assertEqual(stat.S_IMODE(self.key_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.key_file.parent.stat().st_mode), 0o700)
        self.assertEqual(
            json.loads(self.key_file.read_text()),
            {"format": 1, "user_id": "2222", "key_version": "1", "private_keys": VECTORS["private_keys"]},
        )

    def test_nothing_is_saved_by_default(self):
        result = run_cli("--juicebox", "{}", "unlock-check", pin=PIN)

        self.assertEqual((result["key_source"], result["key_saved"]), ("pin", False))
        self.assertFalse(self.key_file.parent.exists())

    def test_saved_key_skips_juicebox_and_the_pin(self):
        self.remember()

        status = run_cli("unlock-check", chat=NoUnlockChat)
        result = run_cli("decrypt", chat=NoUnlockChat, stdin=encrypted_thread([mcp_key()]))

        self.assertEqual((status["key_source"], status["key_saved"]), ("saved", True))
        self.assertEqual(summary(result)[-1], ("Message", "verified", MESSAGE_TEXT))

    def test_forget_deletes_the_saved_key(self):
        self.remember()

        self.assertEqual(run_cli("forget"), {"ok": True, "forgotten": True})
        self.assertFalse(self.key_file.exists())
        self.assertEqual(run_cli("forget"), {"ok": True, "forgotten": False})
        self.assertEqual(run_cli("--juicebox", "{}", "unlock-check", pin=PIN)["key_source"], "pin")

    def test_unusable_saved_key_falls_back_to_one_pin_unlock(self):
        self.remember()
        record = json.loads(self.key_file.read_text())
        cases = {
            "not JSON": "{",
            "another file format": json.dumps({**record, "format": 2}),
            "another account": json.dumps({**record, "user_id": "3333"}),
            "another key version": json.dumps({**record, "key_version": "2"}),
            "invalid key bytes": json.dumps({**record, "private_keys": base64.b64encode(bytes(64)).decode()}),
        }
        for name, saved in cases.items():
            with self.subTest(name):
                self.key_file.write_text(saved)
                with mock.patch.object(
                    OfflineChat, "unlock", autospec=True, side_effect=OfflineChat.unlock
                ) as unlock:
                    result = run_cli("--juicebox", "{}", "unlock-check", pin=PIN)

                unlock.assert_called_once()
                self.assertEqual((result["key_source"], result["key_saved"]), ("pin", False))

    def test_os_keyring_holds_the_key_when_available(self):
        keyring = FakeKeyring()
        with mock.patch.object(xchat_lite, "_keyring", lambda: keyring):
            self.assertTrue(self.remember()["key_saved"])
            self.assertFalse(self.key_file.exists())
            self.assertEqual(run_cli("unlock-check", chat=NoUnlockChat)["key_source"], "saved")
            self.assertEqual(run_cli("forget"), {"ok": True, "forgotten": True})
        self.assertEqual(keyring.passwords, {})

    def test_only_os_keyring_backends_are_used(self):
        def backend(module: str):
            return type("Backend", (), {"__module__": module})()

        os_keyring, file_keyring = backend("keyring.backends.SecretService"), backend("keyrings.alt.file")
        chainer = type("Chainer", (), {"__module__": "keyring.backends.chainer"})()
        chainer.backends = [file_keyring, os_keyring]
        fake_module = types.SimpleNamespace(get_keyring=lambda: chainer)
        with mock.patch.dict(sys.modules, {"keyring": fake_module}):
            self.assertIs(real_keyring_lookup(), os_keyring)
            fake_module.get_keyring = lambda: file_keyring
            self.assertIsNone(real_keyring_lookup())


if __name__ == "__main__":
    unittest.main()
