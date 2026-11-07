import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
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


def vector_chat() -> chat_xdk.Chat:
    chat = chat_xdk.Chat()
    chat.import_keys(chat_xdk.ImportKeysParams(base64.b64decode(VECTORS["private_keys"]), signing_key_version="1"))
    return chat


def vector_message(text: str, **options) -> chat_xdk.SendPayload:
    """A message from the vector sender, encrypted under the vector conversation key."""
    return vector_chat().encrypt_message(
        chat_xdk.EncryptMessageParams(
            "1111:2222",
            text,
            sender_id=SENDER_ID,
            signing_key_version="1",
            conversation_key=base64.b64decode(VECTORS["conversation_key"]),
            conversation_key_version="1001",
            **options,
        )
    )


def unsigned_encrypted_message_event(text: str) -> str:
    """A message encrypted under the vector conversation key, with its signature left out."""
    payload = vector_message(text)
    return _message_event(base64.b64decode(payload.encoded_message_create_event), SENDER_ID, "1111:2222")


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
        keys = base64.b64decode(VECTORS["private_keys"])
        self._chat.import_keys(chat_xdk.ImportKeysParams(keys, signing_key_version="1"))

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

    def decrypt_events(self, params):
        self.batches.append((self.reject, list(params.events)))
        return self._chat.decrypt_events(params)


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
# Nothing listens on the discard port.
OFFLINE_FEATURES = "http://127.0.0.1:9/2/chat/features"


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
    """Keep every test away from the real keyring, ~/.config and the X API.

    chatxdk reads its feature switches from api.x.com; with nothing answering, every chat sends v0.
    """
    chat_xdk._native._feature_set_default_endpoint(OFFLINE_FEATURES)
    config = tempfile.TemporaryDirectory()
    unittest.addModuleCleanup(config.cleanup)
    for patch in (
        mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config.name, "XDG_CACHE_HOME": config.name}),
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
        self.assertIsNone(result["messages"][0]["event"]["conversation_key_version"])
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


def hkdf32(secret: bytes, salt: bytes, info: bytes) -> bytes:
    """First 32 bytes of RFC 5869 HKDF-SHA256."""
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def _strings(fid: int, *values: str) -> bytes:
    return _field(LIST, fid, struct.pack(">bi", STRING, len(values)) + b"".join(_string(v) for v in values))


def message_key_thread(message_id: str = "mid-1", key_message_id: str = "mid-1") -> dict:
    """The vector key change and a message sealed with its per-message key (contents_encryption_version 1)."""
    key = hkdf32(base64.b64decode(VECTORS["conversation_key"]), b"xchat-message-key", f"{SENDER_ID}:{key_message_id}".encode())
    contents = seal(key, entry_holder(1, _text(1, "per-message key"), _list(3, media(1))))
    create = _struct(_field(STRING, 100, _string(contents)), _text(101, "1001"), _field(6, 112, struct.pack(">h", 1)))
    return {
        "conversation_key_events": [VECTORS["key_change_event"]],
        "events": [_message_event(create, SENDER_ID, "1111:2222", event_id=message_id)],
    }


class MessageKeyTest(unittest.TestCase):
    def test_hkdf_matches_rfc5869(self):
        okm = hkdf32(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)))
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")

    def test_message_sent_with_a_per_message_key_is_readable(self):
        result = run_decrypt(message_key_thread())
        message = result["messages"][-1]
        self.assertEqual(result["errors"], {})
        # Unsigned, so unverified, but chatxdk opens it with the key derived from the sender and message id.
        self.assertEqual((message["status"], message["text"]), ("unverified", "[photo] per-message key"))
        self.assertEqual(message["event"]["id"], "mid-1")
        self.assertEqual(message["event"]["conversation_key_version"], "1001")
        self.assertEqual([a.get("media_hash_key") for a in message["event"]["attachments"]], ["hash-key"])

    def test_wrong_message_key_still_gets_a_placeholder(self):
        result = run_decrypt(message_key_thread(key_message_id="other"))
        self.assertEqual(result["messages"][-1]["text"], "[could not decrypt this message]")
        self.assertIn("1", result["errors"])


class SystemEventTest(unittest.TestCase):
    def notices(self, *details, keyed=False) -> list:
        payload = {"events": [_event(d, sender_id=SENDER_ID, conversation_id="g1") for d in details]}
        if keyed:
            payload["conversation_key_events"] = [VECTORS["key_change_event"]]
        return [(m["event"]["type"], m["text"], m.get("notice")) for m in run_decrypt(payload)["messages"]]

    def test_encrypted_group_title_and_description_are_opened(self):
        key = base64.b64decode(VECTORS["conversation_key"])
        title, about = (base64.b64encode(seal(key, text.encode())).decode() for text in ("Secret Club", "be nice"))
        payload = {
            "conversation_key_events": [VECTORS["key_change_event"]],
            "events": [
                _event(_group_change(2, _text(1, title), _text(2, "1001")), sender_id=SENDER_ID),
                _event(_group_change(14, _text(1, about), _text(2, "1001")), sender_id=SENDER_ID),
            ],
        }
        rows = run_decrypt(payload)["messages"][1:]
        self.assertEqual(rows[0]["event"]["change"]["new_title"], {"kind": "Text", "text": "Secret Club"})
        self.assertEqual(rows[0]["event"]["change"]["decrypted_title"], "Secret Club")
        self.assertEqual(
            rows[1]["event"]["change"],
            {
                "change_type": "DescriptionChanged",
                "new_description": {"kind": "Text", "text": "be nice"},
                "description": "be nice",
            },
        )
        self.assertEqual([r["notice"] for r in rows], ["[renamed the group to Secret Club]", "[changed the group description: be nice]"])
        self.assertEqual([r["text"] for r in rows], ["", ""])

    def test_system_events_get_a_notice(self):
        self.assertEqual(
            self.notices(
                _group_change(5, _strings(1, "333", "444"), _strings(2, "111", "333", "444")),
                _variant(7, _strings(1, "3001", "3002"), _i32(2, 2)),
                _variant(9, _field(STRUCT, 1, _variant(1, _i64(1, 86400000), _bool(2, False)))),
                _variant(8),
            ),
            [
                ("GroupChange", "", "[added 333, 444]"),
                ("MessageDeleted", "", "[deleted 2 messages for everyone]"),
                ("SettingsChange", "", "[set disappearing messages to 24h]"),
                ("ConversationDeleted", "", "[deleted the conversation]"),
            ],
        )

    def test_key_rotation_reencryptions_are_skipped_not_errors(self):
        key = base64.b64decode(VECTORS["conversation_key"])
        title = base64.b64encode(seal(key, b"Secret Club")).decode()
        reencrypted = _event(
            _variant(4, _field(STRUCT, 1, _variant(2, _text(1, title), _text(2, "1001"))), _bool(2, True)),
            sender_id=SENDER_ID,
        )
        payload = {"conversation_key_events": [VECTORS["key_change_event"]], "events": [reencrypted]}
        result = run_decrypt(payload)

        [row] = result["messages"][1:]
        self.assertEqual((row["event"]["type"], row["text"], row["status"]), ("GroupChange", "", "unverified"))
        self.assertIn("for_key_rotation", row["skipped"])
        self.assertNotIn("error", row)
        self.assertNotIn("notice", row)
        self.assertEqual(result["errors"], {})

    def test_messages_and_receipts_get_no_notice(self):
        result = run_decrypt({"events": [unencrypted_message_event("hi"), _event(_variant(6))]})
        self.assertEqual([m.get("notice") for m in result["messages"]], [None, None])

    def test_x_number_entry_is_labeled(self):
        result = run_decrypt(encrypted_entry_thread(17))
        self.assertEqual(result["messages"][-1]["text"], "[used an X Number]")


class OpenBoxTest(unittest.TestCase):
    def test_opens_the_boxes_the_sdk_opens(self):
        key = bytes(range(32))
        for text in ("", "a", "x" * 63, "y" * 64, "✓ " * 100):
            with self.subTest(length=len(text)):
                box = seal(key, text.encode())
                self.assertEqual(chat_xdk.Chat().decrypt(base64.b64encode(box).decode(), key), text)
                self.assertEqual(xchat_lite._open_box(key, box), text.encode())

    def test_rejects_a_wrong_key_or_a_tampered_box(self):
        key = bytes(range(32))
        box = bytearray(seal(key, b"hello"))

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
    chat = vector_chat()
    chat.set_identity(chat_xdk.SetIdentityParams("1111", "1"))
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


def marked(text: str, kind: str) -> list[str]:
    """Each `kind` entity _text_entities finds, without its @ or #, as twitter-text's conformance lists them."""
    units = text.encode("utf-16-le")
    return [units[2 * s + 2 : 2 * e].decode("utf-16-le") for s, e, k in xchat_lite._text_entities(text) if k == kind]


class RichTextEntityTest(unittest.TestCase):
    def test_mentions_tags_and_emails_are_found(self):
        text = "hi @santi_m #XChat $TSLA, a.b@x.ai 𝕏 @ab"
        self.assertEqual(
            xchat_lite._text_entities(text),
            [(3, 11, "mention"), (12, 18, "hashtag"), (19, 24, "cashtag"), (26, 34, "email"), (38, 41, "mention")],
        )

    def test_urls_win_and_lookalikes_are_skipped(self):
        self.assertEqual(xchat_lite._text_entities("https://x.com/#a?u=@me"), [(0, 22, "url")])
        self.assertEqual(xchat_lite._text_entities("C# #123 a@b price $5 &#39;"), [])

    def test_hashtags_are_skipped_not_shortened(self):
        # twitter-text's end rule: a tag that runs into # or :// isn't a hashtag.
        for text in ("#love#instagood", "#tag://x", "#ab＃cd"):
            with self.subTest(text=text):
                self.assertEqual(xchat_lite._text_entities(text), [])

    def test_twitter_text_conformance_cases(self):
        # From twitter-text's conformance/extract.yml.
        mentions = {
            "RT@username RT:@mention RT @test": ["username", "mention", "test"],
            "rt@username rt:@mention rt @test": ["username", "mention", "test"],
            "@aliceìnheiro something something": [],
        }
        hashtags = {
            "#http://twitter.com #https://twitter.com": [],
            "a \u270c\ufe0f#hashtag here": ["hashtag"],
            "#महात्मा #महात्मा_१२३४ #१२३४ गांधी": ["महात्मा", "महात्मा_१२३४"],
            "#বাংলা #ગુજરાતી #ಕನ್ನಡ #മലയാളം #ଓଡ଼ିଆ #ਪੰਜਾਬੀ #සිංහල #தமிழ் #తెలుగు": [
                "বাংলা", "ગુજરાતી", "ಕನ್ನಡ", "മലയാളം", "ଓଡ଼ିଆ", "ਪੰਜਾਬੀ", "සිංහල", "தமிழ்", "తెలుగు",
            ],
            "#ผู้เริ่ม #การเมือง #รายละเอียด #นักท่องเที่ยว #ของขวัญ #สนามบิน #เดินทาง #ประธาน": [
                "ผู้เริ่ม", "การเมือง", "รายละเอียด", "นักท่องเที่ยว", "ของขวัญ", "สนามบิน", "เดินทาง", "ประธาน",
            ],
            "#བོད་སྐད་ #བོད་སྐད": ["བོད་སྐད་", "བོད་སྐད"],
            "#មហាត្មះគន្ធី #မြင့်မြတ်သော #ຊີວະສາດ": ["មហាត្មះគន្ធី", "မြင့်မြတ်သော", "ຊີວະສາດ"],
            "#עַל־יְדֵי #וכו׳ #מ״כ": ["עַל־יְדֵי", "וכו׳", "מ״כ"],
            "#أي\u200cبي\u200cإم #می\u200cخواهم": ["أي\u200cبي\u200cإم", "می\u200cخواهم"],
            "#ශ්\u200dරීලංකා": ["ශ්\u200dරීලංකා"],
            "#𖼄𖽑": ["𖼄𖽑"],
            "#il·lusió": ["il·lusió"],
            "#メ～テレ ハッシュタグ内で～が認識されず": ["メ～テレ"],
            "#云々 #学問のすゝめ #いすゞ #各〻 #各〃": ["云々", "学問のすゝめ", "いすゞ", "各〻", "各〃"],
        }
        for kind, cases in (("mention", mentions), ("hashtag", hashtags)):
            for text, expected in cases.items():
                with self.subTest(text=text):
                    self.assertEqual(marked(text, kind), expected)

    def test_encrypt_marks_each_entity_kind(self):
        fields = encrypt("@xdev #api $X a@b.co https://x.com")
        # RichTextContent variants: 1 hashtag, 2 cashtag, 3 mention, 4 url, 5 email.
        self.assertEqual(sent_entities(fields), [(0, 5, 3), (6, 10, 1), (11, 13, 2), (14, 20, 5), (21, 34, 4)])


def session_encrypt(*argv: str, **options) -> dict:
    """session-encrypt on the vector thread as user 2222, with these flags and extra stdin options."""
    body = {"conversation_id": "1111:2222", **encrypted_thread([SDK_KEY]), **options}
    return run_cli("--juicebox", "{}", "session-encrypt", *argv, pin=PIN, stdin=body)


def sent_create(fields: dict) -> tuple[dict, tuple[int, dict]]:
    """An encrypt payload's message create event and its opened (entry variant, fields)."""
    key = base64.b64decode(VECTORS["conversation_key"])
    event, _ = xchat_lite._thrift_value(base64.b64decode(fields["encoded_message_create_event"]), 0, STRUCT)
    holder, _ = xchat_lite._thrift_value(xchat_lite._open_box(key, event[100]), 0, STRUCT)
    return event, next(iter(holder[1].items()))


class SessionEncryptActionTest(unittest.TestCase):
    def test_plain_message_is_marked_as_a_message(self):
        fields = session_encrypt(text="hello", ttl_msec=60000)
        event, (variant, contents) = sent_create(fields)
        self.assertEqual((fields["action"], variant, contents[1], event[103]), ("message", 1, b"hello", 60000))

    def test_reply_carries_a_preview_of_the_target(self):
        fields = session_encrypt(text="pong", reply_to="1")
        _, (variant, contents) = sent_create(fields)
        self.assertEqual((fields["action"], fields["target_sequence_id"], variant), ("reply", "1", 1))
        self.assertEqual(contents[4][2], MESSAGE_TEXT.encode())
        self.assertEqual(contents[4][6], b"1")

    def test_reply_target_can_be_its_message_id(self):
        fields = session_encrypt(text="pong", reply_to="2c2a1d32-988b-4b0e-9e63-c3baab3003fd")
        self.assertEqual(fields["target_sequence_id"], "1")

    def test_reaction_add_and_remove(self):
        added = session_encrypt(reaction={"target": "1", "emoji": "👍"})
        removed = session_encrypt(reaction={"target": "1", "emoji": "👍", "remove": True})
        self.assertEqual((added["action"], removed["action"]), ("reaction", "reaction_removed"))
        self.assertEqual(sent_create(added)[1], (2, {1: b"1", 2: "👍".encode()}))
        self.assertEqual(sent_create(removed)[1][0], 3)

    def test_edit_replaces_the_text_with_entities(self):
        fields = session_encrypt(text="see @xdev", edit="1")
        _, (variant, edit) = sent_create(fields)
        self.assertEqual((fields["action"], variant, edit[1], edit[2]), ("edit", 4, b"1", b"see @xdev"))
        self.assertEqual([(e[1], e[2]) for e in edit[3]], [(4, 9)])

    def test_unknown_target_or_conflicting_options_fail(self):
        for options in (
            {"text": "x", "reply_to": "999"},
            {"text": "x", "reply_to": "1", "edit": "1"},
            {"reaction": {"target": "1", "emoji": "👍"}, "ttl_msec": 1},
        ):
            with self.subTest(options=options), self.assertRaises(SystemExit):
                session_encrypt(**options)

    def test_id_is_the_hyphen_form_send_chat_message_takes(self):
        for conversation_id in ("1111:2222", "2222-1111", "1111"):
            with self.subTest(conversation_id=conversation_id):
                self.assertEqual(session_encrypt(conversation_id=conversation_id, text="hi")["id"], "1111-2222")


class ConversationIdTest(unittest.TestCase):
    def test_one_to_one_ids_canonicalize_as_chat_xdk_does(self):
        cases = {
            ("111-222", "111"): "111:222",
            ("222-111", "111"): "111:222",
            ("222:111", "111"): "111:222",
            ("10-9", "9"): "9:10",
            ("222", "111"): "111:222",
            ("111", "111"): "111:111",
            ("g2031597666757378493", "111"): "g2031597666757378493",
        }
        for (conversation_id, user_id), expected in cases.items():
            with self.subTest(conversation_id=conversation_id, user_id=user_id):
                self.assertEqual(xchat_lite._canonical_conversation_id(conversation_id, user_id), expected)


class JuiceboxConfigTest(unittest.TestCase):
    def unlock(self, juicebox: str) -> list[str]:
        """Run unlock-check with this --juicebox and return the configs Chat was built with."""
        configs = []

        class ConfigChat(OfflineChat):
            def __init__(self, juicebox_config: str = "") -> None:
                configs.append(juicebox_config)
                super().__init__(juicebox_config)

        run_cli("--juicebox", juicebox, "unlock-check", pin=PIN, chat=ConfigChat)
        return configs

    def test_long_inline_config_reaches_the_sdk(self):
        config = json.dumps(
            {
                "key_store_token_map_json": json.dumps({"realms": [{"id": "a" * 32, "address": "https://realm/"}]}),
                "token_map": [{"key": "a" * 32, "value": {"address": "https://realm/", "token": "t" * 5000}}],
            }
        )
        self.assertEqual(self.unlock(config), [config])
        self.assertEqual(self.unlock(f"  {config}\n"), [config])

    def test_config_file_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "juicebox.json")
            path.write_text('{"token_map": []}')
            self.assertEqual(self.unlock(str(path)), ['{"token_map": []}'])

    def test_unreadable_config_file_fails_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in (str(Path(tmp, "missing.json")), tmp, "x" * 300):
                with self.subTest(path=path[:40]):
                    with self.assertRaises(SystemExit) as raised:
                        self.unlock(path)
                    message = str(raised.exception)
                    self.assertIn("juicebox", message)
                    self.assertNotIn(path, message)
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertTrue(raised.exception.__suppress_context__)


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


class UnlockErrorTest(unittest.TestCase):
    def unlock_failing_with(self, error: Exception) -> str:
        class FailingChat(OfflineChat):
            def unlock(self, pin: str) -> None:
                raise error

        with self.assertRaises(SystemExit) as raised:
            run_cli("--juicebox", "{}", "unlock-check", pin=PIN, chat=FailingChat)
        self.assertTrue(raised.exception.__suppress_context__)
        return str(raised.exception)

    def test_wrong_pin_says_how_many_guesses_are_left(self):
        wrong = chat_xdk.InvalidPinError("Invalid PIN")
        wrong.guesses_remaining = 2
        self.assertEqual(self.unlock_failing_with(wrong), "The Chat PIN is wrong; 2 guess(es) left before the keys lock")
        uncounted = chat_xdk.InvalidPinError("Invalid PIN")
        uncounted.guesses_remaining = None
        self.assertEqual(self.unlock_failing_with(uncounted), "The Chat PIN is wrong")

    def test_other_sdk_failures_are_one_line(self):
        failure = chat_xdk.JuiceboxError("Juicebox error: Transient error")
        failure.kind = "juicebox"
        self.assertEqual(
            self.unlock_failing_with(failure), "Could not unlock the X Chat keys (juicebox): Juicebox error: Transient error"
        )

    def test_a_user_id_that_is_not_numeric_fails_with_a_message(self):
        with (
            self.assertRaises(SystemExit) as raised,
            mock.patch.object(xchat_lite, "Chat", OfflineChat),
            mock.patch.dict(os.environ, {"CHAT_PIN": PIN}),
        ):
            xchat_lite._open_session(argparse.Namespace(user_id="me", key_version="1", juicebox="{}", remember_key=False))
        self.assertIn("Invalid user_id 'me'", str(raised.exception))


PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + b"pixels"


def encrypted_media_message(media_hash_key: str) -> tuple[str, bytes]:
    """An unsigned message encrypted under the vector conversation key carrying one image, and PNG
    encrypted as that image."""
    attachment = {
        "attachment_type": "media",
        "media_hash_key": media_hash_key,
        "width": 1,
        "height": 1,
        "filesize_bytes": chat_xdk.encrypted_file_size(len(PNG)),
        "filename": "IMG_0001.PNG",
        "media_type": 1,
    }
    payload = vector_message("look", attachments=[attachment])
    blob = vector_chat().encrypt_file(
        chat_xdk.EncryptFileParams(
            PNG,
            payload.event_b64,
            media_hash_key,
            conversation_key=base64.b64decode(VECTORS["conversation_key"]),
            conversation_key_version="1001",
        )
    )
    return _message_event(base64.b64decode(payload.encoded_message_create_event), SENDER_ID, "1111:2222"), blob


def tool_text(blob: bytes, **overrides) -> dict:
    """The chat_media_download tool's text for these downloaded bytes."""
    text = {
        "content_type": "application/octet-stream",
        "size_bytes": len(blob),
        "encoding": "base64",
        "data": base64.b64encode(blob).decode(),
    }
    text.update(overrides)
    return text


def tool_result(text) -> dict:
    """An MCP tools/call result whose text item is `text` (a dict is serialized)."""
    return {"content": [{"type": "text", "text": text if isinstance(text, str) else json.dumps(text)}]}


class DecryptMediaTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def saved(self, name: str, content) -> str:
        """Path of a file holding `content`: bytes as is, anything else as JSON."""
        path = self.tmp / name
        path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
        return str(path)

    def run_media(self, events: list[str], media: list[dict], *argv: str) -> dict:
        stdin = {"conversation_key_events": [VECTORS["key_change_event"]], "events": events, "media": media}
        return run_cli("--juicebox", "{}", "decrypt-media", *argv, pin=PIN, stdin=stdin)

    def test_decrypts_a_downloaded_image_with_its_message(self):
        event, blob = encrypted_media_message("AGgkIbPRTG")
        saved_results = {
            "the tool text a harness saved": tool_text(blob),
            "a whole JSON-RPC response": {"jsonrpc": "2.0", "id": 1, "result": tool_result(tool_text(blob))},
        }
        for shape, content in saved_results.items():
            with self.subTest(shape):
                out_dir = self.tmp / shape.replace(" ", "-")
                result = self.run_media(
                    [event],
                    [{"media_hash_key": "AGgkIbPRTG", "input": self.saved("result.json", content)}],
                    "--out-dir",
                    str(out_dir),
                )
                self.assertEqual(result["errors"], {})
                [media] = result["media"]
                path = Path(media["path"])
                self.assertEqual(path, out_dir / "AGgkIbPRTG.png")
                self.assertEqual(path.read_bytes(), PNG)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(
                    {k: media[k] for k in ("mime_type", "size_bytes", "media_type", "sender_id")},
                    {"mime_type": "image/png", "size_bytes": len(PNG), "media_type": "image", "sender_id": SENDER_ID},
                )

    def test_each_media_that_cannot_be_decrypted_gets_an_error(self):
        event, blob = encrypted_media_message("AGgkIbPRTG")
        other_key = chat_xdk.Chat().encrypt_file_with_key(chat_xdk.EncryptFileWithKeyParams(PNG, os.urandom(32)))
        forbidden = {"title": "Forbidden", "detail": "Missing required OAuth2 scopes: media.write"}
        too_large = {**tool_result("Failed to read response body: length limit exceeded"), "isError": True}
        media = [
            {"media_hash_key": "AGgkIbPRTG", "input": self.saved("403.json", tool_result(forbidden))},
            {"media_hash_key": "AGgkIbPRTG", "input": self.saved("too-large.json", too_large)},
            {"media_hash_key": "AGgkIbPRTG", "input": self.saved("lossy.json", tool_result("\ufffdPNG\ufffd"))},
            {"media_hash_key": "AGgkIbPRTG", "input": self.saved("wrong-key.json", tool_text(other_key))},
            {"media_hash_key": "AGgkIbPRTG", "input": self.saved("short.json", tool_text(blob, size_bytes=len(blob) + 1))},
            {"media_hash_key": "Unknown1", "input": self.saved("other.json", tool_text(blob))},
        ]
        result = self.run_media([event], media, "--out-dir", str(self.tmp))
        self.assertEqual(result["media"], [])
        self.assertEqual(
            result["errors"],
            {
                "0": "download failed: Missing required OAuth2 scopes: media.write",
                "1": "download failed: Failed to read response body: length limit exceeded",
                "2": "not a chat_media_download result",
                "3": result["errors"]["3"],
                "4": f"download holds {len(blob)} bytes, not {len(blob) + 1}",
                "5": "no decrypted message references this media_hash_key; include its event",
            },
        )
        self.assertIn("Decryption failed", result["errors"]["3"])
        self.assertEqual(list(self.tmp.glob("AGgkIbPRTG*")), [])

    def test_media_of_an_unencrypted_message_is_written_as_downloaded(self):
        event = plain_entry_event(1, _text(1, "look"), _list(3, media(1)))
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.tmp)}):
            result = self.run_media([event], [{"media_hash_key": "hash-key", "input": self.saved("raw.bin", PNG)}])
        self.assertEqual(result["errors"], {})
        media_dir = self.tmp / "xchat-grokbot-helper" / "media"
        self.assertEqual(Path(result["media"][0]["path"]), media_dir / "hashkey.png")
        self.assertEqual((media_dir / "hashkey.png").read_bytes(), PNG)
        self.assertEqual(stat.S_IMODE(media_dir.stat().st_mode), 0o700)


def png(width: int, height: int, size: int = 64) -> bytes:
    """A PNG header for this width and height, padded to `size` bytes."""
    header = bytes.fromhex("89504e470d0a1a0a0000000d49484452") + struct.pack(">II", width, height)
    return header + bytes(size - len(header))


# A JPEG start of frame for 640x480, and a GIF header for 320x240.
JPEG = bytes.fromhex("ffd8ffc000110801e0028003") + bytes(20)
GIF = b"GIF89a" + struct.pack("<HH", 320, 240) + bytes(20)


def parts_bytes(item: dict) -> bytes:
    """The encrypted image a session-encrypt media item's part files add up to."""
    return b"".join(base64.b64decode(Path(part["path"]).read_text()) for part in item["parts"])


class PrepareMediaTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def saved(self, name: str, content: bytes) -> str:
        path = self.tmp / name
        path.write_bytes(content)
        return str(path)

    def run_prepare(self, media: list, signing_keys=(SDK_KEY,), conversation_id="1111:2222") -> dict:
        stdin = {"conversation_id": conversation_id, **encrypted_thread(list(signing_keys)), "media": media}
        result = run_cli("--juicebox", "{}", "prepare-media", pin=PIN, stdin=stdin)
        self.assertNotIn(VECTORS["conversation_key"], json.dumps(result))
        return result

    def test_gives_the_encrypted_size_without_encrypting(self):
        result = self.run_prepare([{"input": self.saved("photo.png", png(640, 480, 200_000))}])

        self.assertEqual(result["errors"], {})
        self.assertNotIn("upload_dir", result)
        [item] = result["media"]
        self.assertEqual(
            {k: v for k, v in item.items() if k != "input"},
            {
                "filename": "photo.png",
                "mime_type": "image/png",
                "width": 640,
                "height": 480,
                "size_bytes": 200_000,
                "total_bytes": chat_xdk.encrypted_file_size(200_000),
                "conversation_key_version": "1001",
            },
        )
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["photo.png"])

    def test_upload_conversation_id_is_the_colon_form_the_upload_tools_take(self):
        photo = self.saved("photo.png", png(1, 1))
        for conversation_id in ("1111:2222", "2222-1111", "1111"):
            with self.subTest(conversation_id=conversation_id):
                result = self.run_prepare([{"input": photo}], conversation_id=conversation_id)
                self.assertEqual(result["upload_conversation_id"], "1111:2222")

    def test_each_file_that_is_not_an_allowed_image_gets_an_error(self):
        media = [
            {"input": self.saved("doc.pdf", b"%PDF-1.4 not an image")},
            {"input": self.saved("logo.bmp", b"BM" + bytes(30))},
            {"input": self.saved("huge.png", png(1, 1, xchat_lite._MAX_IMAGE_BYTES + 1))},
            {"input": self.saved("cut.png", png(1, 1)[:16])},
            {"input": str(self.tmp / "missing.png")},
            {},
            {"input": self.saved("photo.jpg", JPEG), "filename": "IMG_0001.JPG"},
            {"input": self.saved("wave.gif", GIF)},
        ]
        result = self.run_prepare(media)

        errors = result["errors"]
        self.assertIn("No such file", errors.pop("4"))
        self.assertEqual(
            errors,
            {
                "0": "not a PNG, JPEG, GIF or WebP image (application/pdf)",
                "1": "not a PNG, JPEG, GIF or WebP image (image/bmp)",
                "2": f"image is {xchat_lite._MAX_IMAGE_BYTES + 1} bytes, over the {xchat_lite._MAX_IMAGE_BYTES}-byte limit",
                "3": "can't read the width and height of this image/png image",
                "5": "needs input, the image's path",
            },
        )
        self.assertEqual(
            [(m["filename"], m["mime_type"], m["width"], m["height"]) for m in result["media"]],
            [("IMG_0001.JPG", "image/jpeg", 640, 480), ("wave.gif", "image/gif", 320, 240)],
        )

    def test_the_latest_key_change_alone_is_enough(self):
        photo = self.saved("photo.png", png(1, 1))
        for where in ("conversation_key_events", "events"):
            with self.subTest(where=where):
                stdin = {
                    "conversation_id": "1111-2222",
                    where: [VECTORS["key_change_event"]],
                    "signing_keys": [SDK_KEY],
                    "media": [{"input": photo}],
                }
                result = run_cli("--juicebox", "{}", "prepare-media", pin=PIN, stdin=stdin)
                self.assertEqual((result["errors"], result["media"][0]["conversation_key_version"]), ({}, "1001"))

    def test_needs_a_verified_conversation_key(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_prepare([{"input": self.saved("photo.png", png(1, 1))}], signing_keys=())

        self.assertIn("signing_keys", str(raised.exception))

    def test_encrypt_media_is_hidden_and_exits_with_one_line(self):
        def script(*argv: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, xchat_lite.__file__, *argv], input="{}", capture_output=True, text=True, timeout=60
            )

        removed = script("--user-id", "2222", "encrypt-media", "--out-dir", str(self.tmp), "--part-bytes", "65536")
        self.assertEqual(removed.returncode, 1)
        self.assertEqual(removed.stdout, "")
        [line] = removed.stderr.splitlines()
        self.assertIn("removed with chatxdk 0.7", line)
        self.assertIn("prepare-media", line)
        self.assertIn("session-encrypt", line)
        self.assertNotIn("encrypt-media", script("--help").stdout)


class FeatureServer:
    """A local GET /2/chat/features that turns v1_send on for every chat pointed at it."""

    def __init__(self) -> None:
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"features":{"v1_send":true}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/2/chat/features"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def chat_sending_v1() -> chat_xdk.Chat:
    """A chat for user 2222, as the CLI runs, once it sends v1 (signature version 10).

    While it lives, chats created for the same user share its feature switches and send v1 at once.
    """
    chat = vector_chat()
    chat.set_identity(chat_xdk.SetIdentityParams("2222", "1"))
    params = chat_xdk.EncryptMessageParams(
        "1111:2222", "probe", conversation_key=base64.b64decode(VECTORS["conversation_key"]),
        conversation_key_version="1001",
    )
    deadline = time.monotonic() + 10
    while chat.encrypt_message(params).signature_info.signature_version != "10":
        if time.monotonic() > deadline:
            raise AssertionError("the chat never turned v1 on")
        time.sleep(0.01)
    return chat


def turn_v1_on(test: unittest.TestCase) -> None:
    """Have the X API's v1_send switch on for the rest of this test, so sends use per-message keys."""
    server = FeatureServer()
    test.addCleanup(server.close)
    chat_xdk._native._feature_set_default_endpoint(server.url)
    test.addCleanup(chat_xdk._native._feature_set_default_endpoint, OFFLINE_FEATURES)
    test.v1_chat = chat_sending_v1()


def received(fields: dict) -> str:
    """A session-encrypt result as recipients receive it: sent by 2222 under its message id."""
    create = base64.b64decode(fields["encoded_message_create_event"])
    return _message_event(create, "2222", "1111:2222", event_id=fields["message_id"])


class V1SendTest(unittest.TestCase):
    def setUp(self) -> None:
        turn_v1_on(self)

    def test_message_reply_reaction_and_edit_read_back(self):
        sent = {
            "message": session_encrypt(text="hello"),
            "reply": session_encrypt(text="pong", reply_to="1"),
            "reaction": session_encrypt(reaction={"target": "1", "emoji": "👍"}),
            "edit": session_encrypt(text="fixed", edit="1"),
        }
        thread = {**encrypted_thread([SDK_KEY]), "events": [VECTORS["message_event"], *map(received, sent.values())]}
        rows = run_decrypt(thread)["messages"][2:]

        self.assertEqual(texts({"messages": rows}), ["hello", "pong", "reacted 👍 to 1", "edited 1: fixed"])
        # A v1 edit also names the signed message id it edits, which is not what the text shows.
        self.assertEqual(rows[3]["event"]["content"]["target_message_id"], "2c2a1d32-988b-4b0e-9e63-c3baab3003fd")
        self.assertEqual(rows[3]["event"]["content"]["target_message_sequence_id"], "1")
        for name, fields in sent.items():
            with self.subTest(name):
                created, _ = xchat_lite._thrift_value(base64.b64decode(fields["encoded_message_create_event"]), 0, STRUCT)
                self.assertEqual(created.get(112), 1)


class PrepareKeysTest(unittest.TestCase):
    KEYS = {"identity_public_key": VECTORS["identity_public_key"], "public_key_version": "1"}

    def test_takes_either_key_field_names_and_passes_the_request_fields_through(self):
        shapes = {
            "get_users_public_keys names": [
                {"user_id": "1111", "public_key": VECTORS["identity_public_key"], "public_key_version": "1"},
                {"user_id": "2222", "public_key": VECTORS["identity_public_key"], "key_version": 1},
            ],
            "chat-xdk names": [{"user_id": "1111", **self.KEYS}, {"user_id": "2222", **self.KEYS}],
        }
        for shape, public_keys in shapes.items():
            with self.subTest(shape):
                body = run_cli("--juicebox", "{}", "prepare-keys", pin=PIN,
                               stdin={"conversation_id": "1111-2222", "public_keys": public_keys})
                self.assertEqual(
                    sorted(body), ["_local_conversation_key_b64", "action_signatures", "conversation_key_version",
                                   "conversation_participant_keys"],
                )
                self.assertEqual(
                    sorted((k["user_id"], k["public_key_version"]) for k in body["conversation_participant_keys"]),
                    [("1111", "1"), ("2222", "1")],
                )
                [action] = body["action_signatures"]
                self.assertEqual(
                    sorted(action["message_event_signature"]),
                    ["public_key_version", "signature", "signature_version", "signing_public_key"],
                )

    def test_first_message_goes_with_the_add_conversation_keys_body(self):
        public_keys = [{"user_id": "1111", **self.KEYS}, {"user_id": "2222", **self.KEYS}]
        out = run_cli("--juicebox", "{}", "session-encrypt", pin=PIN,
                      stdin={"conversation_id": "1111-2222", "text": "hi", "prepare": {"public_keys": public_keys}})

        self.assertTrue(out["needs_add_conversation_keys_before_send"])
        self.assertNotIn("_local_conversation_key_b64", out["add_conversation_keys"])
        self.assertEqual(len(out["add_conversation_keys"]["conversation_participant_keys"]), 2)
        self.assertTrue(out["encoded_message_create_event"])


class SessionEncryptMediaTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "out"
        self.photo = self.tmp / "photo.png"
        self.photo.write_bytes(png(640, 480, 5000))
        self.entry = {"media_hash_key": "AGgkIbPRTG", "input": str(self.photo)}

    def saved(self, name: str, content: bytes) -> str:
        path = self.tmp / name
        path.write_bytes(content)
        return str(path)

    def test_media_is_sent_as_an_image_attachment(self):
        fields = session_encrypt("--out-dir", str(self.out), text="look", media=[self.entry])
        _, (variant, contents) = sent_create(fields)
        [attachment] = contents[3]

        self.assertEqual((fields["action"], variant, contents[1]), ("message", 1, b"look"))
        self.assertTrue(fields["message_id"])
        total_bytes = chat_xdk.encrypted_file_size(5000)
        sha256 = hashlib.sha256(self.photo.read_bytes()).digest()
        self.assertEqual(
            attachment[1],
            {1: b"AGgkIbPRTG", 2: {1: 640, 2: 480}, 3: 1, 5: total_bytes, 6: b"photo.png", 11: sha256},
        )
        self.assertEqual(
            xchat_lite._attachment_from_thrift(attachment),
            {"filename": "photo.png", "attachment_type": "Media", "media_type": "image"},
        )
        [item] = fields["media"]
        self.assertEqual(
            {k: v for k, v in item.items() if k != "parts"},
            {"media_hash_key": "AGgkIbPRTG", "filename": "photo.png", "total_bytes": total_bytes, "num_parts": 1},
        )
        self.assertEqual(len(parts_bytes(item)), total_bytes)
        upload_dir = Path(fields["upload_dir"])
        self.assertEqual((upload_dir.parent, stat.S_IMODE(upload_dir.stat().st_mode)), (self.out, 0o700))
        self.assertNotIn(VECTORS["conversation_key"], json.dumps(fields))

    def test_parts_are_4_mib_by_default_or_part_bytes(self):
        big = {**self.entry, "input": self.saved("big.png", png(4000, 3000, 4_500_000))}
        [item] = session_encrypt("--out-dir", str(self.out), media=[big])["media"]
        sizes = [len(base64.b64decode(Path(part["path"]).read_text())) for part in item["parts"]]
        self.assertEqual(sizes, [4 * 1024 * 1024, item["total_bytes"] - 4 * 1024 * 1024])

        mid = {**self.entry, "input": self.saved("mid.png", png(640, 480, 200_000))}
        fields = session_encrypt("--out-dir", str(self.out), "--part-bytes", "65536", media=[mid])
        [item] = fields["media"]
        self.assertEqual([part["segment_index"] for part in item["parts"]], [0, 1, 2, 3])
        for part in item["parts"]:
            path = Path(part["path"])
            self.assertEqual((str(path.parent), stat.S_IMODE(path.stat().st_mode)), (fields["upload_dir"], 0o600))
            self.assertLessEqual(len(base64.b64decode(path.read_text())), 65536)

    def test_photo_without_a_caption_and_as_a_reply(self):
        photo = session_encrypt(media=[self.entry])
        reply = session_encrypt(text="here", reply_to="1", media=[{**self.entry, "filename": "chart.png"}])
        _, (_, photo_contents) = sent_create(photo)
        _, (_, reply_contents) = sent_create(reply)

        self.assertEqual((photo["action"], photo_contents[1], photo_contents[3][0][1][6]), ("message", b"", b"photo.png"))
        self.assertEqual(
            (reply["action"], reply_contents[1], reply_contents[3][0][1][6], reply_contents[4][6]),
            ("reply", b"here", b"chart.png", b"1"),
        )
        self.assertEqual([item["filename"] for item in reply["media"]], ["chart.png"])

    def test_bad_media_fails(self):
        notes = self.tmp / "notes.txt"
        notes.write_text("hello, not an image")
        for options in (
            {"media": [{"input": str(self.photo)}]},
            {"media": [{**self.entry, "input": str(notes)}]},
            {"media": ["AGgkIbPRTG"]},
            {"text": "x", "edit": "1", "media": [self.entry]},
            {"reaction": {"target": "1", "emoji": "👍"}, "media": [self.entry]},
        ):
            with self.subTest(options=options), self.assertRaises(SystemExit):
                session_encrypt(**options)

    def test_media_prepared_under_another_conversation_key_fails(self):
        with self.assertRaises(SystemExit) as raised:
            session_encrypt(text="look", media=[{**self.entry, "conversation_key_version": "1000"}])
        self.assertIn("run prepare-media again", str(raised.exception))

    def send_and_read_back(self, image: bytes) -> tuple[dict, dict, bytes]:
        """prepare-media, then session-encrypt with its result, as the README's image flow runs them.

        Returns session-encrypt's output, the sent message's create event, and the image read back from
        the upload parts by decrypt-media.
        """
        stdin = {"conversation_id": "1111:2222", **encrypted_thread([SDK_KEY]), "media": [{"input": self.saved("upload.png", image)}]}
        [item] = run_cli("--juicebox", "{}", "prepare-media", pin=PIN, stdin=stdin)["media"]
        sent = session_encrypt("--out-dir", str(self.out), "--part-bytes", "65536", text="look",
                               media=[{**item, "media_hash_key": "AGgkIbPRTG"}])
        [uploaded] = sent["media"]
        self.assertEqual(uploaded["total_bytes"], item["total_bytes"])
        create = base64.b64decode(sent["encoded_message_create_event"])
        event = _message_event(create, "2222", "1111:2222", event_id=sent["message_id"])
        thread = {"conversation_key_events": [VECTORS["key_change_event"]], "events": [event]}
        self.assertEqual(texts(run_decrypt(thread))[-1], "[photo] look")
        download = self.saved("download.json", json.dumps(tool_text(parts_bytes(uploaded))).encode())
        media = [{"media_hash_key": "AGgkIbPRTG", "input": download}]
        result = run_cli("--juicebox", "{}", "decrypt-media", "--out-dir", str(self.tmp / "down"), pin=PIN,
                         stdin={**thread, "media": media})
        self.assertEqual(result["errors"], {})
        created, _ = xchat_lite._thrift_value(create, 0, STRUCT)
        return sent, created, Path(result["media"][0]["path"]).read_bytes()

    def test_upload_reads_back_with_decrypt_media(self):
        image = png(640, 480, 70_000)
        sent, created, read_back = self.send_and_read_back(image)

        self.assertEqual(read_back, image)
        self.assertNotIn(112, created)
        self.assertTrue(sent["xdk_version"])

    def test_upload_reads_back_when_the_x_api_turns_v1_on(self):
        # Under per-message keys (v1) each file's key is derived from its message and attachment,
        # which is why session-encrypt, not prepare-media, encrypts it.
        turn_v1_on(self)
        image = png(640, 480, 70_000)
        sent, created, read_back = self.send_and_read_back(image)

        self.assertEqual(created.get(112), 1, "the message was not sent with a per-message key")
        self.assertEqual(read_back, image)
        key = base64.b64decode(VECTORS["conversation_key"])
        with self.assertRaises(chat_xdk.DecryptionError):
            chat_xdk.Chat().decrypt_file_with_key(
                chat_xdk.DecryptFileWithKeyParams(parts_bytes(sent["media"][0]), key)
            )


if __name__ == "__main__":
    unittest.main()
