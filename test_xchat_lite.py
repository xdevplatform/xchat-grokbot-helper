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

STOP, BOOL, STRING, STRUCT = 0, 2, 11, 12

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


def _variant(fid: int, *fields: bytes) -> bytes:
    """A union whose variant `fid` is a struct with these fields."""
    return _struct(_field(STRUCT, fid, _struct(*fields)))


def _group_change(change: int, *fields: bytes) -> bytes:
    """A group change event detail holding GroupChange variant `change`."""
    return _variant(4, _field(STRUCT, 1, _variant(change, *fields)))


def _event(detail: bytes, sender_id: str = "222", conversation_id: str = "111-222") -> str:
    """Base64 Thrift MessageEvent with this detail union, without a signature."""
    event = _struct(
        _field(STRING, 1, _string("2001")),
        _field(STRING, 2, _string("m2")),
        _field(STRING, 3, _string(sender_id)),
        _field(STRING, 4, _string(conversation_id)),
        _field(STRING, 6, _string("1700000000001")),
        _field(STRUCT, 7, detail),
    )
    return base64.b64encode(event).decode()


def _message_event(create_event: bytes, sender_id: str, conversation_id: str) -> str:
    return _event(_struct(_field(STRUCT, 1, create_event)), sender_id, conversation_id)


def unencrypted_message_event(text: str, sender_id: str = "222") -> str:
    """A message with plaintext contents and no conversation key version."""
    message_contents = _struct(_field(STRING, 1, _string(text)))
    entry_holder = _struct(_field(STRUCT, 1, _struct(_field(STRUCT, 1, message_contents))))
    create_event = _struct(
        _field(STRING, 100, _string(entry_holder)),
        _field(BOOL, 102, b"\x01"),
    )
    return _message_event(create_event, sender_id, "111-222")


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
    def test_every_event_is_accepted_in_one_pass(self):
        events = [
            VECTORS["key_change_event"],
            VECTORS["message_event"],
            unencrypted_message_event("plain"),
        ]
        chat = RecordingChat("{}")
        xchat_lite._decrypt(chat, {"events": events})

        self.assertEqual(chat.batches, [(False, events)])

    def test_unsigned_group_description_change_is_returned(self):
        event = _event(_group_change(14, _text(1, "about"), _text(2, "1007")))
        result = run_decrypt({"events": [event]})

        self.assertEqual(result["errors"], {})
        self.assertEqual(summary(result), [("GroupChange", "unverified", "")])

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

    def test_message_that_cannot_be_decrypted_has_no_text(self):
        text = "needs a conversation key"
        result = run_decrypt({"events": [unsigned_encrypted_message_event(text)]})

        self.assertNotIn(text, json.dumps(result))
        [message] = result["messages"]
        self.assertEqual(message["text"], "")
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
