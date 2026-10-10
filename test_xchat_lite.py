import argparse
import base64
import io
import json
import os
import struct
import unittest
from contextlib import redirect_stdout
from unittest import mock

import chat_xdk

import xchat_lite

STOP, BOOL, I32, STRING, STRUCT = 0, 2, 8, 11, 12

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


KEYED_DETAILS = {
    "message": (_variant(1, _text(100, "contents"), _text(101, "1001")), "1001"),
    "key change": (_variant(3, _text(1, "1002")), "1002"),
    "group create": (_group_change(1, _text(3, "title"), _text(5, "1003")), "1003"),
    "group title": (_group_change(2, _text(1, "title"), _text(2, "1004")), "1004"),
    "group avatar": (_group_change(3, _text(1, "url"), _text(2, "1005")), "1005"),
    "group member add": (_group_change(5, _text(4, "title"), _text(6, "1006")), "1006"),
    "group description": (_group_change(14, _text(1, "about"), _text(2, "1007")), "1007"),
    "grok message": (_variant(15, _text(1, "cipher"), _text(5, "1008")), "1008"),
    "pin": (_variant(17, _text(1, "contents"), _text(2, "pmk"), _text(3, "1009")), "1009"),
}

UNKEYED_DETAILS = {
    "message": _variant(1, _text(100, "contents")),
    "group create": _group_change(1, _text(3, "title")),
    "group member remove": _group_change(7),
    "group description": _group_change(14, _text(1, "about")),
    "read receipt": _variant(12, _text(1, "299")),
    "grok reply": _variant(16, _text(6, "plaintext reply")),
    "unknown detail": _variant(18),
}


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

    def __init__(self, juicebox_config: str) -> None:
        self._chat = chat_xdk.Chat()

    def unlock(self, pin: str) -> None:
        self._chat.import_keys(base64.b64decode(VECTORS["private_keys"]), version="1")

    def __getattr__(self, name: str):
        return getattr(self._chat, name)


class RecordingChat(OfflineChat):
    """Records each decrypt_events batch and whether it rejected unverified events."""

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
    args = argparse.Namespace(user_id="2222", key_version="1", juicebox="{}")
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


class EventClassificationTest(unittest.TestCase):
    def key_version(self, detail: bytes) -> str | None:
        return xchat_lite._event_info(_event(detail))["key_version"]

    def test_details_that_carry_a_key_version(self):
        for name, (detail, version) in KEYED_DETAILS.items():
            with self.subTest(name):
                self.assertEqual(self.key_version(detail), version)

    def test_details_without_a_key_version(self):
        for name, detail in UNKEYED_DETAILS.items():
            with self.subTest(name):
                self.assertIsNone(self.key_version(detail))

    def test_an_empty_key_version_still_counts(self):
        detail = _variant(1, _text(100, "contents"), _text(101, ""))
        self.assertEqual(self.key_version(detail), "")

    def test_only_a_string_key_version_counts(self):
        numeric = _field(I32, 101, struct.pack(">i", 1001))
        self.assertIsNone(self.key_version(_variant(1, _text(100, "contents"), numeric)))

    def test_undecodable_payloads_are_unclassified(self):
        truncated = _event(KEYED_DETAILS["message"][0])[:16]
        for payload in ("ENCODED_100", "", truncated):
            with self.subTest(payload):
                self.assertIsNone(xchat_lite._event_info(payload))


class VerificationPolicyTest(unittest.TestCase):
    def test_events_carrying_a_key_version_take_the_strict_pass(self):
        keyed = [_event(detail) for detail, _ in KEYED_DETAILS.values()]
        keyed.append(_event(_variant(1, _text(100, "contents"), _text(101, ""))))
        unkeyed = [_event(detail) for detail in UNKEYED_DETAILS.values()]
        chat = RecordingChat("{}")
        xchat_lite._decrypt(chat, {"events": keyed + unkeyed})

        self.assertEqual(chat.batches, [(True, keyed), (False, unkeyed)])

    def test_unsigned_group_description_change_naming_a_key_version_is_rejected(self):
        keyed = _event(KEYED_DETAILS["group description"][0])
        unkeyed = _event(UNKEYED_DETAILS["group description"])
        result = run_decrypt({"events": [keyed, unkeyed]})

        self.assertIn("signature", result["errors"]["0"].lower())
        self.assertEqual([m["event"]["type"] for m in result["messages"]], ["GroupChange"])

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

    def test_encrypted_message_without_a_verifiable_key_has_no_text(self):
        result = run_decrypt(encrypted_thread([]))

        self.assertNotIn(MESSAGE_TEXT, json.dumps(result))
        [message] = result["messages"]
        self.assertEqual(message["status"], "unverified")
        self.assertEqual(message["event"]["sender_id"], SENDER_ID)
        self.assertIn("signature", message["error"].lower())
        self.assertEqual(result["unverified_senders"], [SENDER_ID])

    def test_message_naming_a_key_version_is_verified_even_when_decryptable(self):
        payload = encrypted_thread([mcp_key()])
        payload["events"] = [unsigned_encrypted_message_event("forged without a signature")]
        result = run_decrypt(payload)

        self.assertNotIn("forged without a signature", json.dumps(result))
        self.assertEqual(
            summary(result),
            [("KeyChange", "verified", ""), ("Message", "unverified", "")],
        )
        self.assertEqual(result["unverified_senders"], [SENDER_ID])

    def test_policy_is_chosen_per_event(self):
        payload = encrypted_thread([])
        payload["events"].append({"encoded_event": unencrypted_message_event("plain", "222")})
        result = run_decrypt(payload)

        self.assertEqual(
            summary(result),
            [("Message", "unverified", ""), ("Message", "unencrypted", "plain")],
        )
        self.assertEqual(result["unverified_senders"], [SENDER_ID])


if __name__ == "__main__":
    unittest.main()
