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

STOP, BOOL, STRING, STRUCT = 0, 2, 11, 12


def _field(ftype: int, fid: int, payload: bytes) -> bytes:
    return struct.pack(">bh", ftype, fid) + payload


def _string(value: str | bytes) -> bytes:
    raw = value if isinstance(value, bytes) else value.encode()
    return struct.pack(">i", len(raw)) + raw


def _struct(*fields: bytes) -> bytes:
    return b"".join(fields) + bytes([STOP])


def unencrypted_message_event(text: str, sender_id: str = "222") -> str:
    """Base64 Thrift MessageEvent carrying plaintext contents, no key version, no signature."""
    message_contents = _struct(_field(STRING, 1, _string(text)))
    entry_holder = _struct(_field(STRUCT, 1, _struct(_field(STRUCT, 1, message_contents))))
    create_event = _struct(
        _field(STRING, 100, _string(entry_holder)),
        _field(BOOL, 102, b"\x01"),
    )
    event = _struct(
        _field(STRING, 1, _string("1001")),
        _field(STRING, 2, _string("m1")),
        _field(STRING, 3, _string(sender_id)),
        _field(STRING, 4, _string("111-222")),
        _field(STRING, 6, _string("1700000000000")),
        _field(STRUCT, 7, _struct(_field(STRUCT, 1, create_event))),
    )
    return base64.b64encode(event).decode()


class OfflineChat:
    """A real chat_xdk.Chat whose unlock() skips the Juicebox network round trip."""

    def __init__(self, juicebox_config: str) -> None:
        self._chat = chat_xdk.Chat()

    def unlock(self, pin: str) -> None:
        pass

    def __getattr__(self, name: str):
        return getattr(self._chat, name)


def run_decrypt(payload: dict) -> dict:
    args = argparse.Namespace(user_id="111", key_version="1", juicebox="{}")
    out = io.StringIO()
    with (
        mock.patch.object(xchat_lite, "Chat", OfflineChat),
        mock.patch.dict(os.environ, {"CHAT_PIN": "test-pin"}),
        mock.patch("sys.stdin", io.StringIO(json.dumps(payload))),
        redirect_stdout(out),
    ):
        xchat_lite.cmd_decrypt(args)
    return json.loads(out.getvalue())


class DecryptTest(unittest.TestCase):
    def test_unencrypted_message_is_returned_as_a_message(self) -> None:
        result = run_decrypt({"events": [unencrypted_message_event("sent before encryption")]})

        self.assertEqual(result["errors"], {})
        [message] = result["messages"]
        self.assertEqual(message["text"], "sent before encryption")
        self.assertEqual(message["event"]["type"], "Message")
        self.assertEqual(message["event"]["sender_id"], "222")
        self.assertIsNone(message["event"]["key_version"])
        self.assertFalse(message["event"]["verified"])


if __name__ == "__main__":
    unittest.main()
