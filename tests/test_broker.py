"""Unprivileged protocol/persistence tests; no namespaces, services, or admin changes."""
import copy
import os
import runpy
import sys
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from argus import broker, collector, integrity


class FragmentedConnection:
    def __init__(self, data=b""):
        self.data = bytearray(data)
        self.sent = b""

    def recv(self, size):
        piece = bytes(self.data[:min(size, 3)])
        del self.data[:len(piece)]
        return piece

    def sendall(self, data):
        self.sent += data


def request(**changes):
    value = {"version": 1, "id": str(uuid.uuid4()), "timestamp": time.time(),
             "source": "printf safe", "cwd": str(Path.cwd()), "environment": {"LANG": "C"}}
    value.update(changes)
    return value


class BrokerProtocolTests(unittest.TestCase):
    def test_fragmented_frame_round_trip(self):
        output = FragmentedConnection()
        broker.send_frame(output, {"message": "multibyte: café", "status": 0})
        self.assertEqual(broker.receive_frame(FragmentedConnection(output.sent)),
                         {"message": "multibyte: café", "status": 0})

    def test_invalid_frames_fail_closed(self):
        for payload in (struct.pack("!I", 0), struct.pack("!I", broker.MAX_FRAME + 1),
                        struct.pack("!I", 3) + b"[] ", struct.pack("!I", 10) + b"{}"):
            with self.subTest(payload=payload):
                with self.assertRaises(broker.BrokerError):
                    broker.receive_frame(FragmentedConnection(payload))

    def test_excessive_json_depth_is_a_protocol_error_for_both_services(self):
        depth = sys.getrecursionlimit() + 100
        payload = b'{"nested":' + b"[" * depth + b"0" + b"]" * depth + b"}"
        frame = struct.pack("!I", len(payload)) + payload
        for consumer in (broker.receive_frame, collector.receive_frame):
            with self.subTest(consumer=consumer.__module__):
                with self.assertRaises(broker.BrokerError):
                    consumer(FragmentedConnection(frame))

    def test_request_validation_rejects_unknown_fields_staleness_and_environment(self):
        broker._validate_request(request())
        for changes in ({"root": True}, {"timestamp": time.time() - 120},
                        {"environment": {"BAD=KEY": "value"}},
                        {"environment": {"LANG": "bad\x00value"}},
                        {"source": "x" * (broker.MAX_SOURCE + 1)}, {"id": "not-a-uuid"}):
            with self.subTest(changes=list(changes)):
                with self.assertRaises(broker.BrokerError):
                    broker._validate_request(request(**changes))

    def test_non_linux_strict_mode_has_no_local_execution_fallback(self):
        with patch.object(broker.sys, "platform", "win32"), patch.object(broker.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(broker.BrokerError, "Native Windows strict"):
                broker.execute("echo must-not-run", str(Path.cwd()), {})
            launch.assert_not_called()


class CollectorPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = Ed25519PrivateKey.generate()
        self.key = self.root / "collector.key"
        integrity.signing_key(self.key, create=True)
        self.fingerprint = "a" * 64
        self.policy = {"key": str(self.key), "log": str(self.root / "collector.jsonl"),
            "streams": {"host-one": {"public_key": integrity.public_text(self.source.public_key()),
                                      "certificate_sha256": [self.fingerprint]}}}
        self.first = integrity.sign_record({"event": "command"}, self.source, seq=1, previous=integrity.ZERO_HASH)

    def batch(self, records=None):
        return {"version": 1, "id": str(uuid.uuid4()), "timestamp": time.time(),
                "stream": "host-one", "records": [self.first] if records is None else records}

    def test_authenticated_stream_receipt_replay_and_restart(self):
        server = collector.Collector(self.policy)
        original = self.batch()
        receipt = server.accept(original, self.fingerprint)
        integrity.verify_record(receipt, integrity.signing_key(self.key).public_key())
        self.assertEqual(receipt["record"]["head"], self.first["hash"])
        with self.assertRaisesRegex(collector.CollectorError, "Replayed"):
            server.accept(original, self.fingerprint)
        restarted = collector.Collector(self.policy)
        self.assertEqual(restarted.heads["host-one"]["seq"], 1)
        with self.assertRaisesRegex(collector.CollectorError, "Replayed"):
            restarted.accept(original, self.fingerprint)
        second = integrity.sign_record({"event": "next"}, self.source, seq=2, previous=self.first["hash"])
        restarted.accept(self.batch([second]), self.fingerprint)
        self.assertEqual(collector.Collector(self.policy).heads["host-one"]["seq"], 2)

    def test_wrong_certificate_and_modified_records_never_advance_stream(self):
        server = collector.Collector(self.policy)
        with self.assertRaisesRegex(collector.CollectorError, "not authorized"):
            server.accept(self.batch(), "b" * 64)
        changed = copy.deepcopy(self.first)
        changed["record"]["event"] = "forged"
        with self.assertRaises(integrity.IntegrityError):
            server.accept(self.batch([changed]), self.fingerprint)
        self.assertEqual(server.heads, {})
        self.assertFalse(Path(self.policy["log"]).exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only systemd forwarding resource")
class ForwarderCheckpointTests(unittest.TestCase):
    def test_source_lock_requires_only_read_access_and_never_creates_files(self):
        lock = runpy.run_path(str(Path(__file__).resolve().parents[1] / "service" / "forward.py"))["source_snapshot_lock"]
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "audit.jsonl"
            lock_path = Path(str(source) + ".lock")
            lock_path.write_bytes(b"")
            lock_path.chmod(0o400)
            with patch("os.open", wraps=os.open) as opened:
                with lock(source):
                    pass
                opened.assert_called_once_with(str(lock_path), os.O_RDONLY | os.O_NOFOLLOW)
            with self.assertRaises(FileNotFoundError):
                with lock(Path(temporary) / "absent"):
                    pass
            self.assertFalse((Path(temporary) / "absent.lock").exists())

    def test_authenticated_checkpoint_advances_once_and_detects_truncation(self):
        forward = runpy.run_path(str(Path(__file__).resolve().parents[1] / "service" / "forward.py"))["forward_once"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_key = Ed25519PrivateKey.generate()
            collector_key = Ed25519PrivateKey.generate()
            source = root / "source.jsonl"
            checkpoint = root / "receipt.json"
            first = integrity.append_record(source, {"event": "start"}, private_key=source_key)
            policy = {"source": str(source), "checkpoint": str(checkpoint),
                      "source_key": integrity.public_text(source_key.public_key()),
                      "collector_key": integrity.public_text(collector_key.public_key()),
                      "stream": "source", "host": "collector.example", "port": 9443,
                      "ca_file": "unused", "certificate": "unused", "private_key": "unused"}
            receipt = integrity.sign_record(
                {"event": "collection", "stream": "source", "last_seq": 1, "head": first["hash"]},
                collector_key, seq=1, previous=integrity.ZERO_HASH)
            with patch.object(collector, "submit", side_effect=collector.CollectorError("offline")):
                with self.assertRaises(collector.CollectorError):
                    forward(policy)
            self.assertFalse(checkpoint.exists())
            with patch.object(collector, "submit", return_value=receipt) as submit:
                self.assertEqual(forward(policy), 1)
                self.assertEqual(submit.call_args.args[0], [first])
                self.assertEqual(forward(policy), 0)
                self.assertEqual(submit.call_count, 1)
            source.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "Source audit chain invalid"):
                forward(policy)


if __name__ == "__main__":
    unittest.main()
