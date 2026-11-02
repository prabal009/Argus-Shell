"""Independent mTLS audit collector and cross-platform authenticated client.

Server trust is separately pinned to a collector Ed25519 key; stream keys and
client certificate fingerprints are administrator-configured. Receipt anchors
must be retained outside the originating user's writable account.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time
import uuid

from . import integrity
from .broker import BrokerError, admin_path, receive_frame, send_frame


class CollectorError(RuntimeError):
    pass


def submit(records, *, host, port, ca_file, certificate, private_key,
           collector_key, stream, timeout=30, anchor=None):
    """Submit a contiguous signed batch using TLS1.2+ mutual certificate auth.

    Works on native Windows using Python/OpenSSL, without POSIX APIs. Certificate
    key ACLs and independent server installation remain administrator duties.
    """
    records = list(records)
    if not records or len(records) > 1000:
        raise CollectorError("Submit between 1 and 1000 records")
    request = {"version": 1, "id": str(uuid.uuid4()), "timestamp": time.time(),
               "stream": stream, "records": records}
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_file))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate), str(private_key))
        trusted = integrity.load_public_key(collector_key)
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                send_frame(connection, request)
                response = receive_frame(connection)
        if not response.get("ok"):
            raise CollectorError(str(response.get("error", "Collector rejected request")))
        receipt = response["receipt"]
        integrity.verify_record(receipt, trusted)
        record = receipt["record"]
        if record.get("request_id") != request["id"] or record.get("stream") != stream:
            raise CollectorError("Collector receipt identity mismatch")
        if record.get("request_hash") != hashlib.sha256(integrity.canonical(request)).hexdigest():
            raise CollectorError("Collector receipt batch mismatch")
        if record.get("head") != records[-1]["hash"] or record.get("last_seq") != records[-1]["seq"]:
            raise CollectorError("Collector receipt anchor mismatch")
        if anchor is not None:
            if receipt["seq"] <= anchor["seq"]:
                raise CollectorError("Collector receipt rolled back/replayed")
            # A client may not have observed intervening other-stream receipts.
            # Its exact next receipt must link directly to its previous anchor.
            if receipt["seq"] == anchor["seq"] + 1 and receipt["previous"] != anchor["hash"]:
                raise CollectorError("Collector receipt chain fork")
        return receipt
    except (OSError, ValueError, KeyError, TypeError, BrokerError, integrity.IntegrityError) as exc:
        raise CollectorError(f"Collector authentication/protocol failed: {exc}") from exc


class Collector:
    def __init__(self, policy):
        self.policy = policy
        self.key = integrity.signing_key(policy["key"])
        state = integrity.verify(policy["log"], public_key=self.key.public_key())
        if not state.valid:
            raise CollectorError(f"Collector log invalid: {state.error}")
        self.heads = {}
        self.requests = set()
        # The fsynced append-only collection log is the transaction/state store.
        # No independently rewritable state.json can roll back stream counters.
        for envelope in integrity._records(policy["log"]):
            record = envelope["record"]
            if record.get("event") != "collection":
                raise CollectorError("Unexpected collector log event")
            stream = record["stream"]
            expected = self.heads.get(stream, {"seq": 0, "hash": integrity.ZERO_HASH})
            trusted = policy["streams"].get(stream)
            if trusted is None:
                raise CollectorError("Historical stream key is missing from configuration")
            for item in record["records"]:
                integrity.verify_record(item, trusted["public_key"], seq=expected["seq"] + 1, previous=expected["hash"])
                expected = {"seq": item["seq"], "hash": item["hash"]}
            if expected != {"seq": record["last_seq"], "hash": record["head"]}:
                raise CollectorError("Persisted stream anchor mismatch")
            self.heads[stream] = expected
            self.requests.add(record["request_id"])

    def accept(self, request, fingerprint):
        if set(request) != {"version", "id", "timestamp", "stream", "records"} or request["version"] != 1:
            raise CollectorError("Invalid collector request")
        try:
            if str(uuid.UUID(request["id"])) != request["id"]:
                raise ValueError()
        except (TypeError, ValueError, AttributeError) as exc:
            raise CollectorError("Invalid request identity") from exc
        if type(request["timestamp"]) not in (float, int) or not abs(time.time() - request["timestamp"]) <= 60:
            raise CollectorError("Expired collector request")
        if request["id"] in self.requests:
            raise CollectorError("Replayed collector request")
        stream = request["stream"]
        if not isinstance(stream, str) or stream not in self.policy["streams"]:
            raise CollectorError("Unknown stream")
        identity = self.policy["streams"][stream]
        if fingerprint not in identity["certificate_sha256"]:
            raise CollectorError("Client certificate is not authorized for this stream")
        records = request["records"]
        if not isinstance(records, list) or not 1 <= len(records) <= 1000:
            raise CollectorError("Invalid batch size")
        previous = self.heads.get(stream, {"seq": 0, "hash": integrity.ZERO_HASH})
        expected = previous
        for item in records:
            integrity.verify_record(item, identity["public_key"], seq=expected["seq"] + 1, previous=expected["hash"])
            expected = {"seq": item["seq"], "hash": item["hash"]}
        receipt = integrity.append_record(self.policy["log"], {
            "event": "collection", "time": time.time(), "stream": stream,
            "request_id": request["id"], "request_hash": hashlib.sha256(integrity.canonical(request)).hexdigest(),
            "client_certificate_sha256": fingerprint, "previous_anchor": previous,
            "first_seq": records[0]["seq"], "last_seq": expected["seq"], "head": expected["hash"],
            "records": records}, private_key=self.key)
        self.heads[stream] = expected
        self.requests.add(request["id"])
        return receipt

    def serve(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=self.policy["client_ca"])
        context.load_cert_chain(self.policy["certificate"], self.policy["tls_key"])
        with socket.create_server((self.policy["host"], self.policy["port"])) as listener:
            while True:
                raw, _ = listener.accept()
                raw.settimeout(30)
                try:
                    with context.wrap_socket(raw, server_side=True) as connection:
                        fingerprint = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
                        try:
                            request = receive_frame(connection)
                            receipt = self.accept(request, fingerprint)
                            send_frame(connection, {"ok": True, "receipt": receipt})
                        except (CollectorError, BrokerError, integrity.IntegrityError, ValueError, TypeError) as exc:
                            send_frame(connection, {"ok": False, "error": str(exc)})
                except (OSError, ssl.SSLError):
                    raw.close()


def load_policy(path):
    path = admin_path(path, private=True)
    if path.stat().st_size > 1024 * 1024:
        raise CollectorError("Collector configuration too large")
    policy = json.loads(path.read_text("utf-8"))
    if set(policy) != {"version", "host", "port", "certificate", "tls_key", "client_ca", "key", "log", "streams"} or policy["version"] != 1:
        raise CollectorError("Invalid collector configuration")
    if not isinstance(policy["host"], str) or type(policy["port"]) is not int or not 1 <= policy["port"] <= 65535:
        raise CollectorError("Invalid collector listen address")
    for field in ("certificate", "tls_key", "client_ca", "key"):
        admin_path(policy[field], private=field in ("key", "tls_key"))
    admin_path(Path(policy["log"]).parent, directory=True, private=True)
    if Path(policy["log"]).exists():
        admin_path(policy["log"], private=True)
    if not isinstance(policy["streams"], dict) or not policy["streams"]:
        raise CollectorError("Explicit trusted streams required")
    for stream, identity in policy["streams"].items():
        if not isinstance(stream, str) or not 1 <= len(stream) <= 128 or set(identity) != {"public_key", "certificate_sha256"}:
            raise CollectorError("Invalid trusted stream identity")
        integrity.load_public_key(identity["public_key"])
        fingerprints = identity["certificate_sha256"]
        if not isinstance(fingerprints, list) or not fingerprints or any(not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value) for value in fingerprints):
            raise CollectorError("Client certificate SHA256 fingerprints required")
    return policy


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="/etc/argus/collector.json")
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Collector server requires separately installed administrator-owned POSIX service/configuration. Native Windows clients are supported; Windows server service identity and protected ACL installation are external prerequisites.")
    try:
        Collector(load_policy(args.policy)).serve()
    except (OSError, ValueError, CollectorError, BrokerError, integrity.IntegrityError) as exc:
        print(f"argus-collector: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
