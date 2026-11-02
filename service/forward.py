"""One bounded forwarding pass; run by the administrator-owned systemd timer."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile

from argus import collector, integrity
from argus.broker import MAX_FRAME, admin_path


def load_policy(path):
    path = admin_path(path, private=True)
    if path.stat().st_size > 65536:
        raise ValueError("Forwarder policy too large")
    policy = json.loads(path.read_text("utf-8"))
    fields = {"version", "host", "port", "ca_file", "certificate", "private_key",
              "collector_key", "stream", "source", "source_key", "checkpoint"}
    if set(policy) != fields or policy["version"] != 1:
        raise ValueError("Invalid forwarder policy fields/version")
    if not isinstance(policy["host"], str) or not policy["host"]:
        raise ValueError("Collector host required")
    if type(policy["port"]) is not int or not 1 <= policy["port"] <= 65535:
        raise ValueError("Invalid collector port")
    if not isinstance(policy["stream"], str) or not 1 <= len(policy["stream"]) <= 128:
        raise ValueError("Invalid stream identity")
    for field in ("ca_file", "certificate", "private_key"):
        admin_path(policy[field], private=field == "private_key")
    for field in ("collector_key", "source_key"):
        integrity.load_public_key(policy[field])
    admin_path(Path(policy["source"]).parent, directory=True, private=True)
    if Path(policy["source"]).exists():
        admin_path(policy["source"], private=True)
    checkpoint = Path(policy["checkpoint"])
    if checkpoint.parent != Path("/var/lib/argus-forward"):
        raise ValueError("Checkpoint must be inside /var/lib/argus-forward")
    admin_path(checkpoint.parent, directory=True, private=True)
    if checkpoint.exists():
        admin_path(checkpoint, private=True)
    return policy


@contextmanager
def source_snapshot_lock(source):
    """Share the writer's existing lock without any write access to its tree."""
    import fcntl
    fd = os.open(str(source) + ".lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)


def forward_once(policy):
    checkpoint = Path(policy["checkpoint"])
    with integrity.locked(checkpoint):
        previous = None
        source_anchor = {"seq": 0, "hash": integrity.ZERO_HASH}
        if checkpoint.exists():
            previous = json.loads(checkpoint.read_bytes())
            integrity.verify_record(previous, policy["collector_key"])
            record = previous["record"]
            if record.get("event") != "collection" or record.get("stream") != policy["stream"]:
                raise ValueError("Checkpoint stream identity mismatch")
            source_anchor = {"seq": record["last_seq"], "hash": record["head"]}
        if not Path(policy["source"]).exists():
            if source_anchor["seq"]:
                raise ValueError("Source audit chain invalid: anchored log missing")
            return 0
        batch = []
        # Snapshot only complete, verified records while writers are excluded.
        with source_snapshot_lock(policy["source"]):
            verified = integrity.verify(policy["source"], public_key=policy["source_key"], anchor=source_anchor)
            if not verified.valid:
                raise ValueError(f"Source audit chain invalid: {verified.error}")
            size = 1024
            for envelope in integrity._records(policy["source"]):
                if envelope["seq"] <= source_anchor["seq"]:
                    continue
                item_size = len(integrity.canonical(envelope)) + 1
                # Collector receipts embed the batch; leave protocol overhead.
                if size + item_size > MAX_FRAME - 16384:
                    if not batch:
                        raise ValueError("Source record exceeds collector frame budget")
                    break
                batch.append(envelope)
                size += item_size
                if len(batch) == 1000:
                    break
        if not batch:
            return 0
        receipt = collector.submit(batch, host=policy["host"], port=policy["port"],
            ca_file=policy["ca_file"], certificate=policy["certificate"],
            private_key=policy["private_key"], collector_key=policy["collector_key"],
            stream=policy["stream"], anchor=previous)
        # Never advance the local source cursor without an authenticated receipt.
        fd, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=checkpoint.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(integrity.canonical(receipt) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, checkpoint)
            directory = os.open(checkpoint.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return len(batch)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="/etc/argus/forward.json")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Forwarding service requires explicitly installed Linux administrator identity")
    try:
        count = forward_once(load_policy(args.policy))
    except (OSError, ValueError, collector.CollectorError) as exc:
        print(f"argus-forward: {exc}", file=sys.stderr)
        return 1
    print(f"Forwarded {count} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
