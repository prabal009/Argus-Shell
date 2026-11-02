"""Optional administrator-owned Linux execution broker; never a fallback shell.

The security boundary is bubblewrap/user namespaces plus a delegated cgroup v2,
not a promise that command text can be sanitized. The broker records source,
start and completion independently, not a complete syscall trace.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

from . import integrity

MAX_FRAME = 2 * 1024 * 1024
MAX_SOURCE = 256 * 1024
MAX_ENVIRONMENT = 64 * 1024
DEFAULT_SOCKET = "/run/argus/broker.sock"
DEFAULT_PUBLIC_KEY = "/etc/argus/broker.pub"


class BrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class BrokerResult:
    status: int
    stdout: str
    stderr: str
    receipt: dict


def send_frame(connection, value):
    data = integrity.canonical(value)
    if len(data) > MAX_FRAME:
        raise BrokerError("Protocol frame exceeds limit")
    connection.sendall(struct.pack("!I", len(data)) + data)


def _read_exact(connection, size):
    pieces = bytearray()
    while len(pieces) < size:
        data = connection.recv(size - len(pieces))
        if not data:
            raise BrokerError("Service disconnected during response")
        pieces.extend(data)
    return bytes(pieces)


def receive_frame(connection):
    size, = struct.unpack("!I", _read_exact(connection, 4))
    if not 0 < size <= MAX_FRAME:
        raise BrokerError("Invalid protocol frame size")
    try:
        data = _read_exact(connection, size)
        depth, quoted, escaped = 0, False, False
        for byte in data:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 64:
                    raise ValueError("JSON nesting exceeds protocol limit")
            elif byte in (93, 125):
                depth -= 1
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise BrokerError("Invalid protocol JSON") from exc
    if not isinstance(value, dict):
        raise BrokerError("Protocol message must be an object")
    return value


def execute(source, cwd, environment, *, capture=False, socket_path=None,
            public_key=None, timeout=None) -> BrokerResult:
    if not sys.platform.startswith("linux"):
        raise BrokerError("Strict mode requires the Linux protected broker. Native Windows strict mode needs an independently installed administrator service, authenticated named-pipe ACLs, AppContainer isolation and Job Object enforcement; no such backend is installed.")
    request = {"version": 1, "id": str(uuid.uuid4()), "timestamp": time.time(),
               "source": source, "cwd": str(cwd), "environment": dict(environment)}
    _validate_request(request)
    key = public_key or Path(os.environ.get("ARGUS_BROKER_PUBLIC_KEY", DEFAULT_PUBLIC_KEY))
    try:
        trusted = integrity.load_public_key(key)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout or 3600)
            connection.connect(socket_path or os.environ.get("ARGUS_BROKER_SOCKET", DEFAULT_SOCKET))
            # A user-created socket cannot impersonate the administrator even if
            # the public receipt key remains pinned.
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                raise BrokerError("Broker socket is not served by root")
            send_frame(connection, request)
            response = receive_frame(connection)
        if not response.get("ok"):
            raise BrokerError(str(response.get("error", "Broker rejected request")))
        receipt = response["receipt"]
        integrity.verify_record(receipt, trusted)
        record = receipt["record"]
        if record.get("event") != "completion" or record.get("request_id") != request["id"]:
            raise BrokerError("Receipt belongs to a different request")
        if record.get("uid") != os.getuid() or record.get("request_hash") != hashlib.sha256(integrity.canonical(request)).hexdigest():
            raise BrokerError("Receipt identity/request mismatch")
        stdout, stderr, status = response["stdout"], response["stderr"], response["status"]
        if type(status) is not int or not isinstance(stdout, str) or not isinstance(stderr, str):
            raise BrokerError("Malformed broker result")
        for name, value in (("stdout", stdout), ("stderr", stderr)):
            if hashlib.sha256(value.encode("utf-8")).hexdigest() != record.get(name + "_sha256"):
                raise BrokerError("Broker output does not match signed receipt")
        if status != record.get("status"):
            raise BrokerError("Broker status does not match signed receipt")
        if not capture:
            sys.stdout.write(stdout)
            sys.stderr.write(stderr)
        return BrokerResult(status, stdout, stderr, receipt)
    except (OSError, ValueError, KeyError, TypeError, integrity.IntegrityError) as exc:
        if isinstance(exc, BrokerError):
            raise
        raise BrokerError(f"Protected broker unavailable or invalid: {exc}") from exc


def _validate_request(request):
    if set(request) != {"version", "id", "timestamp", "source", "cwd", "environment"} or request["version"] != 1:
        raise BrokerError("Unsupported request fields/version")
    try:
        if str(uuid.UUID(request["id"])) != request["id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as exc:
        raise BrokerError("Invalid request identity") from exc
    stamp = request["timestamp"]
    if type(stamp) not in (int, float) or not abs(time.time() - stamp) <= 60:
        raise BrokerError("Expired request timestamp")
    source = request["source"]
    if not isinstance(source, str) or "\0" in source or len(source.encode("utf-8")) > MAX_SOURCE:
        raise BrokerError("Invalid or oversized source")
    cwd = request["cwd"]
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or "\0" in cwd or len(cwd) > 4096:
        raise BrokerError("Invalid working directory")
    environment = request["environment"]
    if not isinstance(environment, dict) or len(environment) > 512 or len(integrity.canonical(environment)) > MAX_ENVIRONMENT:
        raise BrokerError("Invalid or oversized environment")
    for name, value in environment.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not isinstance(value, str) or "\0" in value:
            raise BrokerError("Invalid environment entry")


def admin_path(path, *, directory=False, private=False, recursive=False):
    """Reject user-owned/writeable policy, executable, ancestor and symlink targets."""
    path = Path(path)
    if not path.is_absolute():
        raise BrokerError("Administrator paths must be absolute")
    resolved = path.resolve(strict=True)
    for candidate in (path, *path.parents, resolved, *resolved.parents):
        info = candidate.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise BrokerError(f"Unsafe administrator-owned path: {candidate}")
    info = resolved.stat()
    if directory and not stat.S_ISDIR(info.st_mode):
        raise BrokerError(f"Expected directory: {path}")
    if private and info.st_mode & 0o077:
        raise BrokerError(f"Expected root-private file/directory: {path}")
    if recursive:
        for root, dirs, files in os.walk(resolved, followlinks=False):
            for name in dirs + files:
                item = Path(root) / name
                target = item.resolve(strict=True)
                # Runtime symlinks may point at root-owned system interpreters.
                for candidate in (item, target, *target.parents):
                    entry = candidate.stat()
                    if entry.st_uid != 0 or entry.st_mode & 0o022:
                        raise BrokerError(f"Unsafe installed runtime: {candidate}")
    return resolved


def _inside(path, roots):
    return any(path == root or root in path.parents for root in roots)


def load_policy(path):
    path = admin_path(path, private=True)
    if path.stat().st_size > 65536:
        raise BrokerError("Broker policy too large")
    policy = json.loads(path.read_text("utf-8"))
    required = {"version", "allowed_uids", "socket", "socket_gid", "python", "runtime_root", "bubblewrap",
                "readonly_roots", "writable_roots", "network", "memory_bytes", "pids", "cpu_percent",
                "cpu_seconds", "wall_seconds", "output_bytes", "environment_allowlist", "log", "key", "cgroup_root"}
    if set(policy) != required or policy["version"] != 1:
        raise BrokerError("Broker policy fields/version are invalid")
    if not isinstance(policy["allowed_uids"], list) or not policy["allowed_uids"] or any(type(uid) is not int or uid <= 0 for uid in policy["allowed_uids"]):
        raise BrokerError("Explicit non-root allowed_uids required")
    bounds = {"memory_bytes": (16 * 1024 * 1024, 1024 ** 4), "pids": (1, 65536),
              "cpu_percent": (1, 10000), "cpu_seconds": (1, 86400), "wall_seconds": (1, 3600),
              "output_bytes": (1024, 512 * 1024), "socket_gid": (0, 2**31 - 1)}
    for field, (low, high) in bounds.items():
        if type(policy[field]) is not int or not low <= policy[field] <= high:
            raise BrokerError(f"Invalid policy bound: {field}")
    if type(policy["network"]) is not bool:
        raise BrokerError("network must be boolean")
    if not isinstance(policy["environment_allowlist"], list) or any(not isinstance(name, str) or not re.fullmatch(r"(?:LANG|LC_[A-Z_]+|TERM|COLORTERM)", name) for name in policy["environment_allowlist"]):
        raise BrokerError("Only locale/terminal environment entries may be forwarded")
    runtime = admin_path(policy["runtime_root"], directory=True, recursive=True)
    python = admin_path(policy["python"])
    if not _inside(Path(policy["python"]), [runtime]):
        raise BrokerError("Interpreter must be installed inside runtime_root")
    bubblewrap = admin_path(policy["bubblewrap"])
    if bubblewrap.stat().st_mode & (stat.S_ISUID | stat.S_ISGID) or not os.access(bubblewrap, os.X_OK):
        raise BrokerError("A non-setuid executable bubblewrap is required")
    if not os.access(python, os.X_OK):
        raise BrokerError("Interpreter is not executable")
    for field in ("readonly_roots", "writable_roots"):
        if not isinstance(policy[field], list) or not policy[field]:
            raise BrokerError(f"Explicit {field} required")
        for value in policy[field]:
            if not isinstance(value, str) or not os.path.isabs(value) or Path(value) == Path("/"):
                raise BrokerError(f"Invalid mount root in {field}")
    readonly = [admin_path(value) for value in policy["readonly_roots"]]
    protected = [Path("/etc/argus"), Path("/var/lib/argus-broker"), Path("/run"), Path("/sys"), Path("/proc"), Path("/dev")]
    for root in readonly:
        if any(_inside(value, [root]) or _inside(root, [value]) for value in protected):
            raise BrokerError("Read-only mounts expose protected service or kernel paths")
    if any(Path(value).is_symlink() for value in policy["writable_roots"]):
        raise BrokerError("Writable mount roots cannot be symlinks")
    writable = [Path(value).resolve(strict=True) for value in policy["writable_roots"]]
    forbidden = [Path(value) for value in ("/etc", "/proc", "/sys", "/dev", "/run", "/var/lib/argus-broker")]
    for root in writable:
        if root == Path("/") or any(_inside(root, [value]) or _inside(value, [root]) for value in forbidden + readonly + [runtime]):
            raise BrokerError("Writable mounts overlap protected/system/runtime paths")
        # The mountpoint's parent cannot be replaced by the requesting user.
        admin_path(root.parent, directory=True)
        if not root.is_dir() or root.is_symlink():
            raise BrokerError("Writable root must be an existing real directory")
    if not _inside(runtime, readonly):
        raise BrokerError("runtime_root must be on an approved read-only mount")
    for field in ("log", "key"):
        admin_path(Path(policy[field]).parent, directory=True, private=True)
        if Path(policy[field]).exists():
            admin_path(policy[field], private=True)
    admin_path(Path(policy["socket"]).parent, directory=True)
    return policy


class Cgroups:
    def __init__(self, configured):
        if configured:
            self.root = Path(configured)
        else:
            lines = Path("/proc/self/cgroup").read_text().splitlines()
            unified = next((line[3:] for line in lines if line.startswith("0::")), None)
            if unified is None or not unified.startswith("/") or ".." in Path(unified).parts:
                raise BrokerError("Unified cgroup v2 hierarchy is required")
            self.root = Path("/sys/fs/cgroup") / unified.lstrip("/")
        root = self.root.resolve(strict=True)
        if not _inside(root, [Path("/sys/fs/cgroup")]) or root == Path("/sys/fs/cgroup"):
            raise BrokerError("A dedicated delegated service cgroup is required")
        controllers = set((root / "cgroup.controllers").read_text().split())
        if not {"cpu", "memory", "pids"} <= controllers:
            raise BrokerError("Delegated cgroup v2 cpu/memory/pids controllers unavailable")
        manager = root / "manager"
        manager.mkdir(exist_ok=True)
        (manager / "cgroup.procs").write_text(str(os.getpid()))
        (root / "cgroup.subtree_control").write_text("+cpu +memory +pids")
        self.root = root

    def create(self, request_id, policy):
        group = self.root / ("job-" + request_id)
        group.mkdir()
        try:
            (group / "memory.max").write_text(str(policy["memory_bytes"]))
            (group / "memory.swap.max").write_text("0")
            (group / "memory.oom.group").write_text("1")
            (group / "pids.max").write_text(str(policy["pids"]))
            (group / "cpu.max").write_text(f"{policy['cpu_percent'] * 1000} 100000")
            if not (group / "cgroup.kill").exists():
                raise BrokerError("cgroup.kill kernel support is required")
            return group
        except BaseException:
            group.rmdir()
            raise

    @staticmethod
    def kill(group):
        (group / "cgroup.kill").write_text("1")

    @staticmethod
    def cpu(group):
        values = dict(line.split() for line in (group / "cpu.stat").read_text().splitlines())
        return int(values["usage_usec"]) / 1_000_000

    @staticmethod
    def cleanup(group):
        Cgroups.kill(group)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                group.rmdir()
                return
            except OSError:
                time.sleep(0.02)
        raise BrokerError("Unable to remove terminated job cgroup")


def sandbox_command(policy, request, uid):
    readonly = [Path(value).resolve(strict=True) for value in policy["readonly_roots"]]
    writable = [Path(value).resolve(strict=True) for value in policy["writable_roots"]]
    cwd = Path(request["cwd"]).resolve(strict=True)
    if not cwd.is_dir() or not _inside(cwd, readonly + writable):
        raise BrokerError("Working directory outside approved mounts")
    command = [policy["bubblewrap"], "--die-with-parent", "--new-session", "--unshare-all",
               "--disable-userns", "--cap-drop", "ALL"]
    if policy["network"]:
        command.append("--share-net")
    command += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/home"]
    for root in policy["readonly_roots"]:
        command += ["--ro-bind", root, root]
    for root in writable:
        command += ["--bind", str(root), str(root)]
    # No host sockets, user configuration, Python search path, preload variables,
    # writable installation, startup scripts or inherited file descriptors.
    environment = {name: value for name, value in request["environment"].items()
                   if name in policy["environment_allowlist"]}
    environment.update({"PATH": "/usr/bin:/bin", "HOME": "/tmp/home", "USER": str(uid),
                        "LOGNAME": str(uid), "ARGUS_DATA_HOME": "/tmp/data",
                        "ARGUS_STATE_HOME": "/tmp/state", "ARGUS_CONFIG_HOME": "/tmp/config"})
    command += ["--clearenv"]
    for name, value in environment.items():
        command += ["--setenv", name, value]
    command += ["--chdir", str(cwd), "--", policy["python"], "-I", "-m", "argus.main",
                "--norc", "-c", request["source"]]
    return command


def run_isolated(policy, request, uid, gid, cgroups):
    command = sandbox_command(policy, request, uid)
    group = cgroups.create(request["id"], policy)
    process = None
    def dropped_child():
        # This hook only runs administrator code, before exec; the service is
        # deliberately single-threaded. Join the aggregate cgroup BEFORE exec.
        (group / "cgroup.procs").write_text(str(os.getpid()))
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        if os.getuid() == 0 or os.geteuid() == 0:
            os._exit(126)
        import ctypes
        if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            os._exit(126)
        os.umask(0o077)
    output = [bytearray(), bytearray()]
    reason = "exited"
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd="/", env={"PATH": "/usr/bin:/bin"},
                                   close_fds=True, preexec_fn=dropped_child)
        selector = selectors.DefaultSelector()
        for index, stream in enumerate((process.stdout, process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        started = time.monotonic()
        try:
            while selector.get_map():
                if time.monotonic() - started >= policy["wall_seconds"]:
                    reason = "wall_timeout"
                    cgroups.kill(group)
                if cgroups.cpu(group) >= policy["cpu_seconds"]:
                    reason = "cpu_budget"
                    cgroups.kill(group)
                for event, _ in selector.select(0.05):
                    chunk = os.read(event.fd, 65536)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        event.fileobj.close()
                        continue
                    remaining = policy["output_bytes"] - sum(map(len, output))
                    output[event.data].extend(chunk[:max(0, remaining)])
                    if len(chunk) > remaining:
                        reason = "output_limit"
                        cgroups.kill(group)
            status = process.wait(timeout=3)
        finally:
            selector.close()
        if reason != "exited":
            status = 124 if reason in ("wall_timeout", "cpu_budget") else 125
        elif status < 0:
            status = 128 - status
        return status, *(bytes(value).decode("utf-8", "replace") for value in output), reason
    finally:
        if process is not None and process.poll() is None:
            cgroups.kill(group)
            process.wait(timeout=3)
        cgroups.cleanup(group)


class BrokerServer:
    def __init__(self, policy):
        self.policy = policy
        self.key = integrity.signing_key(policy["key"])
        state = integrity.verify(policy["log"], public_key=self.key.public_key())
        if not state.valid:
            raise BrokerError(f"Protected audit log invalid: {state.error}")
        self.seen = set()
        for envelope in integrity._records(policy["log"]):
            identifier = envelope["record"].get("request_id")
            if identifier:
                self.seen.add(identifier)
        self.cgroups = Cgroups(policy["cgroup_root"])

    def record(self, event):
        return integrity.append_record(self.policy["log"], {"time": time.time(), **event}, private_key=self.key)

    def handle(self, connection):
        _, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid == 0 or uid not in self.policy["allowed_uids"]:
            raise BrokerError("Peer UID is not authorized")
        request = receive_frame(connection)
        _validate_request(request)
        if request["id"] in self.seen:
            raise BrokerError("Replayed request identity")
        request_hash = hashlib.sha256(integrity.canonical(request)).hexdigest()
        common = {"request_id": request["id"], "request_hash": request_hash, "uid": uid, "gid": gid}
        self.record({**common, "event": "accepted_script", "source": request["source"], "cwd": request["cwd"]})
        self.seen.add(request["id"])
        start = self.record({**common, "event": "start", "limits": {name: self.policy[name] for name in
                              ("cpu_seconds", "cpu_percent", "memory_bytes", "pids", "wall_seconds", "network")}})
        try:
            status, stdout, stderr, reason = run_isolated(self.policy, request, uid, gid, self.cgroups)
        except Exception as exc:
            status, stdout, stderr, reason = 125, "", f"Isolation failed: {exc}\n", "isolation_failed"
        receipt = self.record({**common, "event": "completion", "status": status, "reason": reason,
                               "start_hash": start["hash"],
                               "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                               "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()})
        send_frame(connection, {"ok": True, "status": status, "stdout": stdout, "stderr": stderr, "receipt": receipt})

    def serve(self):
        activated = os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1"
        if activated:
            listener = socket.socket(fileno=3)
            if listener.family != socket.AF_UNIX or listener.getsockname() != self.policy["socket"]:
                raise BrokerError("Unexpected socket activation descriptor")
        else:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # Do not unlink arbitrary existing paths on startup.
            listener.bind(self.policy["socket"])
            os.chown(self.policy["socket"], 0, self.policy["socket_gid"])
            os.chmod(self.policy["socket"], 0o660)
            listener.listen(16)
        with listener:
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    try:
                        self.handle(connection)
                    except (OSError, ValueError, BrokerError, integrity.IntegrityError) as exc:
                        try:
                            send_frame(connection, {"ok": False, "error": str(exc)})
                        except OSError:
                            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="/etc/argus/broker.json")
    parser.add_argument("--initialize-key", action="store_true")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Broker administration requires Linux root; never invokes sudo")
    try:
        policy = load_policy(args.policy)
        if args.initialize_key:
            key = integrity.signing_key(policy["key"], create=True)
            print(integrity.public_text(key.public_key()))
            return 0
        BrokerServer(policy).serve()
    except (OSError, ValueError, BrokerError, integrity.IntegrityError) as exc:
        print(f"argus-broker: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
