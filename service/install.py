"""Explicit, non-overwriting Linux service installation; never elevates or starts services."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

RESOURCES = Path(__file__).resolve().parent


def safe_path(value):
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) or ".." in path.parts:
        raise ValueError("Installation paths must be absolute without whitespace, '..', or systemd substitutions")
    return path


def protected(path, *, private=False):
    path = safe_path(path)
    if path.is_symlink():
        raise ValueError(f"Refusing symlink: {path}")
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"Administrator ownership and non-writable ancestry required: {item}")
    if private and path.stat().st_mode & 0o077:
        raise ValueError(f"Private administrator permissions required: {path}")
    return path


def directory(path, mode):
    path = safe_path(path)
    if not path.exists():
        protected(path.parent)
        path.mkdir(mode=mode)
    protected(path, private=mode == 0o700)
    if not path.is_dir():
        raise ValueError(f"Expected directory: {path}")
    if mode == 0o755 and path.stat().st_mode & 0o777 != 0o755:
        raise ValueError(f"Expected administrator-managed 0755 directory: {path}")
    return path


def exclusive(path, content, mode=0o600):
    path = safe_path(path)
    protected(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def installed_python(runtime):
    runtime = protected(runtime)
    # Validate the entire import tree before executing even administrator Python.
    for root, directories, files in os.walk(runtime, followlinks=False):
        for name in directories + files:
            item = Path(root) / name
            if item.is_symlink():
                if item.lstat().st_uid != 0:
                    raise ValueError(f"Untrusted runtime symlink: {item}")
                protected(item.resolve(strict=True))
            else:
                protected(item)
    python = runtime / "bin/python"
    protected(python.resolve(strict=True))
    subprocess.run([str(python), "-I", "-c",
        "import sys; from argus.broker import admin_path; "
        "admin_path(sys.argv[1], directory=True, recursive=True)", str(runtime)], check=True)
    return python


def render(name, python, **values):
    text = (RESOURCES / name).read_text("utf-8").replace("@PYTHON@", str(python))
    for key, value in values.items():
        text = text.replace("@" + key + "@", str(value))
    if re.search(r"@[A-Z_]+@", text):
        raise ValueError(f"Unresolved service template value: {name}")
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", default="/opt/argus/venv", help="Existing administrator-owned, non-editable Argus virtualenv")
    commands = parser.add_subparsers(dest="component", required=True)
    broker = commands.add_parser("broker")
    broker.add_argument("--uid", type=int, required=True)
    broker.add_argument("--workdir", required=True)
    for component in ("collector", "forward"):
        commands.add_parser(component).add_argument("--policy", required=True, help="Reviewed complete JSON policy; copied, never linked")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Run explicitly as Linux administrator; this installer never invokes sudo")
    try:
        python = installed_python(safe_path(args.runtime))
        protected(Path("/etc/systemd/system"))
        config = directory(Path("/etc/argus"), 0o755)
        state_name = "argus-broker" if args.component == "broker" else "argus-" + args.component
        directory(Path("/var/lib") / state_name, 0o700)
        targets = [config / (args.component + ".json")]
        units = ["argus-broker.socket", "argus-broker.service"] if args.component == "broker" else ["argus-" + args.component + ".service"]
        if args.component == "forward":
            units.append("argus-forward.timer")
            directory(Path("/usr/local/libexec"), 0o755)
            targets.append(Path("/usr/local/libexec/argus-forward.py"))
        if args.component in ("broker", "collector"):
            targets.append(config / (args.component + ".pub"))
        targets += [Path("/etc/systemd/system") / unit for unit in units]
        if any(target.exists() or target.is_symlink() for target in targets):
            raise ValueError("Existing policy, helper, public key, or unit will not be overwritten")
        substitutions = {}
        if args.component == "broker":
            import pwd
            if args.uid <= 0:
                raise ValueError("A non-root client UID is required")
            user = pwd.getpwuid(args.uid)
            work = safe_path(args.workdir)
            if work.is_symlink() or not work.is_dir():
                raise ValueError("Workdir must be an existing real directory")
            protected(work.parent)
            if work.parts[1] in ("home", "root", "tmp", "run", "etc", "usr", "var", "sys", "proc", "dev"):
                raise ValueError("Use a dedicated workdir below an administrator-owned /srv directory")
            directory(Path("/run/argus"), 0o755)
            policy = {"version": 1, "allowed_uids": [args.uid], "socket": "/run/argus/broker.sock",
                "socket_gid": user.pw_gid, "python": str(python), "runtime_root": str(safe_path(args.runtime)),
                "bubblewrap": "/usr/bin/bwrap", "readonly_roots": ["/usr", "/bin", "/lib", str(safe_path(args.runtime))],
                "writable_roots": [str(work)], "network": False, "memory_bytes": 536870912,
                "pids": 64, "cpu_percent": 100, "cpu_seconds": 60, "wall_seconds": 120,
                "output_bytes": 262144, "environment_allowlist": ["LANG", "TERM"],
                "log": "/var/lib/argus-broker/audit.jsonl", "key": "/var/lib/argus-broker/signing.key", "cgroup_root": ""}
            if Path("/lib64").exists():
                policy["readonly_roots"].append("/lib64")
            substitutions = {"WORKDIR": str(work), "SOCKET_GROUP": str(user.pw_gid)}
        else:
            source = Path(args.policy)
            if source.stat().st_size > 1024 * 1024:
                raise ValueError("Input policy too large")
            policy = json.loads(source.read_text("utf-8"))
            if args.component == "collector" and (policy.get("key") != "/var/lib/argus-collector/signing.key" or policy.get("log") != "/var/lib/argus-collector/audit.jsonl"):
                raise ValueError("Collector key/log must use the documented /var/lib/argus-collector paths")
        # Render all templates before changing configuration.
        rendered = {unit: render(unit, python, **substitutions) for unit in units}
        policy_path = targets[0]
        exclusive(policy_path, json.dumps(policy, indent=2) + "\n")
        if args.component == "broker":
            result = subprocess.run([str(python), "-I", "-m", "argus.broker", "--initialize-key", "--policy", str(policy_path)], check=True, capture_output=True, text=True)
            exclusive(config / "broker.pub", result.stdout, 0o644)
        elif args.component == "collector":
            result = subprocess.run([str(python), "-I", "-c",
                "import sys; from argus import integrity; from argus.collector import load_policy; "
                "key=integrity.signing_key('/var/lib/argus-collector/signing.key', create=True); "
                "load_policy(sys.argv[1]); print(integrity.public_text(key.public_key()))", str(policy_path)],
                check=True, capture_output=True, text=True)
            exclusive(config / "collector.pub", result.stdout, 0o644)
        else:
            helper = Path("/usr/local/libexec/argus-forward.py")
            exclusive(helper, (RESOURCES / "forward.py").read_text("utf-8"), 0o644)
            subprocess.run([str(python), "-I", "-c",
                "import runpy,sys; runpy.run_path('/usr/local/libexec/argus-forward.py')['load_policy'](sys.argv[1])",
                str(policy_path)], check=True)
        for unit, text in rendered.items():
            exclusive(Path("/etc/systemd/system") / unit, text, 0o644)
        enable = "argus-broker.socket" if args.component == "broker" else ("argus-forward.timer" if args.component == "forward" else "argus-collector.service")
        print(f"Installed inert resources. Review {policy_path}, then explicitly run:\nsystemctl daemon-reload\nsystemctl enable --now {enable}")
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"Installation stopped: {exc}. No service was started. Inspect any newly created files before retrying; nothing is overwritten.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
