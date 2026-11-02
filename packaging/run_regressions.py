#!/usr/bin/env python3
"""Run repository regressions without inheriting operator state."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from verify_runtime import private_environment

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", action="store_true", help="Include repository tests (POSIX-only legacy integration fixtures)")
    args = parser.parse_args()
    portable = subprocess.run([sys.executable, str(ROOT / "packaging" / "verify_runtime.py")], check=False)
    if portable.returncode:
        return portable.returncode
    if not args.legacy:
        return 0
    if os.name != "posix":
        print("SKIP legacy POSIX process-group/PTY fixtures on native Windows; running portable integrity/protocol regressions.")
        with tempfile.TemporaryDirectory(prefix="argus-regressions-") as temporary:
            env = private_environment(Path(temporary))
            for pattern in ("test_integrity.py", "test_broker.py"):
                result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"],
                                        cwd=ROOT, env=env, check=False)
                if result.returncode:
                    return result.returncode
        return 0
    with tempfile.TemporaryDirectory(prefix="argus-regressions-") as temporary:
        env = private_environment(Path(temporary))
        return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                              cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
