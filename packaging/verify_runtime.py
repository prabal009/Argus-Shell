#!/usr/bin/env python3
"""Installed-package/frozen CLI regressions with private state and bounded children.

Runs on Linux, macOS and native Windows. POSIX PTY coverage is explicitly skipped
on Windows, where it cannot establish ConPTY/console-control behavior.
"""
from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest

LAUNCHER = [sys.executable, "-c", "from argus.main import main; raise SystemExit(main())"]


def python_command(code: str, *args: str) -> str:
    return " ".join(shlex.quote(value) for value in (sys.executable, "-c", code, *args))


def private_environment(home: Path) -> dict[str, str]:
    env = dict(os.environ)
    # Do not inherit a user's custom policy, broker, startup path, or Python path.
    for key in list(env):
        if key.startswith("ARGUS_") or key in {"PYTHONPATH", "PYTHONHOME", "BASH_ENV", "ENV"}:
            env.pop(key, None)
    env.update(HOME=str(home), USERPROFILE=str(home),
               XDG_CONFIG_HOME=str(home / "config"), XDG_DATA_HOME=str(home / "data"),
               XDG_STATE_HOME=str(home / "state"), XDG_CACHE_HOME=str(home / "cache"),
               APPDATA=str(home / "appdata"), LOCALAPPDATA=str(home / "localappdata"),
               ARGUS_CONFIG_HOME=str(home / "config"), ARGUS_DATA_HOME=str(home / "data"),
               ARGUS_STATE_HOME=str(home / "state"), TERM="xterm", NO_COLOR="1",
               PYTHONIOENCODING="utf-8")
    return env


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="argus-runtime-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.env = private_environment(self.home)

    def invoke(self, *args: str, timeout: float = 25) -> subprocess.CompletedProcess:
        with subprocess.Popen([*LAUNCHER, *args], cwd=self.home, env=self.env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, encoding="utf-8") as child:
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                import psutil
                try:
                    descendants = psutil.Process(child.pid).children(recursive=True)
                except psutil.NoSuchProcess:
                    descendants = []
                for process in reversed(descendants):
                    try:
                        process.kill()
                    except psutil.NoSuchProcess:
                        pass
                child.kill()
                child.communicate()
                self.fail(f"CLI timed out: {args!r}")
            return subprocess.CompletedProcess(child.args, child.returncode, stdout, stderr)

    def command(self, source: str, expected: int = 0):
        result = self.invoke("--norc", "--no-color", "-c", source)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_installed_entrypoint_and_version(self):
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("argus", result.stdout.lower())
        self.assertTrue(result.stdout.strip())

    def test_native_external_backend_and_exit_status(self):
        result = self.command(python_command("print('NATIVE-OK')"))
        self.assertIn("NATIVE-OK", result.stdout)
        self.command(python_command("raise SystemExit(7)"), expected=7)

    def test_language_functions_loops_aliases_and_substitution(self):
        emit = python_command("import sys; print(sys.argv[1])", "$value")
        # Construct variable arguments with double quotes, not shlex's literal quote.
        emit = python_command("import sys; print(sys.argv[1])") + ' "$value"'
        capture = python_command("print('CAPTURED')")
        result = self.command(
            f"emit() {{ {emit}; }}; for value in ALPHA BETA; do emit; done; "
            f"value=$({capture}); emit; alias show=emit\nshow")
        for marker in ("ALPHA", "BETA", "CAPTURED"):
            self.assertIn(marker, result.stdout)
        self.assertGreaterEqual(result.stdout.count("CAPTURED"), 2)

    def test_export_and_unexported_variable_boundaries(self):
        source = "LOCAL_ONLY=private; export ARGUS_PORTABLE_VALUE=visible; " + python_command(
            "import os; assert os.environ['ARGUS_PORTABLE_VALUE'] == 'visible'; "
            "assert 'LOCAL_ONLY' not in os.environ; print('EXPORT-OK')")
        self.assertIn("EXPORT-OK", self.command(source).stdout)

    def test_pipeline_and_ordered_redirection(self):
        producer = python_command("import sys; sys.stdout.write('pipeline-data')")
        consumer = python_command("import sys; print(sys.stdin.read().upper())")
        result = self.command(f"{producer} | {consumer} > result.txt; " +
                              python_command("from pathlib import Path; print(Path('result.txt').read_text())"))
        self.assertIn("PIPELINE-DATA", result.stdout)
        result = self.command(python_command("import sys; print('OUT'); print('ERR', file=sys.stderr)") +
                              " > combined.txt 2>&1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(set((self.home / "combined.txt").read_text().splitlines()), {"OUT", "ERR"})

    def test_builtin_worker_pipeline_and_background_wait(self):
        result = self.command("pwd | " + python_command("import sys; print('WORKER-' + str(bool(sys.stdin.read().strip())))"))
        self.assertIn("WORKER-True", result.stdout)
        marker = self.home / "background.txt"
        background = python_command("from pathlib import Path; import time; time.sleep(.1); Path('background.txt').write_text('done')")
        self.command(f"{background} & wait")
        self.assertEqual(marker.read_text(), "done")

    def test_script_source_and_positional_arguments(self):
        rc = self.home / "library.argus"
        rc.write_text("export ARGUS_SOURCE_VALUE=sourced\n", encoding="utf-8")
        script = self.home / "script.argus"
        script.write_text("source library.argus\n" + python_command(
            "import os, sys; assert os.environ['ARGUS_SOURCE_VALUE'] == 'sourced'; print(sys.argv[1])") +
            ' "$1"\n', encoding="utf-8")
        result = self.invoke("--norc", "--no-color", str(script), "SCRIPT-ARGUMENT")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SCRIPT-ARGUMENT", result.stdout)

    @unittest.skipUnless(os.name == "posix", "POSIX PTY/session APIs unavailable on native Windows; ConPTY requires separate target verification")
    def test_interactive_posix_pty(self):
        import pty
        import select
        import struct
        import termios
        import fcntl
        import runpy
        # Share the terminal model used by the real editing regressions. This
        # recognizes rendered cursor state and answers split CPR requests rather
        # than depending on prompt-toolkit's incidental output byte layout.
        harness = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tests" / "test_terminal_integration.py"))
        environment = dict(self.env, ARGUS_PROMPT=harness["PROMPT"], ARGUS_LOCALE="en")
        pid, master = pty.fork()
        if pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
            os.chdir(self.home)
            os.execvpe(LAUNCHER[0], [*LAUNCHER, "--norc", "--no-color"], environment)
        reaped = False
        try:
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
            chunks = bytearray()
            screen = harness["TerminalScreen"](lambda data: os.write(master, data), rows=24, columns=100)
            deadline = time.monotonic() + 20
            sent = False
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not data:
                        break
                    chunks.extend(data)
                    screen.feed(data)
                    if not sent and screen.at_prompt:
                        # Marker is not contiguous in echoed input, avoiding a false pass.
                        command = python_command("print('PTY' + '-OK')")
                        os.write(master, (command + "\n").encode())
                        sent = True
                    if sent and "PTY-OK" in screen.text and screen.at_prompt:
                        os.write(master, b"exit\n")
                        break
            self.assertIn("PTY-OK", screen.text, bytes(chunks).decode(errors="replace"))
            self.assertNotIn("terminal does not support cursor position requests", screen.text.lower())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    reaped = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                    break
                time.sleep(.05)
            self.assertTrue(reaped, "interactive exit did not terminate")
        finally:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            os.close(master)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, help="Test a standalone executable instead of the installed package")
    args, remaining = parser.parse_known_args()
    if args.executable:
        executable = args.executable.resolve()
        if not executable.is_file():
            parser.error(f"executable does not exist: {executable}")
        LAUNCHER[:] = [str(executable)]
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
