"""Real Windows CLI argument transport, supervised exec and descriptor regressions."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
ARGUMENTS = [
    '', 'two words', 'tab\tseparated', 'line\nbreak', '"quoted"',
    "single'quote", 'mixed \' and " quotes', 'C:\\space dir\\',
    'plain\\', 'slashes\\\\"quote', '終わり café 🐚',
    '& | < > ^ %PATH% !bang! $HOME $(not-a-command); * ?',
]


@unittest.skipUnless(os.name == 'nt', 'requires actual Windows CRT process creation')
class WindowsProcessTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory(prefix='argus windows argv ')
        self.addCleanup(self.home.cleanup)
        self.root = Path(self.home.name)
        self.environment = dict(
            os.environ, HOME=str(self.root), USERPROFILE=str(self.root),
            XDG_CONFIG_HOME=str(self.root / 'config'),
            XDG_STATE_HOME=str(self.root / 'state'),
            XDG_DATA_HOME=str(self.root / 'data'),
            ARGUS_CONFIG_HOME=str(self.root / 'config'),
            ARGUS_STATE_HOME=str(self.root / 'state'),
            ARGUS_DATA_HOME=str(self.root / 'data'), PYTHONPATH=str(REPO))

    def python(self, code, arguments=()):
        # Argus parses POSIX shell source, even on Windows. The native launch
        # must quote the resulting argv again for the Windows CRT, not cmd.exe.
        return shlex.join([sys.executable, '-c', code, *arguments])

    def producer(self, status=0):
        return self.python(
            'import json,sys;print(json.dumps(sys.argv[1:]));'
            f'raise SystemExit({status})', ARGUMENTS)

    def run_shell(self, source):
        return subprocess.run(
            [sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
            cwd=self.root, env=self.environment, capture_output=True,
            text=True, encoding='utf-8', timeout=30)

    def assert_arguments(self, result, status):
        self.assertEqual(result.returncode, status, result.stderr)
        self.assertEqual(json.loads(result.stdout), ARGUMENTS, result.stderr)

    def test_external_argv_and_meaningful_nonzero_status(self):
        self.assert_arguments(self.run_shell(self.producer(7)), 7)

    def test_pipeline_transports_argv_stdin_and_final_status(self):
        consumer = self.python(
            'import json,sys;value=json.load(sys.stdin);'
            'print(json.dumps(value));raise SystemExit(23)')
        self.assert_arguments(self.run_shell(f'{self.producer()} | {consumer}'), 23)

    def test_pipeline_pipefail_keeps_native_nonzero_status(self):
        consumer = self.python('import sys;sys.stdout.write(sys.stdin.read())')
        result = self.run_shell(f'set -o pipefail; {self.producer(7)} | {consumer}')
        self.assert_arguments(result, 7)

    def test_command_substitution_keeps_argument_boundaries(self):
        result = self.run_shell(f'printf "%s" "$({self.producer()})"')
        self.assert_arguments(result, 0)

    def test_shell_exec_waits_for_status_and_does_not_run_exit_trap(self):
        result = self.run_shell(
            f"trap 'printf forbidden-trap' EXIT; exec {self.producer(7)}; "
            'printf forbidden-after-exec')
        self.assert_arguments(result, 7)

    def test_subshell_worker_exec_terminates_worker_with_native_status(self):
        result = self.run_shell(
            f"(trap 'printf forbidden-trap' EXIT; exec {self.producer(7)}; "
            'printf forbidden-after-exec)')
        self.assert_arguments(result, 7)

    def test_function_worker_exec_preserves_pipeline_io(self):
        consumer = self.python(
            'import json,sys;print(json.dumps(json.load(sys.stdin)));'
            'raise SystemExit(23)')
        result = self.run_shell(
            f"f() {{ trap 'printf forbidden-trap' EXIT; exec {self.producer(7)}; "
            f'printf forbidden-after-exec; }}; f | {consumer}')
        self.assert_arguments(result, 23)

    def test_extra_crt_descriptor_survives_native_spawn(self):
        writer = self.python(
            "import json,os,sys;os.write(9,b'extra descriptor');"
            'print(json.dumps(sys.argv[1:]));raise SystemExit(7)', ARGUMENTS)
        result = self.run_shell(
            f'exec 9>extra; {writer}; status=$?; exec 9>&-; exit "$status"')
        self.assert_arguments(result, 7)
        self.assertEqual((self.root / 'extra').read_bytes(), b'extra descriptor')

    def test_native_exec_child_remains_in_assigned_job(self):
        command = self.python(
            'import ctypes;from ctypes import wintypes;'
            "kernel=ctypes.WinDLL('kernel32',use_last_error=True);"
            'kernel.GetCurrentProcess.restype=wintypes.HANDLE;'
            'kernel.IsProcessInJob.argtypes=[wintypes.HANDLE,wintypes.HANDLE,'
            'ctypes.POINTER(wintypes.BOOL)];'
            'assigned=wintypes.BOOL();'
            'assert kernel.IsProcessInJob(kernel.GetCurrentProcess(),None,'
            'ctypes.byref(assigned));assert assigned.value;'
            "print('assigned');raise SystemExit(11)")
        result = self.run_shell(f'exec {command}')
        self.assertEqual(result.returncode, 11, result.stderr)
        self.assertEqual(result.stdout, 'assigned\n')


if __name__ == '__main__':
    unittest.main()
