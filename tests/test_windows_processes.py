"""Real Windows CLI argument transport, supervised exec and descriptor regressions."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
import venv


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

    def test_nested_venv_keeps_direct_worker_identity_dependencies_and_job_limits(self):
        outer = self.root / 'outer venv'
        nested = self.root / 'nested venv'
        venv.EnvBuilder(with_pip=False, system_site_packages=True).create(outer)
        created = subprocess.run(
            [str(outer / 'Scripts' / 'python.exe'), '-I', '-c',
             'import sys,venv;venv.EnvBuilder(with_pip=False,system_site_packages=True)'
             '.create(sys.argv[1])', str(nested)],
            cwd=self.root, env=self.environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(created.returncode, 0, created.stderr)
        (nested / 'Lib' / 'site-packages' / 'argus_venv_probe.py').write_text(
            "VALUE = 'nested-only dependency'\n", encoding='utf-8')
        shadow = self.root / 'argus'
        shadow.mkdir()
        (shadow / '__init__.py').write_text("raise RuntimeError('untrusted cwd import')\n")
        code = textwrap.dedent('''
            import ctypes, json, os, subprocess, sys
            from ctypes import wintypes
            from pathlib import Path
            sys.path.insert(0, sys.argv[1])
            from argus import jobs, processes
            from argus.language import Command, Redirection, ShellRuntime, ShellState
            from argus.security import security_policy
            expected = Path(sys.argv[2])
            assert Path(sys.prefix) == expected
            assert Path(sys.executable) == expected / 'Scripts' / 'python.exe'
            environment = dict(os.environ, __PYVENV_LAUNCHER__='untrusted launcher')
            argv = processes._worker_argv('unused-payload', environment)
            assert argv[0] == sys._base_executable
            assert environment['__PYVENV_LAUNCHER__'] == sys.executable
            argv[3] = (
                'import argus_venv_probe,json,sys;'
                'print(json.dumps([sys.prefix,sys.executable,sys.flags.isolated,'
                'argus_venv_probe.VALUE]))')
            probe = subprocess.run(argv, env=environment, capture_output=True,
                                   text=True, timeout=30)
            assert probe.returncode == 0, probe.stderr
            prefix, executable, isolated, dependency = json.loads(probe.stdout)
            assert Path(prefix) == expected
            assert Path(executable) == Path(sys.executable)
            assert isolated == 1
            assert dependency == 'nested-only dependency'

            assigned, ready_pids = {}, []
            original_assign = processes.WindowsJob.assign
            original_ready = processes._read_ready
            def in_exact_job(controller, child):
                query = controller.kernel.IsProcessInJob
                query.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                  ctypes.POINTER(wintypes.BOOL)]
                query.restype = wintypes.BOOL
                member = wintypes.BOOL()
                assert query(int(child._handle), controller.handle, ctypes.byref(member))
                assert member.value, 'worker escaped the exact aggregate-limit Job'
            def assign(controller, child):
                original_assign(controller, child)
                in_exact_job(controller, child)
                assigned[child.pid] = (controller, child)
            def read_ready(connection):
                ready = original_ready(connection)
                assert ready['pid'] in assigned, 'redirector PID differs from interpreter PID'
                controller, child = assigned[ready['pid']]
                in_exact_job(controller, child)
                ready_pids.append(ready['pid'])
                return ready
            processes.WindowsJob.assign = assign
            processes._read_ready = read_ready
            jobs._terminal_initialized = True
            jobs._terminal_fd = None
            security_policy['resource_limits'] = {
                'enabled': True, 'max_processes': 2, 'memory_mb': 0,
                'cpu_seconds': 0, 'file_size_mb': 0, 'open_files': 0}
            runtime = ShellRuntime(processes.execute_pipeline, state=ShellState())
            try:
                # Two workers must fit a two-process aggregate cap, with no
                # hidden redirector occupying a slot or escaping ownership.
                status = processes.execute_pipeline(
                    [Command(['pwd'], {}, []), Command(['true'], {}, [])], False, runtime)
                assert status == 0, status
                assert len(ready_pids) == 2
                output = Path.cwd() / 'nested-native-output'
                status = processes.execute_pipeline(
                    [Command([sys._base_executable, '-c',
                              "print('native');raise SystemExit(7)"], {},
                             [Redirection(1, '>', str(output))])], False, runtime)
                assert status == 7, status
                assert output.read_text() == 'native\\n'
                assert processes.execute_pipeline(
                    [Command(['true'], {}, [])], True, runtime) == 0
                assert runtime.state.last_background == ready_pids[-1]
                assert jobs.wait_job() == 0
                assert len(ready_pids) == 4
                assert all(child.poll() is not None for _, child in assigned.values())
            finally:
                jobs.shutdown_jobs(grace_period=0)
            print('nested-venv-identity-and-job-ok')
        ''')
        result = subprocess.run(
            [str(nested / 'Scripts' / 'python.exe'), '-I', '-c', code, str(REPO), str(nested)],
            cwd=self.root, env=dict(self.environment, PYTHONPATH=str(self.root)),
            capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('nested-venv-identity-and-job-ok', result.stdout)


if __name__ == '__main__':
    unittest.main()
