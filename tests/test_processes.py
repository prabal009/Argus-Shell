"""Native subprocess/worker regressions; all processes and shell state isolated."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import shlex
import subprocess
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import psutil
from argus import jobs, processes
from argus.language import Command, Redirection, ShellRuntime, ShellState
from argus.security import security_policy

REPO = Path(__file__).resolve().parents[1]


def isolated_environment(directory):
    return dict(os.environ, HOME=str(directory), USERPROFILE=str(directory),
                XDG_CONFIG_HOME=str(directory / 'config'), XDG_STATE_HOME=str(directory / 'state'),
                XDG_DATA_HOME=str(directory / 'data'), ARGUS_CONFIG_HOME=str(directory / 'config'),
                ARGUS_STATE_HOME=str(directory / 'state'), ARGUS_DATA_HOME=str(directory / 'data'),
                PYTHONPATH=str(REPO))


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.dict(os.environ, isolated_environment(self.directory)))
        self.stack.enter_context(patch.dict(jobs.jobs, {}, clear=True))
        self.stack.enter_context(patch.object(jobs, 'next_job_id', 1))
        self.stack.enter_context(patch.object(jobs, '_terminal_initialized', True))
        self.stack.enter_context(patch.object(jobs, '_terminal_fd', None))
        self.stack.enter_context(patch.object(jobs, 'update_audit', return_value=True))
        self.stack.enter_context(patch.dict(security_policy, {'resource_limits': {'enabled': False}}))
        self.runtime = ShellRuntime(processes.execute_pipeline, state=ShellState())
        self.addCleanup(jobs.shutdown_jobs, grace_period=0)

    def python(self, source, redirections=()):
        return Command([sys.executable, '-c', source], {}, list(redirections))

    def output(self, name):
        return Redirection(1, '>', str(self.directory / name))

    def run_commands(self, commands, background=False):
        return processes.execute_pipeline(commands, background, self.runtime, cwd=str(self.directory))

    def test_external_redirections_are_left_to_right(self):
        command = self.python("import os;os.write(1,b'out');os.write(2,b'err')", [
            self.output('first'), Redirection(2, '>&', '1'), self.output('last')])
        self.assertEqual(self.run_commands([command]), 0)
        self.assertEqual((self.directory / 'first').read_text(), 'err')
        self.assertEqual((self.directory / 'last').read_text(), 'out')

    def test_duplication_before_output_retains_previous_stdout(self):
        with processes.builtin_redirection([self.output('original')]):
            status = self.run_commands([self.python("import os;os.write(1,b'out');os.write(2,b'err')", [
                Redirection(2, '>&', '1'), self.output('new')])])
        self.assertEqual(status, 0)
        self.assertEqual((self.directory / 'original').read_text(), 'err')
        self.assertEqual((self.directory / 'new').read_text(), 'out')

    def test_explicit_redirection_overrides_pipeline_output(self):
        producer = self.python("print('saved')", [self.output('producer')])
        consumer = self.python('import sys;sys.stdout.write(sys.stdin.read())', [self.output('consumer')])
        self.assertEqual(self.run_commands([producer, consumer]), 0)
        self.assertEqual((self.directory / 'producer').read_text(), 'saved\n')
        self.assertEqual((self.directory / 'consumer').read_text(), '')

    def test_large_heredoc_and_here_string_do_not_deadlock(self):
        body = 'x' * (256 * 1024) + '\n'
        for operator, text, expected in [('<<', body, body), ('<<-', 'stripped\n', 'stripped\n'),
                                         ('<<<', 'word', 'word\n')]:
            command = self.python('import sys;sys.stdout.write(sys.stdin.read())', [
                Redirection(0, operator, text), self.output('document')])
            self.assertEqual(self.run_commands([command]), 0)
            self.assertEqual((self.directory / 'document').read_text(), expected)

    def test_arbitrary_descriptor_and_move_close(self):
        command = self.python("import os;os.write(8,b'extra');\ntry:os.fstat(7)\nexcept OSError:pass\nelse:raise RuntimeError('fd7 leaked')", [
            Redirection(7, '>', str(self.directory / 'extra')), Redirection(8, '>&', '7-')])
        self.assertEqual(self.run_commands([command]), 0)
        self.assertEqual((self.directory / 'extra').read_text(), 'extra')

    def test_builtin_pipeline_and_background_do_not_change_parent_state(self):
        self.runtime.state.variables['ISOLATED'] = 'parent'
        export = Command(['export', 'ISOLATED=child'], {}, [])
        consumer = self.python('import sys;sys.stdin.read()', [self.output('sink')])
        self.assertEqual(self.run_commands([export, consumer]), 0)
        self.assertEqual(self.runtime.state.variables['ISOLATED'], 'parent')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_commands([export], background=True), 0)
        self.assertEqual(jobs.wait_job(), 0)
        self.assertEqual(self.runtime.state.variables['ISOLATED'], 'parent')
        self.assertIsNotNone(self.runtime.state.last_background)

    def test_background_cd_and_function_worker_are_isolated(self):
        original = os.getcwd()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_commands([Command(['cd', str(self.directory)], {}, [])], True), 0)
        self.assertEqual(jobs.wait_job(), 0)
        self.assertEqual(os.getcwd(), original)
        self.runtime.state.functions['worker_function'] = 'worker_function() { export WORKER_ONLY=child; true; }'
        command = Command(['worker_function'], {}, [self.output('function')])
        self.assertEqual(self.run_commands([command, self.python('import sys;sys.stdin.read()')]), 0)
        self.assertNotIn('WORKER_ONLY', self.runtime.state.variables)

    def test_failed_late_initialization_never_releases_earlier_stage(self):
        marker = self.directory / 'executed'
        first = self.python(f"from pathlib import Path;Path({str(marker)!r}).touch()")
        last = self.python('pass', [Redirection(0, '<', str(self.directory / 'missing'))])
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_commands([first, last]), 1)
        self.assertFalse(marker.exists())
        self.assertEqual(jobs.jobs, {})

    def test_invalid_readiness_identity_rolls_back_every_gated_stage(self):
        real_popen, real_read_ready = subprocess.Popen, processes._read_ready
        for identity in ('unrelated', 'nonce', 'duplicate'):
            with self.subTest(identity=identity):
                children, messages = [], []
                marker = self.directory / ('released-' + identity)

                def record_popen(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    children.append(child)
                    return child

                def corrupt_ready(connection):
                    ready = real_read_ready(connection)
                    if identity == 'unrelated':
                        ready['pid'] = os.getpid()
                    elif identity == 'nonce':
                        ready['token'] = 'not-the-private-nonce'
                    elif messages:
                        ready['pid'] = messages[0]['pid']
                    messages.append(ready)
                    return ready

                command = self.python(f"from pathlib import Path;Path({str(marker)!r}).touch()")
                errors = io.StringIO()
                with patch.object(processes.subprocess, 'Popen', side_effect=record_popen), \
                        patch.object(processes, '_read_ready', side_effect=corrupt_ready), \
                        redirect_stderr(errors):
                    self.assertEqual(self.run_commands([command, command]), 1)
                self.assertIn('duplicate worker initialization' if identity == 'duplicate'
                              else 'invalid worker initialization identity', errors.getvalue())
                self.assertEqual(len(children), 2)
                self.assertTrue(all(child.poll() is not None for child in children))
                self.assertFalse(marker.exists())
                self.assertEqual(jobs.jobs, {})

    def test_status_pipefail_and_command_environment(self):
        first = self.python('raise SystemExit(7)')
        last = self.python('import sys;sys.stdin.read()')
        self.assertEqual(self.run_commands([first, last]), 0)
        self.runtime.state.options['pipefail'] = True
        self.assertEqual(self.run_commands([first, last]), 7)
        command = self.python("import os;print(os.environ['COMMAND_VALUE'])", [self.output('environment')])
        command.assignments['COMMAND_VALUE'] = 'temporary'
        self.assertEqual(self.run_commands([command]), 0)
        self.assertEqual((self.directory / 'environment').read_text(), 'temporary\n')
        self.assertNotIn('COMMAND_VALUE', self.runtime.state.variables)

    def test_worker_bootstrap_ignores_writable_cwd_package_shadow(self):
        package = self.directory / 'argus'
        package.mkdir()
        marker = self.directory / 'shadow-imported'
        (package / '__init__.py').write_text(
            f"from pathlib import Path;Path({str(marker)!r}).touch();raise RuntimeError('shadow')")
        self.assertEqual(self.run_commands([self.python('print(\"trusted\")', [self.output('trusted')])]), 0)
        self.assertFalse(marker.exists())
        self.assertEqual((self.directory / 'trusted').read_text(), 'trusted\n')

    @unittest.skipUnless(Path('/proc/self/fd').exists(), 'Linux descriptor accounting')
    def test_partial_pipe_creation_failure_closes_prior_pipes(self):
        real_pipe, calls = os.pipe, 0
        def fail_second_pipe():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected pipe allocation failure')
            return real_pipe()
        before = set(Path('/proc/self/fd').iterdir())
        with patch.object(processes.os, 'pipe', side_effect=fail_second_pipe), redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_commands([self.python('pass')] * 3), 1)
        self.assertEqual(set(Path('/proc/self/fd').iterdir()), before)

    def test_disowned_job_survives_shutdown_and_is_cleaned_by_fixture(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_commands([self.python('import time;time.sleep(30)')], True), 0)
        job_id = jobs.select_job()
        pid = jobs.jobs[job_id]['pids'][0]
        try:
            self.assertEqual(jobs.disown_job(), 0)
            jobs.shutdown_jobs(grace_period=0)
            self.assertTrue(psutil.pid_exists(pid))
        finally:
            jobs.terminate_tree(pid)
            deadline = time.monotonic() + 5
            while jobs.jobs[job_id]['status'] != 'done' and time.monotonic() < deadline:
                jobs.update_jobs()
                time.sleep(.01)

    @unittest.skipUnless(os.name == 'posix', 'POSIX escaped process groups')
    def test_shutdown_cleans_escaped_descendant_tree(self):
        child_file = self.directory / 'child.pid'
        code = ("import subprocess,sys,time;from pathlib import Path;"
                "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],start_new_session=True);"
                f"Path({str(child_file)!r}).write_text(str(p.pid));time.sleep(30)")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_commands([self.python(code)], True), 0)
        deadline = time.monotonic() + 5
        while not child_file.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(child_file.exists())
        child = psutil.Process(int(child_file.read_text()))
        try:
            jobs.update_jobs()
            jobs.shutdown_jobs(grace_period=0)
            deadline = time.monotonic() + 5
            while child.is_running() and child.status() != psutil.STATUS_ZOMBIE and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE)
        finally:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass

    @unittest.skipUnless(os.name == 'nt', 'actual native Windows Job Object')
    def test_windows_job_object_enforces_aggregate_active_process_limit(self):
        limits = {'enabled': True, 'max_processes': 1, 'memory_mb': 0, 'cpu_seconds': 0,
                  'file_size_mb': 0, 'open_files': 0}
        with patch.dict(security_policy, {'resource_limits': limits}):
            status = self.run_commands([self.python('print("cannot spawn past job limit")')])
        # The worker occupies the single allowed process; its native tool spawn
        # must fail rather than silently escape the aggregate process budget.
        self.assertNotEqual(status, 0)

    @unittest.skipUnless(os.name == 'nt', 'actual native Windows Job Object')
    def test_windows_job_object_is_assigned_and_memory_limit_is_real(self):
        limits = {'enabled': True, 'max_processes': 0, 'memory_mb': 128, 'cpu_seconds': 0,
                  'file_size_mb': 0, 'open_files': 0}
        with patch.dict(security_policy, {'resource_limits': limits}):
            status = self.run_commands([self.python("x=bytearray(512*1024*1024)")])
        self.assertNotEqual(status, 0)


class ParentRedirectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_builtin_order_append_combined_and_read_write(self):
        redirections = [Redirection(1, '>', str(self.path / 'one')), Redirection(2, '>&', '1'),
                        Redirection(1, '>', str(self.path / 'two'))]
        with processes.builtin_redirection(redirections):
            print('out', end='')
            print('err', end='', file=sys.stderr)
        self.assertEqual((self.path / 'one').read_text(), 'err')
        self.assertEqual((self.path / 'two').read_text(), 'out')
        with processes.builtin_redirection([Redirection(1, '&>>', str(self.path / 'two'))]):
            print('a', end='')
            print('b', end='', file=sys.stderr)
        self.assertEqual((self.path / 'two').read_text(), 'outab')
        with processes.builtin_redirection([Redirection(0, '<>', str(self.path / 'readwrite'))]):
            os.write(0, b'written')
            os.lseek(0, 0, os.SEEK_SET)
            self.assertEqual(sys.stdin.read(), 'written')

    def test_here_string_and_exception_restore_all_descriptors(self):
        original = (sys.stdin, sys.stdout, sys.stderr)
        with self.assertRaisesRegex(RuntimeError, 'body failed'):
            with processes.builtin_redirection([Redirection(0, '<<<', 'input'),
                                                Redirection(1, '>', str(self.path / 'out'))]):
                self.assertEqual(sys.stdin.readline(), 'input\n')
                print('saved')
                raise RuntimeError('body failed')
        self.assertEqual((sys.stdin, sys.stdout, sys.stderr), original)
        self.assertEqual((self.path / 'out').read_text(), 'saved\n')

    def test_flush_failure_still_restores_terminal_and_streams(self):
        original = (sys.stdin, sys.stdout, sys.stderr)
        terminal = jobs._terminal_fd
        with patch.object(jobs, '_terminal_fd', 0):
            with self.assertRaises(OSError):
                with processes.builtin_redirection([Redirection(0, '<<<', 'input'),
                                                    Redirection(1, '>', str(self.path / 'out'))]):
                    self.assertNotEqual(jobs._terminal_fd, 0)
                    sys.stdout.flush = lambda: (_ for _ in ()).throw(OSError('flush failed'))
            self.assertEqual(jobs._terminal_fd, 0)
        self.assertEqual(jobs._terminal_fd, terminal)
        self.assertEqual((sys.stdin, sys.stdout, sys.stderr), original)

    def test_noclobber_and_force_override(self):
        path = self.path / 'existing'
        path.write_text('original')
        with self.assertRaises(FileExistsError):
            with processes.builtin_redirection([Redirection(1, '>', str(path))], noclobber=True):
                self.fail('noclobber allowed overwrite')
        self.assertEqual(path.read_text(), 'original')
        with processes.builtin_redirection([Redirection(1, '>|', str(path))], noclobber=True):
            print('replacement', end='')
        self.assertEqual(path.read_text(), 'replacement')

    @unittest.skipUnless(Path('/proc/self/fd').exists(), 'Linux descriptor accounting')
    def test_repeated_redirection_does_not_leak_fds(self):
        before = set(Path('/proc/self/fd').iterdir())
        for _ in range(25):
            with processes.builtin_redirection([Redirection(0, '<<', 'body\n'),
                                                Redirection(1, '>', str(self.path / 'output'))]):
                print(sys.stdin.read(), end='')
        self.assertEqual(set(Path('/proc/self/fd').iterdir()), before)


class WorkerShellTests(unittest.TestCase):
    def test_function_pipeline_background_and_initial_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = ('LOCAL=parent; f() { LOCAL=child; export EXPORTED=worker; '
                      'printf "%s" "$1:$LOCAL"; }; '
                      'f argument | read RESULT; '
                      'f background > result & pid=$!; wait "$pid"; '
                      'printf "%s" "$LOCAL:${EXPORTED-unset}:${RESULT-unset}"')
            result = subprocess.run([sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
                                    cwd=path, env=isolated_environment(path), capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('parent:unset:unset', result.stdout)
            self.assertEqual((path / 'result').read_text(), 'background:child')

    def test_persistent_and_function_scoped_extra_descriptors_reach_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            writer = shlex.join([sys.executable, '-c', "import os;os.write(9,b'written')"])
            source = (f'exec 9>persistent; {writer}; '
                      f'f() {{ {writer}; }}; f | true; exec 9>&-; '
                      'f 9>scoped')
            result = subprocess.run([sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
                                    cwd=path, env=isolated_environment(path), capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((path / 'persistent').read_text(), 'writtenwritten')
            self.assertEqual((path / 'scoped').read_text(), 'written')

    def test_worker_exit_traps_normal_exit_and_executable_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            executable = shlex.join([sys.executable, '-c', 'pass'])
            cases = [
                ("(trap 'printf cleanup' EXIT; printf body)", 0, 'bodycleanup'),
                ("(trap 'printf cleanup' EXIT; exit 7)", 7, 'cleanup'),
                (f"(trap 'printf cleanup' EXIT; exec {executable})", 0, ''),
            ]
            for source, status, expected in cases:
                with self.subTest(source=source):
                    result = subprocess.run(
                        [sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
                        cwd=path, env=isolated_environment(path), capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stdout, expected)
            source = ("f() { trap 'printf cleanup' EXIT; printf body; }; "
                      'f > background & pid=$!; wait "$pid"')
            result = subprocess.run([sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
                                    cwd=path, env=isolated_environment(path), capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((path / 'background').read_text(), 'bodycleanup')

    def test_wait_next_does_not_reconsume_foreground_or_explicit_wait_results(self):
        cases = [
            'false; true & wait -n; first=$?; wait -n; printf "%s:%s" "$first" "$?"',
            'true & pid=$!; wait "$pid"; first=$?; wait -n; printf "%s:%s" "$first" "$?"',
        ]
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                result = subprocess.run(
                    [sys.executable, str(REPO / 'argus_shell.py'), '--norc', '-c', source],
                    cwd=path, env=isolated_environment(path), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('0:127', result.stdout)

    def test_nested_worker_preserves_settings_and_registered_secret_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            driver = (
                "from argus import config,main,utils;"
                "config.get_settings()['redaction_patterns']=['CUSTOM-NESTED'];"
                "config.get_settings()['retention_records']=1234;"
                "utils.register_secret('vault-worker-value');"
                "raise SystemExit(main.main(['--norc','-c',"
                "'f() { true CUSTOM-NESTED vault-worker-value; }; f | true']))"
            )
            result = subprocess.run([sys.executable, '-c', driver], cwd=path,
                                    env=isolated_environment(path), capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            connection = sqlite3.connect(path / 'state' / 'argus.db')
            try:
                nested = [row[0] for row in connection.execute(
                    "SELECT command FROM command_audit WHERE command LIKE 'true %'")]
            finally:
                connection.close()
            self.assertTrue(nested, 'nested function callbacks must be audited')
            for command in nested:
                self.assertNotIn('CUSTOM-NESTED', command)
                self.assertNotIn('vault-worker-value', command)
                self.assertGreaterEqual(command.count('[REDACTED]'), 2)


if __name__ == '__main__':
    unittest.main()
