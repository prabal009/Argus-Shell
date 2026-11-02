"""Internal JSON-only stage worker; not an interactive shell entry point."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys


def _load_payload(path):
    path = Path(path)
    # Payloads are ephemeral and created with exclusive mode by the parent.
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('invalid worker payload')
    with path.open(encoding='utf-8') as stream:
        payload = json.load(stream)
    path.unlink()
    if payload.get('version') != 1:
        raise ValueError('unsupported worker payload version')
    return payload


def _reset_signals():
    for name in ('SIGINT', 'SIGTSTP', 'SIGQUIT', 'SIGTTIN', 'SIGTTOU', 'SIGPIPE', 'SIGCHLD'):
        signum = getattr(signal, name, None)
        if signum is not None:
            signal.signal(signum, signal.SIG_DFL)


def _windows_standard_handles():
    # dup2 changes CRT descriptors; native Windows tools also use Win32 handles.
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
    kernel.SetStdHandle.restype = wintypes.BOOL
    for fd, handle_id in ((0, -10), (1, -11), (2, -12)):
        try:
            handle = msvcrt.get_osfhandle(fd)
        except OSError:
            handle = 0
        if not kernel.SetStdHandle(handle_id & 0xffffffff, handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _restore_windows_fds(mapping):
    import msvcrt
    for target, handle in mapping.items():
        target = int(target)
        opened = msvcrt.open_osfhandle(int(handle), os.O_BINARY | os.O_RDWR)
        if opened != target:
            try:
                os.dup2(opened, target)
            finally:
                os.close(opened)
        os.set_inheritable(target, True)


def _finish_runtime(runtime, status):
    """Consume EXIT once; ordinary trap status does not replace shell status."""
    if runtime is None:
        return status
    runtime.state.last_status = status
    action = runtime.state.traps.pop('EXIT', None)
    if action is not None:
        try:
            runtime.run(action, filename='<trap EXIT>')
        except SystemExit as error:
            status = error.code if isinstance(error.code, int) else (0 if error.code is None else 1)
    return status


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print('Argus: internal worker requires one private payload', file=sys.stderr)
        return 2
    control = None
    initialized = False
    runtime = None
    try:
        payload = _load_payload(argv[0])
        if os.name == 'nt':
            _restore_windows_fds(payload['windows_fds'])
        control = socket.create_connection(('127.0.0.1', payload['control']['port']), timeout=30)
        from . import processes, jobs
        from .processes import apply_redirections, _fd_stream, _redirection_fds, _duplicate_away
        from .language import Command, Redirection, ShellRuntime, ShellState
        from .config import get_settings, validate_settings
        from .utils import register_secret
        candidate = validate_settings(payload['settings'])
        settings = get_settings()
        settings.clear()
        settings.update(candidate)
        for value in payload['secrets']:
            register_secret(value)
        from . import main as shell_main
        from .security import security_policy
        security_policy.clear()
        security_policy.update(payload['policy'])
        command_data = payload['command']
        command = Command(argv=command_data['argv'], assignments=command_data['assignments'],
                          redirections=[Redirection(**item) for item in command_data['redirections']],
                          source=command_data.get('source', ''))
        if os.name != 'nt':
            # Keep internal transport out of the user's descriptor graph.
            duplicate = _duplicate_away(control.fileno(), _redirection_fds(command.redirections) | {0, 1, 2})
            original = control
            control = socket.socket(fileno=duplicate)
            original.close()
        state = ShellState.from_snapshot(payload['state'])
        environment = state.environment(command.assignments)
        os.environ.clear()
        os.environ.update(environment)
        os.chdir(payload['cwd'])
        _reset_signals()
        apply_redirections(command.redirections, noclobber=state.options.get('noclobber', False))
        if os.name == 'nt':
            _windows_standard_handles()
        else:
            from .resource import apply_resource_limits
            apply_resource_limits(payload['policy'])
        # Avoid inherited buffering state and ensure builtin Python I/O follows
        # the same descriptor graph as native programs.
        reserved = _redirection_fds(command.redirections)
        sys.stdin, sys.stdout, sys.stderr = (_fd_stream(0, 'r', reserved),
                                             _fd_stream(1, 'w', reserved),
                                             _fd_stream(2, 'w', reserved))
        # A function worker is already in the outer shell's foreground group.
        # Its nested commands must not steal the terminal or split that group.
        jobs._terminal_initialized = True
        jobs._terminal_fd = None
        if os.name != 'nt':
            processes._worker_group = os.getpgrp()
        ready = {'token': payload['control']['token'], 'pid': os.getpid(), 'ok': True}
        control.sendall(json.dumps(ready).encode('utf-8') + b'\n')
        initialized = True
        control.settimeout(None)
        if control.recv(1) != b'G':
            return 125
        control.close()
        control = None
        if payload['builtin']:
            state.variables.update(command.assignments)
            # Prefix assignments are visible to subprocesses of this builtin or
            # function but cannot leak out of this isolated worker.
            state.exported.update(command.assignments)
            runtime = ShellRuntime(shell_main.execute_pipeline, state=state,
                                   stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            runtime.isolated_worker = True
            runtime.persistent_fds = processes.redirected_fds(
                command.redirections, payload['persistent_fds'])
            runtime.bypass_functions = payload.get('bypass_functions', False)
            runtime.exec_requested = payload.get('exec_requested', False)
            runtime.classify_command = lambda name: 'builtin' if shell_main.is_builtin([name], runtime) else None
            status = shell_main.dispatch_builtin(command.argv, runtime) if command.argv else 0
            status = _finish_runtime(runtime, 0 if status is None else int(status))
            sys.stdout.flush()
            sys.stderr.flush()
            return 0 if status is None else int(status)
        search_path = command.assignments.get('PATH', state.variables.get('PATH', os.defpath))
        executable = shutil.which(command.argv[0], path=search_path)
        if executable is None:
            if os.path.exists(command.argv[0]):
                raise PermissionError(command.argv[0])
            raise FileNotFoundError(command.argv[0])
        if os.name == 'nt':
            # _wspawnve joins its argv entries with spaces without quoting.
            # Encode each entry for the target's CRT parser before that join;
            # never pass these shell-independent arguments through cmd.exe.
            # Keep spawnve rather than Popen: the CRT also transfers fd>2.
            # P_WAIT keeps this worker in its assigned Job Object until the
            # native child exits, preserving status and descendant ownership.
            arguments = [subprocess.list2cmdline([argument]) for argument in command.argv]
            return os.spawnve(os.P_WAIT, executable, arguments, environment)
        os.execve(executable, command.argv, environment)
    except SystemExit as error:
        status = error.code if isinstance(error.code, int) else (0 if error.code is None else 1)
        return _finish_runtime(runtime, status)
    except BaseException as error:
        if control is not None and not initialized:
            try:
                control.sendall(json.dumps({'token': payload['control']['token'],
                                            'pid': os.getpid(), 'ok': False,
                                            'error': str(error)}).encode('utf-8') + b'\n')
            except OSError:
                pass
        try:
            from .utils import safe_text, redact_text
            print('Argus: worker: ' + safe_text(redact_text(error)), file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass
        status = 127 if isinstance(error, FileNotFoundError) else 126 if isinstance(error, PermissionError) else 1
        return _finish_runtime(runtime, status)
    finally:
        if control is not None:
            control.close()


if __name__ == '__main__':
    raise SystemExit(main())
