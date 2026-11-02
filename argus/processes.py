"""Gated subprocess pipelines and ordered descriptor redirection.

No child runs user code before every stage has initialized.  Windows workers
belong to a native Job Object; POSIX workers share a process group.  Workers
receive private JSON, never executable serialization such as pickle.
"""
from contextlib import contextmanager
from dataclasses import asdict
import errno
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time

from . import jobs
from .utils import safe_text, redact_text, secret_values
from .storage import open_private, private_temporary_directory

_worker_group = None


def _flush_streams():
    for stream in (sys.stdout, sys.stderr):
        stream.flush()


def _redirection_fds(redirections):
    descriptors = set()
    for redirection in redirections:
        descriptors.add(redirection.fd)
        if redirection.operator in ('&>', '&>>'):
            descriptors.update((1, 2))
        if redirection.operator in ('<&', '>&'):
            target = redirection.target.rstrip('-')
            if target.isdecimal():
                descriptors.add(int(target))
    if any(type(fd) is not int or fd < 0 or fd > 65535 for fd in descriptors):
        raise ValueError('descriptor must be between 0 and 65535')
    return descriptors


def _duplicate_away(fd, reserved):
    """Save an fd without accidentally occupying a user-mentioned descriptor."""
    held = []
    try:
        while True:
            duplicate = os.dup(fd)
            if duplicate not in reserved:
                os.set_inheritable(duplicate, False)
                return duplicate
            held.append(duplicate)
    finally:
        for duplicate in held:
            os.close(duplicate)


def _install_file(fd, target, flags):
    opened = os.open(target, flags | getattr(os, 'O_BINARY', 0), 0o666)
    try:
        if opened != fd:
            os.dup2(opened, fd)
        else:
            os.set_inheritable(fd, True)
    finally:
        if opened != fd:
            os.close(opened)


def apply_redirections(redirections, *, noclobber=False):
    """Apply redirections left-to-right, after the pipeline's default fds."""
    _redirection_fds(redirections)
    for redirection in redirections:
        fd, operator, target = redirection.fd, redirection.operator, redirection.target
        if operator in ('<&', '>&'):
            if target == '-':
                try:
                    os.close(fd)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
            elif target.rstrip('-').isdecimal():
                source = int(target.rstrip('-'))
                os.dup2(source, fd)
                if target.endswith('-') and source != fd:
                    os.close(source)
            elif operator == '>&' and fd == 1:
                flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if noclobber else os.O_TRUNC)
                _install_file(1, target, flags)
                os.dup2(1, 2)
            else:
                raise ValueError('invalid descriptor duplication: ' + target)
        elif operator in ('<<', '<<-', '<<<'):
            # Temporary files cannot deadlock on a heredoc larger than a pipe.
            body = target + ('\n' if operator == '<<<' else '')
            with tempfile.TemporaryFile() as document:
                document.write(body.encode('utf-8', 'surrogateescape'))
                document.flush()
                document.seek(0)
                if document.fileno() == fd:
                    duplicate = os.dup(fd)
                    document.close()
                    try:
                        os.dup2(duplicate, fd)
                    finally:
                        os.close(duplicate)
                else:
                    os.dup2(document.fileno(), fd)
        elif operator == '<':
            _install_file(fd, target, os.O_RDONLY)
        elif operator == '<>':
            _install_file(fd, target, os.O_RDWR | os.O_CREAT)
        elif operator in ('>', '>|', '>>', '&>', '&>>'):
            flags = os.O_WRONLY | os.O_CREAT
            flags |= os.O_APPEND if operator in ('>>', '&>>') else os.O_TRUNC
            if noclobber and operator in ('>', '&>'):
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            _install_file(1 if operator.startswith('&') else fd, target, flags)
            if operator.startswith('&'):
                os.dup2(1, 2)
        else:
            raise ValueError('unsupported redirection operator: ' + operator)


def _fd_stream(fd, mode, reserved=()):
    """Python builtins must observe dup2 even under redirected Python streams."""
    try:
        duplicate = _duplicate_away(fd, set(reserved) | {0, 1, 2})
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        # A closed descriptor remains closed. Writes/reads fail, not disappear.
        return _ClosedStream()
    try:
        return io.open(duplicate, mode, encoding='utf-8', errors='surrogateescape',
                       buffering=1 if mode == 'w' else -1, closefd=True)
    except BaseException:
        os.close(duplicate)
        raise


class _ClosedStream(io.TextIOBase):
    def write(self, text):
        raise OSError(errno.EBADF, 'bad file descriptor')

    def read(self, size=-1):
        raise OSError(errno.EBADF, 'bad file descriptor')

    def readline(self, size=-1):
        raise OSError(errno.EBADF, 'bad file descriptor')


@contextmanager
def builtin_redirection(redirections, *, noclobber=False):
    """Temporarily redirect parent builtins, restoring even after flush errors."""
    redirections = list(redirections)
    if not redirections:
        yield
        return
    reserved = _redirection_fds(redirections) | {0, 1, 2}
    touched = {redirection.fd for redirection in redirections}
    for redirection in redirections:
        if redirection.operator in ('&>', '&>>') or (
                redirection.operator == '>&' and redirection.fd == 1
                and not redirection.target.rstrip('-').isdecimal()
                and redirection.target != '-'):
            touched.update((1, 2))
        if redirection.operator in ('<&', '>&') and redirection.target.endswith('-'):
            source = redirection.target[:-1]
            if source.isdecimal():
                touched.add(int(source))
    originals = (sys.stdin, sys.stdout, sys.stderr)
    saved, streams = {}, []
    inheritable = {}
    terminal_original, terminal_saved = jobs._terminal_fd, None
    pending_error = None
    try:
        _flush_streams()
        if terminal_original in touched:
            terminal_saved = _duplicate_away(terminal_original, reserved)
            jobs._terminal_fd = terminal_saved
        for fd in sorted(touched):
            try:
                saved[fd] = _duplicate_away(fd, reserved)
                inheritable[fd] = os.get_inheritable(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                saved[fd] = None
        apply_redirections(redirections, noclobber=noclobber)
        for fd, attribute, mode in ((0, 'stdin', 'r'), (1, 'stdout', 'w'), (2, 'stderr', 'w')):
            if fd in touched:
                stream = _fd_stream(fd, mode, reserved)
                streams.append(stream)
                setattr(sys, attribute, stream)
        yield
    finally:
        # Never let a buffered write prevent restoration of another descriptor.
        active_exception = sys.exc_info()[0] is not None
        for stream in streams:
            try:
                stream.flush()
            except BaseException as error:
                pending_error = pending_error or error
        sys.stdin, sys.stdout, sys.stderr = originals
        for fd, saved_fd in saved.items():
            try:
                if saved_fd is None:
                    try:
                        os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                else:
                    os.dup2(saved_fd, fd, inheritable=inheritable.get(fd, True))
            except BaseException as error:
                pending_error = pending_error or error
            finally:
                if saved_fd is not None:
                    os.close(saved_fd)
        for stream in streams:
            try:
                stream.close()
            except BaseException as error:
                pending_error = pending_error or error
        jobs._terminal_fd = terminal_original
        if terminal_saved is not None:
            os.close(terminal_saved)
        if pending_error is not None and not active_exception:
            raise pending_error


class WindowsJob:
    """Native aggregate process, memory and CPU limits with tree ownership."""
    def __init__(self, limits=None):
        if os.name != 'nt':
            raise OSError('Windows Job Objects require Windows')
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]
        class BASIC(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                        ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD),
                        ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t),
                        ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.c_size_t),
                        ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]
        class EXTENDED(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', BASIC), ('IoInfo', IO_COUNTERS),
                        ('ProcessMemoryLimit', ctypes.c_size_t),
                        ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t),
                        ('PeakJobMemoryUsed', ctypes.c_size_t)]
        self.EXTENDED = EXTENDED
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        # Intentionally NOT KILL_ON_JOB_CLOSE: disowned processes survive exit.
        info = EXTENDED()
        limits = limits or {}
        try:
            if limits.get('enabled'):
                for key in ('cpu_seconds', 'memory_mb', 'max_processes', 'file_size_mb', 'open_files'):
                    value = limits.get(key, 0)
                    if type(value) is not int or value < 0:
                        raise ValueError(key + ' must be a nonnegative integer')
                unsupported = [key for key in ('file_size_mb', 'open_files') if limits.get(key, 0)]
                if unsupported:
                    raise ValueError('Windows cannot enforce resource limits: ' + ', '.join(unsupported))
                if limits.get('cpu_seconds'):
                    info.BasicLimitInformation.PerJobUserTimeLimit = limits['cpu_seconds'] * 10_000_000
                    info.BasicLimitInformation.LimitFlags |= 0x00000004
                if limits.get('memory_mb'):
                    info.JobMemoryLimit = limits['memory_mb'] * 1024 * 1024
                    info.BasicLimitInformation.LimitFlags |= 0x00000200
                if limits.get('max_processes'):
                    info.BasicLimitInformation.ActiveProcessLimit = limits['max_processes']
                    info.BasicLimitInformation.LimitFlags |= 0x00000008
            if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def assign(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def terminate(self):
        if self.handle and not self.kernel.TerminateJobObject(self.handle, 1):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _worker_argv(payload, environment):
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--internal-worker', str(payload)]
    executable = sys.executable
    if os.name == 'nt':
        # Match multiprocessing's Windows venv launch (bpo-35797). Scripts'
        # python.exe is a redirector: Popen would own its PID/handle rather
        # than the interpreter reporting readiness, and Job assignment could
        # race the redirector's child creation. Launch the real interpreter
        # directly while retaining the trusted venv's executable/site paths.
        environment.pop('__PYVENV_LAUNCHER__', None)
        base_executable = getattr(sys, '_base_executable', executable)
        if os.path.normcase(base_executable) != os.path.normcase(executable):
            environment['__PYVENV_LAUNCHER__'] = executable
            executable = base_executable
    package_root = str(Path(__file__).resolve().parent.parent)
    bootstrap = ("import runpy,sys;sys.path.insert(0," + repr(package_root) + ");"
                 "sys.argv=['argus.worker',sys.argv[1]];"
                 "runpy.run_module('argus.worker',run_name='__main__')")
    return [executable, '-I', '-c', bootstrap, str(payload)]


def _read_ready(connection):
    message = bytearray()
    while len(message) < 65536:
        chunk = connection.recv(1)
        if not chunk:
            raise OSError('worker disconnected before initialization')
        if chunk == b'\n':
            return json.loads(message)
        message.extend(chunk)
    raise OSError('oversized worker initialization message')


def _rollback(children, controller):
    if controller is not None:
        try:
            controller.terminate()
        except OSError:
            pass
    # Per-PID/tree termination also handles children that left the group.
    for child in children:
        jobs.terminate_tree(child.pid)
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def _runtime_stream(stream):
    try:
        stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None
    return stream


def redirected_fds(redirections, existing=()):
    """Currently open, shell-owned extra fds after applying user redirections."""
    result = set()
    for fd in (set(existing) | _redirection_fds(redirections)) - {0, 1, 2}:
        try:
            os.fstat(fd)
        except OSError:
            continue
        result.add(fd)
    return result


def _windows_inheritance(descriptors, owned_handles):
    """Pass only duplicated user handles; reconstruct CRT fd numbers in worker."""
    import _winapi
    import msvcrt
    mapping = {}
    process = _winapi.GetCurrentProcess()
    for fd in descriptors:
        handle = _winapi.DuplicateHandle(process, msvcrt.get_osfhandle(fd), process,
                                         0, True, _winapi.DUPLICATE_SAME_ACCESS)
        owned_handles.append(handle)
        mapping[fd] = handle
    startup = subprocess.STARTUPINFO()
    startup.lpAttributeList = {'handle_list': list(mapping.values())}
    return mapping, startup


def execute_pipeline(commands, background, runtime, *, audit_id=None, started=None, cwd=None):
    """Launch already-authorized expanded Commands, preserving pipeline status."""
    from . import main
    from .security import security_policy
    from .config import get_settings
    commands = list(commands)
    if not commands:
        return 0
    started = time.monotonic() if started is None else started
    cwd = os.getcwd() if cwd is None else cwd
    children, connections, pipes = [], [], []
    persistent = set(getattr(runtime, 'persistent_fds', ())) - {0, 1, 2}
    # Snapshot before allocating pipes/listeners: their fd numbers must never
    # masquerade as a previously open shell descriptor in e.g. 0<&3.
    shell_descriptors = redirected_fds(
        [redirection for command in commands for redirection in command.redirections], persistent)
    persistent.intersection_update(shell_descriptors)
    windows_handles = []
    controller, job_id, pgid = None, None, (_worker_group or 0)
    listener = None
    token = secrets.token_hex(32)
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(max(1, len(commands)))
        listener.settimeout(30)
        _flush_streams()
        if os.name == 'nt':
            controller = WindowsJob(security_policy.get('resource_limits', {}))
        with private_temporary_directory(prefix='argus-worker-') as directory:
            for _ in range(len(commands) - 1):
                pipes.append(os.pipe())
            for index, command in enumerate(commands):
                inherited = (persistent | _redirection_fds(command.redirections)) & shell_descriptors
                windows_mapping, windows_startup = ({}, None)
                if os.name == 'nt' and inherited:
                    windows_mapping, windows_startup = _windows_inheritance(inherited, windows_handles)
                payload_path = Path(directory) / (str(index) + '.json')
                payload = {
                    'version': 1, 'command': asdict(command),
                    'state': runtime.state.snapshot(), 'cwd': cwd,
                    'policy': security_policy,
                    'settings': get_settings(),
                    'secrets': secret_values(),
                    'persistent_fds': sorted(persistent),
                    'windows_fds': windows_mapping,
                    'builtin': not command.argv or main.is_builtin(command.argv, runtime),
                    'bypass_functions': bool(getattr(runtime, 'bypass_functions', False)),
                    'exec_requested': bool(getattr(runtime, 'exec_requested', False)),
                    'control': {'port': listener.getsockname()[1], 'token': token + ':' + str(index)},
                }
                with os.fdopen(open_private(payload_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                               'w', encoding='utf-8') as stream:
                    json.dump(payload, stream, ensure_ascii=True)
                environment = runtime.state.environment(command.assignments)
                kwargs = {'stdin': pipes[index - 1][0] if index else _runtime_stream(runtime.stdin),
                          'stdout': pipes[index][1] if index < len(pipes) else _runtime_stream(runtime.stdout),
                          'stderr': _runtime_stream(runtime.stderr),
                          'env': environment, 'cwd': cwd, 'close_fds': True}
                if os.name == 'nt':
                    kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
                    if windows_startup is not None:
                        kwargs['startupinfo'] = windows_startup
                else:
                    kwargs['process_group'] = pgid
                    kwargs['pass_fds'] = tuple(inherited)
                child = subprocess.Popen(_worker_argv(payload_path, environment), **kwargs)
                children.append(child)
                if controller is not None:
                    controller.assign(child)
                if not pgid:
                    pgid = child.pid
            for pair in pipes:
                for fd in pair:
                    os.close(fd)
            pipes.clear()
            ready_tokens = set()
            expected_tokens = {token + ':' + str(index) for index in range(len(children))}
            while len(ready_tokens) < len(children):
                connection, _ = listener.accept()
                connections.append(connection)
                connection.settimeout(30)
                ready = _read_ready(connection)
                # Identity is the per-worker secret token, not the PID: on Windows a
                # venv launcher may interpose a process so the reporting PID differs
                # from the Popen handle's PID.
                if ready.get('token') not in expected_tokens:
                    raise OSError('invalid worker initialization identity')
                if ready['token'] in ready_tokens:
                    raise OSError('duplicate worker initialization')
                if not ready.get('ok'):
                    raise OSError(ready.get('error', 'worker initialization failed'))
                ready_tokens.add(ready['token'])
            description = ' | '.join(command.source or shlex.join(command.argv) for command in commands)
            hook = getattr(runtime, 'drain_traps', None)
            job_id = jobs.create_job(pgid, [child.pid for child in children], description,
                                     background=background,
                                     command_type='pipeline' if len(commands) > 1 else 'external',
                                     audit_id=audit_id, cwd=cwd, start_time=started,
                                     handles=children, controller=controller, signal_hook=hook,
                                     pipefail=runtime.state.options.get('pipefail', False))
            if not background and not jobs.give_terminal_to(pgid):
                raise OSError('cannot give terminal to pipeline')
            for connection in connections:
                connection.sendall(b'G')
            if background:
                runtime.state.last_background = children[-1].pid
                print(f'[{job_id}] {pgid}')
                return 0
            return jobs.wait_for_job(job_id)
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        _rollback(children, controller)
        if job_id is not None:
            jobs.update_jobs()
        print('Argus: launch failed: ' + safe_text(redact_text(error)), file=sys.stderr)
        return 1
    except BaseException:
        _rollback(children, controller)
        if job_id is not None:
            jobs.update_jobs()
        raise
    finally:
        for pair in pipes:
            for fd in pair:
                os.close(fd)
        if listener is not None:
            listener.close()
        for connection in connections:
            connection.close()
        if job_id is None and controller is not None:
            controller.close()
        if windows_handles:
            import _winapi
            for handle in windows_handles:
                _winapi.CloseHandle(handle)
        if not background:
            jobs.give_terminal_to_shell()
