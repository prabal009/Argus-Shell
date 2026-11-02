"""Programmable Argus shell, portable process dispatch and explicit trust profiles."""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import signal
import sys
import time

from . import __version__, builtins, jobs, operations, processes
from . import config
from .audit import audit_command, update_audit
from .database import initialize_database
from .language import Command, ShellRuntime, ShellState, command_text
from .security import (security_policy, load_policy_from_disk, evaluate_security,
                       analyze_command_risk, administrative_command, log_security_action)
from .suspicious import detect_suspicious
from .utils import SESSION_ID, get_current_directory, safe_text, redact_text

_SESSION = None
_RUNTIME = None
_TRAP_HANDLERS = {}
_REPLAYING = False
_ARGUS_BUILTINS = {
    'cd': builtins.builtin_cd, 'pwd': builtins.builtin_pwd, 'env': builtins.builtin_env,
    'history': builtins.builtin_history, 'jobs': builtins.builtin_jobs,
    'audit': builtins.builtin_audit, 'audit-stats': builtins.builtin_audit_stats,
    'risk': builtins.builtin_risk, 'suspicious': builtins.builtin_suspicious,
    'suspicious-stats': builtins.builtin_suspicious_stats,
    'suspicious-clear': builtins.builtin_suspicious_clear,
    'security': builtins.builtin_security, 'allow': builtins.builtin_allow,
    'deny': builtins.builtin_deny, 'allowlist': builtins.builtin_allowlist,
    'help': builtins.builtin_help, 'settings': operations.builtin_settings,
    'redaction': operations.builtin_redaction, 'vault': operations.builtin_vault,
    'security-actions': operations.builtin_security_actions,
}
_SPECIAL = {'fg', 'bg', 'wait', 'disown', 'redo', 'exit', 'echo', 'printf'}


def is_builtin(argv, runtime=None):
    if not argv:
        return False
    runtime = runtime or _RUNTIME
    if runtime is not None and runtime.exec_requested:
        return False
    return argv[0] in _ARGUS_BUILTINS or argv[0] in _SPECIAL or bool(
        runtime and (argv[0] in runtime.builtin_names or runtime.has_function(argv[0])))


def _install_traps(runtime):
    for name in runtime.state.traps:
        if name in {'EXIT', 'ERR', 'DEBUG', 'RETURN'}:
            continue
        number = getattr(signal, 'SIG' + name, None)
        if number is None or number in {getattr(signal, 'SIGKILL', None), getattr(signal, 'SIGSTOP', None)}:
            continue
        try:
            if number not in _TRAP_HANDLERS:
                _TRAP_HANDLERS[number] = signal.getsignal(number)
            signal.signal(number, lambda value, frame: runtime.deliver_signal(value))
        except (ValueError, OSError):
            continue
    for number in list(_TRAP_HANDLERS):
        name = signal.Signals(number).name.removeprefix('SIG')
        if name not in runtime.state.traps:
            signal.signal(number, _TRAP_HANDLERS.pop(number))


def _printf(argv, runtime):
    if len(argv) < 2:
        print('printf: format required', file=runtime.stderr)
        return 2
    import re
    import codecs
    template, values = argv[1], list(argv[2:])
    def escapes(text):
        # Decode shell printf escapes without changing non-ASCII characters.
        return re.sub(r'\\(?:[abefnrtv\\]|0[0-7]{0,3}|x[0-9a-fA-F]{1,2})',
                      lambda m: codecs.decode(m[0].replace('\\e', '\\x1b'), 'unicode_escape'), text)
    template = escapes(template)
    index = 0
    pattern = re.compile(r'%(?:([-+ #0]*)(\d*)(?:\.(\d+))?([sdbouxXeEfFgGq%]))')
    while True:
        before = index
        def replace(match):
            nonlocal index
            flags, width, precision, kind = match.groups()
            if kind == '%':
                return '%'
            value = values[index] if index < len(values) else ''
            index += 1
            if kind == 'b':
                return escapes(value)
            if kind == 'q':
                import shlex
                return shlex.quote(value)
            fmt = '%' + flags + width + ('.' + precision if precision is not None else '') + kind
            if kind in 'douxX':
                converted = int(value, 0) if value else 0
            elif kind in 'eEfFgG':
                converted = float(value or 0)
            else:
                converted = value
            return fmt % converted
        try:
            runtime.stdout.write(pattern.sub(replace, template))
        except (ValueError, TypeError, OverflowError) as error:
            print('printf: ' + safe_text(error), file=runtime.stderr)
            return 1
        if index >= len(values) or index == before:
            break
    return 0


def dispatch_builtin(argv, runtime):
    """The same dispatch is used in the parent and isolated pipeline workers."""
    global _REPLAYING
    builtins.configure_runtime(runtime, _SESSION)
    if runtime.classify_command is None:
        runtime.classify_command = lambda item: "builtin" if item in _ARGUS_BUILTINS or item in _SPECIAL else None
    name, args = argv[0], argv[1:]
    if name == 'exit':
        if len(args) > 1:
            return 2
        try:
            status = int(args[0]) % 256 if args else runtime.state.last_status
        except ValueError:
            print('exit: integer status required', file=runtime.stderr)
            return 2
        raise SystemExit(status)
    if name == 'redo':
        if args or _REPLAYING:
            return 2
        source = getattr(runtime.state, 'last_command', '')
        if not source:
            print('Argus: nothing to redo', file=runtime.stderr)
            return 1
        _REPLAYING = True
        try:
            return runtime.run(source, filename='<redo>')
        finally:
            _REPLAYING = False
    if name in {'fg', 'bg', 'disown'}:
        if len(args) > 1:
            return 2
        function = {'fg': jobs.foreground_job, 'bg': jobs.background_job, 'disown': jobs.disown_job}[name]
        return function(args[0] if args else None)
    if name == 'wait':
        if args == ['-n']:
            while True:
                for number, job in list(jobs.jobs.items()):
                    if job.get('background') and not job.get('disowned') and job['status'] == 'done' and not job.get('waited'):
                        job['waited'] = True
                        return job['last_status']
                if not any(j.get('background') and not j.get('disowned') and j['status'] != 'done' for j in jobs.jobs.values()):
                    return 127
                jobs.update_jobs()
                runtime.drain_traps()
                time.sleep(.01)
        if args:
            status = 0
            for selector in args:
                status = jobs.wait_job(selector)
            return status
        for number, job in list(jobs.jobs.items()):
            if not job.get('disowned'):
                jobs.wait_for_job(number)
                job['waited'] = True
        return 0
    if name == 'echo':
        newline = True
        if args and args[0] == '-n':
            newline, args = False, args[1:]
        print(' '.join(args), end='\n' if newline else '', file=runtime.stdout)
        return 0
    if name == 'printf':
        return _printf(argv, runtime)
    if runtime.has_function(name) or name in runtime.builtin_names:
        return runtime.run_builtin(argv)
    if name in _ARGUS_BUILTINS:
        return _ARGUS_BUILTINS[name](argv)
    return None


def _inspection(command):
    argv = command.argv
    if not argv:
        return False
    name = argv[0]
    if name in {'pwd', 'env', 'history', 'jobs', 'help', 'risk', 'audit-stats', 'suspicious-stats', 'allowlist', 'exit'}:
        return len(argv) == 1 or name == 'risk' or name == 'exit' or (name == 'history' and argv[1] in {'search', 'list'})
    if name in {'audit', 'suspicious', 'security-actions'}:
        return len(argv) == 1 or argv[1] not in {'clear', 'archive'}
    return name == 'security' and len(argv) == 1


def _authorize(source, commands, background, runtime, score, hits):
    decision, reason = evaluate_security(
        source, score, hits, stages=commands,
        administrative=administrative_command(commands, background),
        environment=runtime.state.variables,
    )
    if decision == 'confirm':
        print('Argus: confirmation required: ' + safe_text(reason), file=runtime.stderr)
        try:
            # Script input is not silently consumed as an authorization answer.
            accepted = sys.stdin.isatty() and input('Run anyway? [y/N] ').strip().lower() == 'y'
        except (EOFError, KeyboardInterrupt):
            accepted = False
        log_security_action(security_policy['mode'], 'confirm-allowed' if accepted else 'confirm-denied',
                            reason, source, score, hits, SESSION_ID)
        return accepted, reason
    if decision == 'deny':
        print('Argus: BLOCKED: ' + safe_text(reason), file=runtime.stderr)
        log_security_action(security_policy['mode'], 'deny', reason, source, score, hits, SESSION_ID)
        return False, reason
    return True, reason


def execute_pipeline(commands, background, runtime):
    """Authorize each expanded command before its redirects or dispatch occur."""
    commands = list(commands)
    if not commands:
        return 0
    source = command_text(commands)
    if not (len(commands) == 1 and commands[0].argv and
            (commands[0].argv[0] == "redo" or commands[0].argv[0].startswith("__argus_"))):
        runtime.state.last_command = " | ".join(command.source or command_text(command) for command in commands)
    started, cwd = time.monotonic(), get_current_directory()
    score, reasons = analyze_command_risk(source, commands, environment=runtime.state.variables)
    inspection = len(commands) == 1 and _inspection(commands[0])
    hits = [] if inspection else detect_suspicious(source)
    allowed, reason = _authorize(source, commands, background, runtime, score, hits)
    name = commands[0].argv[0] if commands[0].argv else 'assignment'
    if not allowed:
        audit_command(source, command_name=name, exit_status=126, background=background,
                      command_type='blocked', cwd=cwd, risk_score=score, risk_reasons=reasons,
                      security_action=reason, state='blocked')
        return 126
    if runtime.state.options.get('noexec'):
        return 0
    if runtime.state.options.get('xtrace'):
        print('+ ' + safe_text(redact_text(source)), file=runtime.stderr)
    if score >= 70 and not inspection:
        print(f'Argus: high-risk command (score {score})', file=runtime.stderr)
    audit_id = audit_command(source, command_name=name, background=background,
                             command_type='pipeline' if len(commands) > 1 else 'builtin' if is_builtin(commands[0].argv, runtime) else 'external',
                             cwd=cwd, risk_score=score, risk_reasons=reasons, state='running')
    handed_to_job, status = False, 1
    try:
        command = commands[0]
        if (len(commands) == 1 and not background and command.argv[:1] != ['__argus_subshell__']
                and (not command.argv or is_builtin(command.argv, runtime))):
            permanent = command.argv == ['exec'] and command.redirections
            if permanent:
                processes.apply_redirections(command.redirections, noclobber=runtime.state.options.get('noclobber', False))
                persistent = set(getattr(runtime, 'persistent_fds', ()))
                persistent.update(redirection.fd for redirection in command.redirections if redirection.fd > 2)
                runtime.persistent_fds = {fd for fd in persistent if _descriptor_open(fd)}
                streams = getattr(runtime, '_persistent_streams', {})
                touched = {redirection.fd for redirection in command.redirections}
                for fd, attribute, mode in ((0, 'stdin', 'r'), (1, 'stdout', 'w'), (2, 'stderr', 'w')):
                    if fd in touched:
                        stream = processes._fd_stream(fd, mode, runtime.persistent_fds)
                        if mode == 'w' and (config.get_settings()['no_color'] or config.get_settings()['accessibility'] or 'NO_COLOR' in os.environ):
                            stream = _PlainStream(stream)
                        previous = streams.get(fd)
                        setattr(sys, attribute, stream)
                        setattr(runtime, attribute, stream)
                        streams[fd] = stream
                        if previous is not None:
                            previous.close()
                runtime._persistent_streams = streams
                status = 0
            else:
                with processes.builtin_redirection(command.redirections, noclobber=runtime.state.options.get('noclobber', False)):
                    original_streams = runtime.stdin, runtime.stdout, runtime.stderr
                    original_fds = set(getattr(runtime, 'persistent_fds', ()))
                    runtime.persistent_fds = processes.redirected_fds(command.redirections, original_fds)
                    if command.redirections:
                        runtime.stdin, runtime.stdout, runtime.stderr = sys.stdin, sys.stdout, sys.stderr
                    try:
                        with runtime.assignment_scope(command.assignments):
                            status = dispatch_builtin(command.argv, runtime) if command.argv else 0
                            runtime.stdout.flush()
                            runtime.stderr.flush()
                    finally:
                        runtime.stdin, runtime.stdout, runtime.stderr = original_streams
                        runtime.persistent_fds = original_fds
            _install_traps(runtime)
        else:
            if (runtime.exec_requested and len(commands) == 1 and not background
                    and os.name != 'nt'):
                sys.stdout.flush()
                sys.stderr.flush()
                processes.apply_redirections(command.redirections, noclobber=runtime.state.options.get('noclobber', False))
                from .resource import apply_resource_limits
                apply_resource_limits(security_policy)
                update_audit(audit_id, state="replaced", duration_ms=(time.monotonic()-started)*1000)
                environment = runtime.state.environment(command.assignments)
                lookup = command.assignments.get('PATH', runtime.state.variables.get('PATH', os.defpath))
                executable = shutil.which(command.argv[0], path=lookup)
                if executable is None:
                    raise FileNotFoundError(command.argv[0])
                os.execve(executable, command.argv, environment)
            status = processes.execute_pipeline(commands, background, runtime,
                                                audit_id=audit_id, started=started, cwd=cwd)
            handed_to_job = any(job.get('audit_id') == audit_id for job in jobs.jobs.values())
            if runtime.state.options.get('pipefail') and not background:
                job = next((job for job in jobs.jobs.values() if job.get('audit_id') == audit_id), None)
                if job:
                    outcomes = [job['processes'][pid]['status'] or 0 for pid in job['pids']]
                    status = next((value for value in reversed(outcomes) if value), 0)
                    update_audit(audit_id, exit_status=status, duration_ms=(time.monotonic()-started)*1000)
            if runtime.exec_requested and len(commands) == 1 and not background:
                # Windows has no Unix process overlay. Use the same gated,
                # Job Object-owned worker as ordinary external commands, wait
                # for its real status, then terminate this shell/worker. CRT
                # exec would orphan the replacement and report false success.
                runtime.state.traps.pop('EXIT', None)
                raise SystemExit(status)
        return 0 if status is None else int(status)
    except SystemExit as error:
        status = int(error.code or 0)
        raise
    except (OSError, ValueError, RuntimeError) as error:
        print('Argus: ' + safe_text(error), file=runtime.stderr)
        status = 1
        return status
    except BaseException as flow:
        status = int(getattr(flow, 'value', 130 if isinstance(flow, KeyboardInterrupt) else 1))
        raise
    finally:
        if not handed_to_job:
            update_audit(audit_id, exit_status=status, duration_ms=(time.monotonic()-started)*1000)


def _descriptor_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def _runtime(state=None):
    runtime = ShellRuntime(execute_pipeline, state=state)
    runtime.classify_command = lambda name: 'builtin' if is_builtin([name], runtime) else None
    def execute_external(argv, replace=False):
        status = execute_pipeline([Command(list(argv))], False, runtime)
        if replace:
            raise SystemExit(status)
        return status
    runtime.execute_external = execute_external
    return runtime


def execute_command(source, runtime=None):
    global _RUNTIME
    if runtime is None:
        if _RUNTIME is None:
            _RUNTIME = _runtime()
        runtime = _RUNTIME
    return runtime.run(source)


def _notify_children():
    for number in jobs.update_jobs():
        job = jobs.jobs.get(number)
        if job and job['background'] and not job.get('notified'):
            print(f'[{number}] Done {safe_text(job["command"])}')
            jobs.mark_job_notified(number)


class _PlainStream:
    def __init__(self, stream): self.stream = stream
    def write(self, text):
        import re
        return self.stream.write(re.sub(r'\x1b\[[0-9;:]*m', '', text))
    def __getattr__(self, name): return getattr(self.stream, name)


def _arguments(argv):
    parser = argparse.ArgumentParser(prog='argus', description='Programmable shell with policy analysis and optional protected execution')
    parser.add_argument('--version', action='version', version='Argus ' + __version__)
    parser.add_argument('-c', dest='command', metavar='SOURCE', help='execute shell source; remaining arguments supply $0 and positional parameters')
    parser.add_argument('--no-color', action='store_true', help='disable ANSI styling')
    parser.add_argument('--accessible', action='store_true', help='plain editing and accessible presentation')
    parser.add_argument('--locale', metavar='LOCALE', help='UI locale (en or es)')
    parser.add_argument('--private', action='store_true', help='do not persist session command history')
    parser.add_argument('--strict', action='store_true', help='require administrator-owned protected Linux broker; no fallback')
    parser.add_argument('--broker', metavar='SOCKET', help='protected broker socket')
    parser.add_argument('--config', metavar='FILE', help='validated user settings JSON')
    parser.add_argument('--norc', action='store_true', help='do not read startup scripts')
    parser.add_argument('--rcfile', action='append', default=[], metavar='FILE', help='additional startup script')
    parser.add_argument('script', nargs='?', help='script file, - for standard input, or $0 with -c')
    parser.add_argument('script_args', nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv=None):
    global _SESSION, _RUNTIME
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--internal-worker']:
        from .worker import main as worker_main
        return worker_main(argv[1:])
    arguments = _arguments(argv)
    try:
        config.prepare_paths()
        if arguments.config:
            config.SETTINGS_FILE = os.path.abspath(arguments.config)
        config.load_settings(arguments.config)
        settings = config.get_settings()
        for option, key in [('no_color','no_color'), ('accessible','accessibility'), ('private','history_private'), ('strict','strict')]:
            if getattr(arguments, option): settings[key] = True
        if arguments.locale: settings['locale'] = arguments.locale
        if arguments.broker: settings['broker_socket'] = arguments.broker
        load_policy_from_disk()
        if not initialize_database(): return 1
    except (OSError, ValueError) as error:
        print('Argus: refusing invalid or unsafe configuration: ' + safe_text(error), file=sys.stderr)
        return 1
    from .i18n import set_locale, translate
    try: set_locale(settings['locale'])
    except ValueError as error:
        print('Argus: ' + safe_text(error), file=sys.stderr)
        return 2
    original_stdout, original_stderr = sys.stdout, sys.stderr
    if settings['no_color'] or settings['accessibility'] or 'NO_COLOR' in os.environ or not sys.stdout.isatty():
        sys.stdout, sys.stderr = _PlainStream(sys.stdout), _PlainStream(sys.stderr)
    state = ShellState()
    if arguments.command is not None:
        state.argv0 = arguments.script or 'argus'
        state.positional = arguments.script_args
        source, filename = arguments.command, '<command>'
    elif arguments.script is not None:
        state.argv0, state.positional = arguments.script, arguments.script_args
        try:
            source = sys.stdin.read() if arguments.script == '-' else Path(arguments.script).read_text(encoding='utf-8')
        except OSError as error:
            print('Argus: ' + safe_text(error), file=sys.stderr)
            return 1
        filename = arguments.script
    elif not sys.stdin.isatty():
        source, filename = sys.stdin.read(), '<stdin>'
    else:
        source, filename = None, '<input>'
    if settings['strict']:
        if source is None:
            print('Argus: protected execution accepts -c or a script; isolated service jobs do not share interactive parent state.', file=sys.stderr)
            return 2
        try:
            from .broker import execute
            return execute(source, os.getcwd(), dict(os.environ), socket_path=settings['broker_socket'], public_key=Path(settings['broker_public_key'])).status
        except (OSError, RuntimeError, ValueError) as error:
            print('Argus: protected execution refused: ' + safe_text(error), file=sys.stderr)
            return 126
        finally:
            sys.stdout, sys.stderr = original_stdout, original_stderr
    runtime = _RUNTIME = _runtime(state)
    previous_signals = {}
    status = 0
    try:
        if source is None:
            if not jobs.initialize_terminal(): return 1
            from .interactive import InteractiveSession
            _SESSION = InteractiveSession(runtime, _notify_children, settings)
            _SESSION.completer.builtins.update(_ARGUS_BUILTINS.keys() | _SPECIAL)
            if hasattr(signal, 'SIGCHLD'):
                previous_signals[signal.SIGCHLD] = signal.signal(signal.SIGCHLD, lambda *_: _SESSION.wake())
            for name in ('SIGTSTP', 'SIGTTIN', 'SIGTTOU', 'SIGQUIT'):
                number = getattr(signal, name, None)
                if number is not None:
                    previous_signals[number] = signal.signal(number, signal.SIG_IGN)
            from .banner import show_banner
            show_banner(settings)
        builtins.configure_runtime(runtime, _SESSION)
        if not arguments.norc:
            startup = settings['startup_files'] + arguments.rcfile
            for path in startup:
                file = Path(os.path.expanduser(path))
                if file.exists(): runtime.run(file.read_text(encoding='utf-8'), filename=str(file))
                elif path in arguments.rcfile: raise FileNotFoundError(path)
        if source is not None:
            status = runtime.run(source, filename=filename)
        else:
            while True:
                try:
                    runtime.drain_traps()
                    line = _SESSION.read()
                    status = runtime.run(line)
                except KeyboardInterrupt:
                    print(translate('interrupted', settings['locale']))
                    runtime.state.last_status = status = 130
                except EOFError:
                    status = runtime.state.last_status
                    break
    except SystemExit as error:
        status = int(error.code or 0)
    except (OSError, ValueError, RuntimeError) as error:
        print(translate('error', settings['locale'], message=safe_text(error)), file=sys.stderr)
        status = 1
    finally:
        try:
            exit_body = runtime.state.traps.pop('EXIT', None)
            if exit_body:
                runtime.state.last_status = status
                try: runtime.run(exit_body, filename='<trap EXIT>')
                except SystemExit as error: status = int(error.code or 0)
            old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                jobs.shutdown_jobs()
                if _SESSION is not None: _SESSION.close()
                for stream in getattr(runtime, '_persistent_streams', {}).values():
                    stream.close()
            finally:
                signal.signal(signal.SIGINT, old_int)
                jobs.give_terminal_to_shell()
        finally:
            for number, handler in {**previous_signals, **_TRAP_HANDLERS}.items():
                signal.signal(number, handler)
            _TRAP_HANDLERS.clear()
            _SESSION = None
            sys.stdout, sys.stderr = original_stdout, original_stderr
    return status


if __name__ == '__main__':
    raise SystemExit(main())
