"""
Main Argus shell loop and command execution engine.
"""

import os
import re
import signal
import sys
import time
from datetime import datetime

# readline is Unix/Linux/macOS only; optional on Windows
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

from .colors import (
    BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN,
    BRIGHT_BLACK, BRIGHT_PURPLE, BOLD, DIM, BRIGHT_WHITE, RESET
)
from .config import HISTORY_FILE, HISTORY_LIMIT
from .database import initialize_database, get_database_connection
from .security import (
    security_policy, evaluate_security, log_security_action,
    load_policy_from_disk
)
from .suspicious import (
    detect_suspicious, current_suspicious_hits, suspicious_session_id
)
from .risk import score_command, risk_color
from .execution import (
    tokenize_operators, expand_variables, parse_pipeline,
    parse_redirection, apply_redirection, setup_child_signals,
    strip_quotes_from_token, OPERATORS
)
from .jobs import (
    create_job, give_terminal_to, give_terminal_to_shell,
    wait_for_job, jobs, update_jobs, shell_pid, shell_pgid,
    parse_job_number, foreground_job, background_job
)
from .audit import audit_command
from .builtins import (
    builtin_cd, builtin_pwd, builtin_export, builtin_unset,
    builtin_env, builtin_history, builtin_redo, builtin_jobs,
    builtin_audit, builtin_audit_stats,
    builtin_risk, builtin_suspicious, builtin_suspicious_stats,
    builtin_suspicious_clear, builtin_security, builtin_allow,
    builtin_deny, builtin_allowlist, builtin_help
)
from .resource import apply_resource_limits, HAVE_RESOURCE
from .utils import get_current_directory


# Global state
last_command = ""


def is_builtin(command):
    """Check if a command is a builtin."""
    if not command:
        return False

    return command[0] in {
        "cd", "pwd", "export", "unset", "env",
        "history", "jobs", "fg", "bg",
        "audit", "audit-stats", "risk",
        "suspicious", "suspicious-stats", "suspicious-clear",
        "security", "allow", "deny", "allowlist",
        "redo",
        "help", "exit"
    }


def run_builtin(args):
    """Run a builtin command."""
    global last_command
    
    command = args[0]

    if command == "cd":
        builtin_cd(args)
        return 0

    if command == "pwd":
        builtin_pwd()
        return 0

    if command == "export":
        builtin_export(args)
        return 0

    if command == "unset":
        builtin_unset(args)
        return 0

    if command == "env":
        builtin_env()
        return 0

    if command == "history":
        builtin_history()
        return 0

    if command == "redo":
        return builtin_redo(args, last_command, execute_command)

    if command == "jobs":
        builtin_jobs()
        return 0

    if command == "fg":
        if len(args) < 2:
            print(f"{BRIGHT_RED}Argus: fg requires a job number{RESET}")
            return 1

        job_id = parse_job_number(args[1])
        if job_id is None:
            print(f"{BRIGHT_RED}Argus: invalid job number{RESET}")
            return 1

        return foreground_job(job_id)

    if command == "bg":
        if len(args) < 2:
            print(f"{BRIGHT_RED}Argus: bg requires a job number{RESET}")
            return 1

        job_id = parse_job_number(args[1])
        if job_id is None:
            print(f"{BRIGHT_RED}Argus: invalid job number{RESET}")
            return 1

        background_job(job_id)
        return 0

    if command == "audit":
        builtin_audit(args)
        return 0

    if command == "audit-stats":
        builtin_audit_stats()
        return 0

    if command == "risk":
        builtin_risk(args)
        return 0

    if command == "suspicious":
        builtin_suspicious(args)
        return 0

    if command == "suspicious-stats":
        builtin_suspicious_stats()
        return 0

    if command == "suspicious-clear":
        builtin_suspicious_clear(args)
        return 0

    if command == "security":
        builtin_security(args)
        return 0

    if command == "allow":
        builtin_allow(args)
        return 0

    if command == "deny":
        builtin_deny(args)
        return 0

    if command == "allowlist":
        builtin_allowlist()
        return 0

    if command == "help":
        builtin_help()
        return 0

    if command == "exit":
        sys.exit(0)

    return 0


def enforce_security_policy(
    original_command,
    risk_score,
    suspicious_hits,
    command_name
):
    """Enforce security policy and return True if command should execute."""
    from .security import security_policy
    from .suspicious import suspicious_session_id
    
    mode = security_policy.get("mode", "warn")

    decision, reason = evaluate_security(
        original_command,
        risk_score,
        suspicious_hits
    )

    if decision == "allow":
        return True

    if decision == "deny":
        color = BRIGHT_RED

        print(
            f"{color}{BOLD}"
            f"✗ BLOCKED [{mode}]: {reason}"
            f"{RESET}"
        )

        log_security_action(
            mode,
            "deny",
            reason,
            original_command,
            risk_score,
            suspicious_hits,
            suspicious_session_id
        )

        audit_command(
            original_command,
            command_name=command_name,
            pid=os.getpid(),
            background=False,
            exit_status=126,
            duration_ms=0,
            command_type="blocked",
            cwd=get_current_directory(),
            risk_score=risk_score,
            security_action="deny"
        )

        return False

    if decision == "confirm":

        color = BRIGHT_YELLOW

        print(
            f"{color}{BOLD}"
            f"⚠  CONFIRM REQUIRED: {reason}"
            f"{RESET}"
        )

        try:
            answer = input(
                f"{color}"
                f"   Run anyway? [y/N] "
                f"{RESET}"
            )
        except (EOFError, KeyboardInterrupt):
            answer = "n"
            print()

        if answer.strip().lower() != "y":

            log_security_action(
                mode,
                "confirm-denied",
                reason,
                original_command,
                risk_score,
                suspicious_hits,
                suspicious_session_id
            )

            audit_command(
                original_command,
                command_name=command_name,
                pid=os.getpid(),
                background=False,
                exit_status=126,
                duration_ms=0,
                command_type="confirm-denied",
                cwd=get_current_directory(),
                risk_score=risk_score,
                security_action="confirm-denied"
            )

            print(f"{BRIGHT_CYAN}Argus: cancelled.{RESET}")
            return False

        log_security_action(
            mode,
            "confirm-allowed",
            reason,
            original_command,
            risk_score,
            suspicious_hits,
            suspicious_session_id
        )

    return True


def execute_single_command(
    args,
    background=False,
    original_command=""
):
    """Execute a single (non-pipeline) command."""
    parsed = parse_redirection(args)

    if parsed is None:
        return 1

    (
        cleaned_args,
        input_file,
        output_file,
        append_output
    ) = parsed

    if not cleaned_args:
        return 0

    if is_builtin(cleaned_args):
        if background:
            print(
                f"{BRIGHT_YELLOW}"
                "Argus: built-in commands cannot run in the background yet."
                f"{RESET}"
            )

            audit_command(
                original_command,
                command_name=cleaned_args[0],
                pid=os.getpid(),
                background=True,
                exit_status=1,
                duration_ms=0,
                command_type="builtin",
                cwd=get_current_directory()
            )
            return 1

        start_time = time.time()
        exit_status = run_builtin(cleaned_args)
        duration_ms = (time.time() - start_time) * 1000

        audit_command(
            original_command,
            command_name=cleaned_args[0],
            pid=os.getpid(),
            background=False,
            exit_status=exit_status,
            duration_ms=duration_ms,
            command_type="builtin",
            cwd=get_current_directory()
        )

        return exit_status

    start_time = time.time()

    pid = os.fork()

    if pid == 0:
        try:
            setup_child_signals()
            os.setpgid(0, 0)
            apply_resource_limits(security_policy)
            apply_redirection(input_file, output_file, append_output)
            os.execvp(cleaned_args[0], cleaned_args)

        except FileNotFoundError:
            print(
                f"{BRIGHT_RED}"
                f"Argus: command not found: {cleaned_args[0]}"
                f"{RESET}"
            )
        except PermissionError:
            print(
                f"{BRIGHT_RED}"
                f"Argus: permission denied: {cleaned_args[0]}"
                f"{RESET}"
            )
        except Exception as error:
            print(f"{BRIGHT_RED}Argus: {error}{RESET}")

        os._exit(127)

    else:
        try:
            os.setpgid(pid, pid)
        except OSError:
            pass

        pgid = pid
        command_text = original_command if original_command else " ".join(args)

        job_id = create_job(
            pgid,
            [pid],
            command_text,
            "running",
            background=background,
            command_type="external"
        )

        if background:
            print(f"{BRIGHT_CYAN}[{job_id}]{RESET} {pid}")
            return 0

        give_terminal_to(pgid)

        try:
            exit_status = wait_for_job(job_id)
        finally:
            give_terminal_to_shell()

        duration_ms = (time.time() - start_time) * 1000

        audit_command(
            command_text,
            command_name=cleaned_args[0],
            pid=pid,
            background=False,
            exit_status=exit_status,
            duration_ms=duration_ms,
            command_type="external",
            job_id=job_id,
            cwd=get_current_directory()
        )

        jobs[job_id]["audited"] = True
        return exit_status


def execute_pipeline(
    commands,
    background=False,
    original_command=""
):
    """Execute a pipeline of commands."""
    if len(commands) == 1:
        return execute_single_command(
            commands[0],
            background,
            original_command
        )

    for command in commands:
        if any(op in command for op in ("<", ">", ">>")):
            print(
                f"{BRIGHT_YELLOW}"
                "Argus: redirection inside pipelines is not supported yet."
                f"{RESET}"
            )
            audit_command(
                original_command,
                command_name=commands[0][0] if commands[0] else "",
                pid=os.getpid(),
                background=background,
                exit_status=1,
                duration_ms=0,
                command_type="pipeline-error",
                cwd=get_current_directory()
            )
            return 1

    for command in commands:
        if is_builtin(command):
            print(
                f"{BRIGHT_YELLOW}"
                "Argus: built-in commands inside pipelines "
                "are not supported yet."
                f"{RESET}"
            )
            audit_command(
                original_command,
                command_name=commands[0][0] if commands[0] else "",
                pid=os.getpid(),
                background=background,
                exit_status=1,
                duration_ms=0,
                command_type="pipeline-error",
                cwd=get_current_directory()
            )
            return 1

    start_time = time.time()

    pipe_fds = []
    for _ in range(len(commands) - 1):
        pipe_fds.append(os.pipe())

    pids = []
    pgid = None

    for index, command in enumerate(commands):
        pid = os.fork()

        if pid == 0:
            try:
                setup_child_signals()

                if pgid is None:
                    os.setpgid(0, 0)
                else:
                    os.setpgid(0, pgid)

                apply_resource_limits(security_policy)

                if index > 0:
                    read_fd = pipe_fds[index - 1][0]
                    os.dup2(read_fd, sys.stdin.fileno())

                if index < len(commands) - 1:
                    write_fd = pipe_fds[index][1]
                    os.dup2(write_fd, sys.stdout.fileno())

                for read_fd, write_fd in pipe_fds:
                    try:
                        os.close(read_fd)
                    except OSError:
                        pass
                    try:
                        os.close(write_fd)
                    except OSError:
                        pass

                os.execvp(command[0], command)

            except FileNotFoundError:
                print(
                    f"{BRIGHT_RED}"
                    f"Argus: command not found: {command[0]}"
                    f"{RESET}"
                )
            except PermissionError:
                print(
                    f"{BRIGHT_RED}"
                    f"Argus: permission denied: {command[0]}"
                    f"{RESET}"
                )
            except Exception as error:
                print(f"{BRIGHT_RED}Argus: {error}{RESET}")

            os._exit(127)

        else:
            if pgid is None:
                pgid = pid

            try:
                os.setpgid(pid, pgid)
            except OSError:
                pass

            pids.append(pid)

    for read_fd, write_fd in pipe_fds:
        try:
            os.close(read_fd)
        except OSError:
            pass
        try:
            os.close(write_fd)
        except OSError:
            pass

    command_text = (
        original_command
        if original_command
        else " | ".join(" ".join(c) for c in commands)
    )

    job_id = create_job(
        pgid,
        pids,
        command_text,
        "running",
        background=background,
        command_type="pipeline"
    )

    if background:
        print(f"{BRIGHT_CYAN}[{job_id}]{RESET} {pgid}")
        return 0

    give_terminal_to(pgid)

    try:
        exit_status = wait_for_job(job_id)
    finally:
        give_terminal_to_shell()

    duration_ms = (time.time() - start_time) * 1000

    audit_command(
        command_text,
        command_name=commands[0][0] if commands else "",
        pid=pgid,
        background=False,
        exit_status=exit_status,
        duration_ms=duration_ms,
        command_type="pipeline",
        job_id=job_id,
        cwd=get_current_directory()
    )

    jobs[job_id]["audited"] = True
    return exit_status


def execute_command(command_line):
    """Parse and execute a command line."""
    global current_suspicious_hits
    global last_command

    original_command = command_line.strip()

    if not original_command:
        return

    first_word_preview = original_command.split(None, 1)[0]
    if first_word_preview != "redo":
        last_command = original_command

    current_suspicious_hits = []

    detect_suspicious(original_command)

    preview_score, preview_reasons = score_command(original_command)

    preview_name = ""
    stripped = original_command
    if stripped:
        preview_name = stripped.split(None, 1)[0]

    SECURITY_BUILTINS_EXEMPT = {
        "security", "allow", "deny", "allowlist",
        "suspicious", "suspicious-stats", "suspicious-clear",
        "audit", "audit-stats", "risk",
        "help", "exit",
    }

    if preview_name not in SECURITY_BUILTINS_EXEMPT:
        if not enforce_security_policy(
            original_command,
            preview_score,
            list(current_suspicious_hits),
            preview_name
        ):
            return

    if preview_score >= 70:
        color = risk_color(preview_score)
        print(
            f"{color}{BOLD}"
            f"⚠  Argus: high-risk command (score {preview_score})"
            f"{RESET}"
        )
        for reason in preview_reasons:
            print(f"{BRIGHT_BLACK}   ↳ {reason}{RESET}")

    command_line = expand_variables(command_line)

    tokens = tokenize_operators(command_line)

    if not tokens:
        return

    args = []
    try:
        for token in tokens:
            if token in OPERATORS:
                args.append(token)
            else:
                args.extend(strip_quotes_from_token(token))
    except ValueError as error:
        print(f"{BRIGHT_RED}Argus: {error}{RESET}")
        audit_command(
            original_command,
            command_name="parse-error",
            pid=os.getpid(),
            background=False,
            exit_status=2,
            duration_ms=0,
            command_type="parse-error",
            cwd=get_current_directory()
        )
        return

    if not args:
        return

    if "&&" in args or "||" in args:
        print(
            f"{BRIGHT_YELLOW}"
            "Argus: && and || are not supported yet."
            f"{RESET}"
        )
        audit_command(
            original_command,
            command_name="unsupported-operator",
            pid=os.getpid(),
            background=False,
            exit_status=2,
            duration_ms=0,
            command_type="unsupported-operator",
            cwd=get_current_directory()
        )
        return

    background = False
    if args and args[-1] == "&":
        background = True
        args = args[:-1]

    if not args:
        return

    if (
        len(args) == 1
        and "=" in args[0]
        and not args[0].startswith("=")
    ):
        name, value = args[0].split("=", 1)

        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            os.environ[name] = value

            audit_command(
                original_command,
                command_name="assignment",
                pid=os.getpid(),
                background=False,
                exit_status=0,
                duration_ms=0,
                command_type="environment-assignment",
                cwd=get_current_directory()
            )
            return

    commands = parse_pipeline(args)

    if not commands:
        return

    if len(commands) == 1 and is_builtin(commands[0]):
        if background:
            print(
                f"{BRIGHT_YELLOW}"
                "Argus: built-in commands cannot run in the background yet."
                f"{RESET}"
            )
            audit_command(
                original_command,
                command_name=commands[0][0],
                pid=os.getpid(),
                background=True,
                exit_status=1,
                duration_ms=0,
                command_type="builtin-background-error",
                cwd=get_current_directory()
            )
            return

        execute_pipeline(commands, False, original_command)
        return

    execute_pipeline(commands, background, original_command)


def setup_shell_signals():
    """Set up signal handlers for the shell."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)


def initialize_shell_process_group():
    """Initialize the shell's process group."""
    from .jobs import shell_pid, shell_pgid
    
    try:
        os.environ["PWD"] = os.getcwd()
    except OSError:
        pass


def load_history():
    """Load command history from file."""
    if not HAS_READLINE:
        return
    
    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass

    readline.set_history_length(HISTORY_LIMIT)


def save_history():
    """Save command history to file."""
    if not HAS_READLINE:
        return
    
    try:
        readline.set_history_length(HISTORY_LIMIT)
        readline.write_history_file(HISTORY_FILE)
    except Exception:
        pass


def setup_readline_bindings():
    """Set up readline key bindings."""
    if not HAS_READLINE:
        return
    
    try:
        readline.parse_and_bind(r'"\C-r": reverse-search-history')
        readline.parse_and_bind(r'"\C-s": forward-search-history')
        readline.parse_and_bind(r'"\C-l": clear-screen')
        readline.parse_and_bind(r'"\e.": yank-last-arg')
        readline.parse_and_bind(r'"\e\e[C": forward-word')
        readline.parse_and_bind(r'"\e\e[D": backward-word')
        readline.parse_and_bind("set bell-style none")
        readline.parse_and_bind("set completion-ignore-case on")
    except Exception:
        pass


def print_banner():
    """Print the Argus welcome banner."""
    glyph_lines = [
        " █████╗ ██████╗   ██████╗ ██╗   ██╗███████╗",
        "██╔══██╗██╔══██╗ ██╔════╝ ██║   ██║██╔════╝",
        "███████║██████╔╝ ██║  ████╗██║   ██║███████║",
        "███████║██████╔╝ ██║  ████║██║   ██║███████║",
        "██╔══██║██╔══██╗ ██║   ██║██║   ██║╚════██║",
        "██║  ██║██║  ██║ ╚██████╔╝╚██████╔╝███████║",
        "╚═╝  ╚═╝╚═╝  ╚═╝  ╚═════╝  ╚═════╝ ╚══════╝",
    ]

    gradient = [
        BRIGHT_PURPLE,
        BRIGHT_PURPLE,
        BRIGHT_CYAN,
        BRIGHT_CYAN,
        BRIGHT_CYAN,
        BRIGHT_PURPLE,
        BRIGHT_PURPLE,
    ]

    tagline = "Security-Aware Shell"

    width = max(
        max(len(line) for line in glyph_lines),
        len(tagline)
    ) + 4

    top_border = "╭" + "─" * width + "╮"
    bottom_border = "╰" + "─" * width + "╯"

    print()
    print(f"{BRIGHT_BLACK}{top_border}{RESET}")

    for line, color in zip(glyph_lines, gradient):
        padding = " " * (width - len(line))
        print(
            f"{BRIGHT_BLACK}│ {RESET}"
            f"{color}{BOLD}{line}{RESET}"
            f"{padding[:-2]}"
            f"{BRIGHT_BLACK} │{RESET}"
        )

    print(f"{BRIGHT_BLACK}├{'─' * width}┤{RESET}")

    tagline_padding = " " * max(0, width - len(tagline) - 1)
    print(
        f"{BRIGHT_BLACK}│ {RESET}"
        f"{DIM}{BRIGHT_WHITE}{tagline}{RESET}"
        f"{tagline_padding}"
        f"{BRIGHT_BLACK}│{RESET}"
    )

    print(f"{BRIGHT_BLACK}{bottom_border}{RESET}")
    print()
    print(
        f"{BRIGHT_BLACK}  type "
        f"{RESET}{BRIGHT_CYAN}help{RESET}"
        f"{BRIGHT_BLACK} for commands, "
        f"{RESET}{BRIGHT_CYAN}security{RESET}"
        f"{BRIGHT_BLACK} for the current policy{RESET}"
    )
    print()


def print_exit_banner():
    """Print the Argus exit message."""
    print()
    print(
        f"{BRIGHT_PURPLE}{BOLD}"
        "  ────────────────────────────────────────"
        f"{RESET}"
    )
    print(
        f"{BRIGHT_CYAN}{BOLD}"
        "   Thanks for using Argus."
        f"{RESET}"
    )
    print(
        f"{BRIGHT_BLACK}"
        f"   Session: {suspicious_session_id}"
        f"{RESET}"
    )
    print(
        f"{BRIGHT_PURPLE}{BOLD}"
        "  ────────────────────────────────────────"
        f"{RESET}"
    )
    print()


def get_display_directory():
    """Get the directory for the prompt display."""
    current_directory = get_current_directory()
    home_directory = os.path.expanduser("~")

    if current_directory == home_directory:
        return "~"

    if current_directory.startswith(home_directory + os.sep):
        return "~" + current_directory[len(home_directory):]

    return current_directory


def get_prompt():
    """Get the shell prompt string."""
    directory = get_display_directory()

    mode = security_policy.get("mode", "warn")

    if mode in ("off", "warn"):
        mode_tag = ""
    else:
        mode_color = BRIGHT_RED if mode in ("block", "allowlist") else BRIGHT_YELLOW
        mode_tag = (
            f"{mode_color}"
            f"[{mode}]"
            f"{RESET}"
            " "
        )

    return (
        f"{mode_tag}"
        f"{BRIGHT_CYAN}{BOLD}"
        "Argus"
        f"{RESET}"
        f"{BRIGHT_CYAN}"
        " ["
        f"{BRIGHT_WHITE}{directory}"
        f"{BRIGHT_CYAN}"
        "]"
        f"{RESET}"
        " "
        f"{BRIGHT_PURPLE}{BOLD}"
        ">"
        f"{RESET}"
        " "
    )


def main():
    """Main shell loop."""
    initialize_shell_process_group()
    setup_shell_signals()
    load_history()
    setup_readline_bindings()
    initialize_database()

    load_policy_from_disk()

    print_banner()

    try:
        while True:
            finished_jobs = update_jobs()

            for job_id in finished_jobs:
                job = jobs.get(job_id)
                if job:
                    print(
                        f"\n{BRIGHT_GREEN}[{job_id}] Done{RESET} "
                        f"{job['command']}"
                    )

            try:
                os.environ["PWD"] = os.getcwd()
            except OSError:
                pass

            try:
                command = input(get_prompt())
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                print(f"{BRIGHT_CYAN}Exiting Argus...{RESET}")
                break

            if not command.strip():
                continue

            try:
                execute_command(command)
            except KeyboardInterrupt:
                print()
            except EOFError:
                print()
            except Exception as error:
                print(f"{BRIGHT_RED}Argus: {error}{RESET}")
                audit_command(
                    command,
                    command_name="internal-error",
                    pid=os.getpid(),
                    background=False,
                    exit_status=1,
                    duration_ms=0,
                    command_type="internal-error",
                    cwd=get_current_directory()
                )

    finally:
        save_history()
        give_terminal_to_shell()
        print_exit_banner()


if __name__ == "__main__":
    main()
