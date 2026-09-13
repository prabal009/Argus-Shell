"""
Job management for foreground and background processes.
"""

import os
import signal
import sys
import time
from .colors import BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN, BRIGHT_BLACK, RESET
from .audit import audit_command
from .utils import get_current_directory


# Platform detection: these functions only exist on Unix/Linux/macOS
IS_UNIX = hasattr(os, 'getpgrp')

# Global job state
jobs = {}
next_job_id = 1
shell_pid = os.getpid()
shell_pgid = os.getpgrp() if IS_UNIX else os.getpid()


def create_job(
    pgid,
    pids,
    command,
    status="running",
    background=False,
    command_type="external"
):
    """Create a new job entry."""
    global next_job_id

    job_id = next_job_id
    next_job_id += 1

    jobs[job_id] = {
        "pgid": pgid,
        "pids": pids,
        "command": command,
        "status": status,
        "created": time.time(),
        "start_time": time.time(),
        "background": background,
        "command_type": command_type,
        "command_name": command.split()[0] if command else "",
        "cwd": get_current_directory(),
        "last_status": 0,
        "audited": False
    }

    return job_id


def give_terminal_to(pgid):
    """Give terminal control to a process group (Unix only)."""
    if not IS_UNIX:
        return
    
    try:
        terminal_fd = sys.stdin.fileno()
        os.tcsetpgrp(terminal_fd, pgid)
    except Exception:
        pass


def give_terminal_to_shell():
    """Give terminal control back to the shell (Unix only)."""
    global shell_pgid
    if not IS_UNIX:
        return
    
    try:
        terminal_fd = sys.stdin.fileno()
        os.tcsetpgrp(terminal_fd, shell_pgid)
    except Exception:
        pass


def update_jobs():
    """Update the status of all jobs and return list of finished job IDs."""
    finished_jobs = []

    for job_id, job in list(jobs.items()):
        if job["status"] == "done":
            continue

        all_done = True
        stopped = False

        for pid in job["pids"]:
            try:
                if IS_UNIX:
                    result = os.waitpid(
                        pid,
                        os.WNOHANG | os.WUNTRACED | os.WCONTINUED
                    )

                    if result == (0, 0):
                        all_done = False
                        continue

                    waited_pid, status = result

                    if waited_pid == 0:
                        all_done = False
                        continue

                    if os.WIFSTOPPED(status):
                        stopped = True
                        all_done = False
                    elif os.WIFCONTINUED(status):
                        job["status"] = "running"
                        all_done = False
                    elif os.WIFEXITED(status):
                        job["last_status"] = os.WEXITSTATUS(status)
                    elif os.WIFSIGNALED(status):
                        job["last_status"] = 128 + os.WTERMSIG(status)
                    else:
                        all_done = False
                else:
                    # Windows: try non-blocking wait
                    try:
                        waited_pid, status = os.waitpid(pid, os.WNOHANG if hasattr(os, 'WNOHANG') else 0)
                        if waited_pid == 0:
                            all_done = False
                        else:
                            job["last_status"] = status
                    except OSError:
                        all_done = False

            except ChildProcessError:
                continue
            except OSError:
                continue

        if stopped:
            job["status"] = "stopped"
        elif all_done:
            job["status"] = "done"
            finished_jobs.append(job_id)

            if not job.get("audited", False):
                end_time = time.time()
                start_time = job.get("start_time", end_time)
                duration_ms = (end_time - start_time) * 1000

                audit_command(
                    job["command"],
                    command_name=job.get("command_name", ""),
                    pid=job["pgid"],
                    background=True,
                    exit_status=job.get("last_status", 0),
                    duration_ms=duration_ms,
                    command_type=job.get("command_type", "external"),
                    job_id=job_id,
                    cwd=job.get("cwd", get_current_directory())
                )

                job["audited"] = True

    return finished_jobs


def job_status_name(status):
    """Get the display name for a job status."""
    if status == "running":
        return "Running"
    if status == "stopped":
        return "Stopped"
    if status == "done":
        return "Done"
    return status


def job_status_color(status):
    """Get the ANSI color for a job status."""
    if status == "running":
        return BRIGHT_GREEN
    if status == "stopped":
        return BRIGHT_YELLOW
    if status == "done":
        return BRIGHT_BLACK
    return "\033[97m"  # BRIGHT_WHITE


def wait_for_job(job_id):
    """Wait for a foreground job to complete."""
    if job_id not in jobs:
        return 0

    job = jobs[job_id]
    pgid = job["pgid"]

    final_status = 0
    stopped = False

    remaining_pids = set(job["pids"])

    while remaining_pids:
        try:
            # On Unix, use negative pgid for process group; on Windows, use single pid
            if IS_UNIX:
                pid, status = os.waitpid(-pgid, os.WUNTRACED)
            else:
                # Windows: waitpid works on individual processes only
                pid_to_wait = remaining_pids.pop()
                remaining_pids.add(pid_to_wait)
                pid, status = os.waitpid(pid_to_wait, 0)
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        except OSError:
            break

        if pid == 0:
            continue

        # Unix-only status macros
        if IS_UNIX:
            if os.WIFSTOPPED(status):
                stopped = True
                job["status"] = "stopped"
                print(f"\n{BRIGHT_YELLOW}[{job_id}] Stopped{RESET}")
                break

            if os.WIFEXITED(status):
                final_status = os.WEXITSTATUS(status)
            elif os.WIFSIGNALED(status):
                signal_number = os.WTERMSIG(status)
                final_status = 128 + signal_number

                if signal_number != signal.SIGINT:
                    print(
                        f"\n{BRIGHT_RED}"
                        f"Argus: process terminated by signal {signal_number}"
                        f"{RESET}"
                    )
        else:
            # Windows: status is the exit code directly
            final_status = status

        remaining_pids.discard(pid)

    if stopped:
        job["status"] = "stopped"
    else:
        job["status"] = "done"

    job["last_status"] = final_status
    return final_status


def foreground_job(job_id):
    """Bring a job to the foreground."""
    if job_id not in jobs:
        print(f"{BRIGHT_RED}Argus: no such job %{job_id}{RESET}")
        return 1

    job = jobs[job_id]

    if job["status"] == "done":
        print(f"{BRIGHT_YELLOW}Argus: job %{job_id} has finished{RESET}")
        return 0

    if job["status"] == "stopped":
        try:
            if IS_UNIX:
                os.killpg(job["pgid"], signal.SIGCONT)
            else:
                # Windows: send signal to individual process
                for pid in job["pids"]:
                    try:
                        os.kill(pid, signal.SIGCONT)
                    except (OSError, ProcessLookupError):
                        pass
        except ProcessLookupError:
            print(f"{BRIGHT_RED}Argus: process no longer exists{RESET}")
            return 1

    job["status"] = "running"

    give_terminal_to(job["pgid"])

    start_time = time.time()

    try:
        exit_status = wait_for_job(job_id)
    finally:
        give_terminal_to_shell()

    duration_ms = (time.time() - start_time) * 1000

    if job["status"] == "done":
        audit_command(
            job["command"],
            command_name=job.get("command_name", ""),
            pid=job["pgid"],
            background=False,
            exit_status=exit_status,
            duration_ms=duration_ms,
            command_type=job.get("command_type", "external"),
            job_id=job_id,
            cwd=job.get("cwd", get_current_directory())
        )
        job["audited"] = True

    return exit_status


def background_job(job_id):
    """Continue a stopped job in the background."""
    if job_id not in jobs:
        print(f"{BRIGHT_RED}Argus: no such job %{job_id}{RESET}")
        return

    job = jobs[job_id]

    if job["status"] == "done":
        print(f"{BRIGHT_YELLOW}Argus: job %{job_id} has finished{RESET}")
        return

    try:
        if IS_UNIX:
            os.killpg(job["pgid"], signal.SIGCONT)
        else:
            # Windows: send signal to individual processes
            for pid in job["pids"]:
                try:
                    os.kill(pid, signal.SIGCONT)
                except (OSError, ProcessLookupError):
                    pass
        
        job["status"] = "running"
        print(
            f"{BRIGHT_CYAN}[{job_id}]{RESET} continued in background"
        )
    except ProcessLookupError:
        print(f"{BRIGHT_RED}Argus: process no longer exists{RESET}")


def parse_job_number(argument):
    """Parse a job number from command arguments."""
    if argument.startswith("%"):
        argument = argument[1:]

    try:
        return int(argument)
    except ValueError:
        return None
