"""Owned process trees, precise per-stage status and terminal job control.

Reaping and trap callbacks only run at main-loop safe points. Disowned jobs
remain reapable/auditable but are excluded from notifications and shutdown.
"""

import errno
import os
import signal
import sys
import time

import psutil

try:
    import termios
except ImportError:  # Noninteractive imports remain usable on non-POSIX hosts.
    termios = None

from .colors import BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN, BRIGHT_BLACK, RESET
from .audit import update_audit
from .utils import get_current_directory, safe_text


IS_UNIX = hasattr(os, "getpgrp")
MAX_COMPLETED_JOBS = 64
jobs = {}
next_job_id = 1
shell_pid = os.getpid()
shell_pgid = os.getpgrp() if IS_UNIX else shell_pid
_terminal_initialized = False
_terminal_fd = None
_shell_termios = None
_terminal_owner = None
_TERMINAL_ERRORS = (OSError, ValueError, AttributeError)
if termios is not None:
    _TERMINAL_ERRORS += (termios.error,)


def _error(message):
    print(f"Argus: {safe_text(message)}", file=sys.stderr)


def _set_terminal_group(pgid):
    """Avoid SIGTTOU while reclaiming a terminal from a child group."""
    previous = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        os.tcsetpgrp(_terminal_fd, pgid)
    finally:
        signal.signal(signal.SIGTTOU, previous)


def initialize_terminal():
    """Join the foreground before creating the interactive shell's own group.

    A nested shell launched in the background suspends with SIGTTIN until its
    parent foregrounds it. Redirected input needs no terminal manipulation.
    False means setup failed, with an actionable diagnostic on stderr.
    """
    global shell_pid, shell_pgid, _terminal_initialized, _terminal_fd
    global _shell_termios, _terminal_owner
    if _terminal_initialized:
        return True
    if not IS_UNIX or termios is None:
        _terminal_initialized = True
        return True
    try:
        if not sys.stdin.isatty():
            _terminal_initialized = True
            return True
        fd = sys.stdin.fileno()
        if not os.isatty(fd):
            _terminal_initialized = True
            return True
        while os.tcgetpgrp(fd) != os.getpgrp():
            previous = signal.signal(signal.SIGTTIN, signal.SIG_DFL)
            try:
                os.killpg(os.getpgrp(), signal.SIGTTIN)
            finally:
                signal.signal(signal.SIGTTIN, previous)
        shell_pid = os.getpid()
        if os.getpgrp() != shell_pid:
            os.setpgid(shell_pid, shell_pid)
        shell_pgid = os.getpgrp()
        _terminal_fd = fd
        _set_terminal_group(shell_pgid)
        _shell_termios = termios.tcgetattr(fd)
        _terminal_owner = shell_pgid
        _terminal_initialized = True
        return True
    except _TERMINAL_ERRORS as exc:
        _terminal_fd = None
        _error(f"cannot initialize terminal job control: {exc}")
        return False


def give_terminal_to(pgid):
    """Hand off the terminal, returning False rather than hiding failures."""
    global _shell_termios, _terminal_owner
    if not initialize_terminal():
        return False
    if _terminal_fd is None:
        return True
    try:
        if _terminal_owner == shell_pgid:
            _shell_termios = termios.tcgetattr(_terminal_fd)
        _set_terminal_group(pgid)
        _terminal_owner = pgid
        for job in jobs.values():
            if job["pgid"] == pgid and job.get("terminal_modes") is not None:
                termios.tcsetattr(_terminal_fd, termios.TCSADRAIN, job["terminal_modes"])
                break
        return True
    except _TERMINAL_ERRORS as exc:
        _error(f"cannot give terminal to process group {pgid}: {exc}")
        return False


def give_terminal_to_shell():
    """Reclaim ownership and restore shell modes, preserving stopped modes."""
    global _terminal_owner
    if not _terminal_initialized:
        return initialize_terminal()
    if _terminal_fd is None:
        return True
    success = True
    if _terminal_owner != shell_pgid:
        try:
            for job in jobs.values():
                if job["pgid"] == _terminal_owner and job["status"] == "stopped":
                    job["terminal_modes"] = termios.tcgetattr(_terminal_fd)
                    break
        except _TERMINAL_ERRORS as exc:
            _error(f"cannot save stopped job terminal modes: {exc}")
            success = False
    try:
        _set_terminal_group(shell_pgid)
        _terminal_owner = shell_pgid
    except _TERMINAL_ERRORS as exc:
        _error(f"cannot return terminal to shell: {exc}")
        success = False
    try:
        if _shell_termios is not None:
            termios.tcsetattr(_terminal_fd, termios.TCSADRAIN, _shell_termios)
    except _TERMINAL_ERRORS as exc:
        _error(f"cannot restore shell terminal modes: {exc}")
        success = False
    return success


def _prune_completed():
    completed = [job_id for job_id, job in jobs.items() if job["status"] == "done"]
    completed.sort(key=lambda job_id: jobs[job_id].get("completed_at", 0))
    for job_id in completed[:-MAX_COMPLETED_JOBS]:
        del jobs[job_id]


def mark_job_notified(job_id):
    """Acknowledge notification while retaining bounded wait-able outcomes."""
    job = jobs.get(job_id)
    if job is not None and job["status"] == "done":
        job["notified"] = True


def _audit_state(job_id, job, state):
    if job["audit_id"] is None:
        return False
    kwargs = {"state": state, "pid": job["pgid"], "job_id": job_id}
    if state == "completed":
        kwargs["exit_status"] = job["last_status"]
        kwargs["duration_ms"] = (job["completed_at"] - job["start_time"]) * 1000
    return update_audit(job["audit_id"], **kwargs)


def create_job(pgid, pids, command, status="running", background=False,
               command_type="external", *, audit_id=None, cwd=None, start_time=None,
               handles=None, controller=None, signal_hook=None, pipefail=False):
    """Register children in pipeline order, keeping immutable launch metadata."""
    global next_job_id
    pids = list(pids)
    if not pids:
        raise ValueError("a job must contain at least one process")
    job_id = next_job_id
    next_job_id += 1
    jobs[job_id] = job = {
        "pgid": pgid,
        "pids": pids,
        "processes": {pid: {"state": status, "status": None, "stop_signal": None}
                      for pid in pids},
        "command": command,
        "status": status,
        "created": time.time(),
        "start_time": time.monotonic() if start_time is None else start_time,
        "background": background,
        "command_type": command_type,
        "command_name": command.split()[0] if command else "",
        "cwd": get_current_directory() if cwd is None else cwd,
        "last_status": 0,
        "audit_id": audit_id,
        "audited": False,
        "stop_requested": False,
        "handles": {handle.pid: handle for handle in (handles or [])},
        "controller": controller,
        "signal_hook": signal_hook,
        "disowned": False,
        "notified": False,
        "waited": False,
        "selection": max((item["selection"] for item in jobs.values()), default=0) + 1,
        "descendants": {},
        "pipefail": pipefail,
    }
    _audit_state(job_id, job, status)
    _prune_completed()
    return job_id


def _tree_processes(job):
    """Remember descendants before a launcher can exit or change its group."""
    found = dict(job.get("descendants", {}))
    for pid, process in job["processes"].items():
        if process["state"] == "exited":
            continue
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                found[child.pid] = child
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    job["descendants"] = found
    return found


def terminate_tree(pid):
    """Kill a partial launch including descendants, not only its initial group."""
    try:
        parent = psutil.Process(pid)
        descendants = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        descendants, parent = [], None
    for process in reversed(descendants):
        try:
            process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if parent is not None:
        try:
            parent.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def _process_status(pid):
    """Observe liveness without inventing an exit status or consuming waitpid."""
    try:
        return psutil.Process(pid).status()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _is_active_status(status):
    return status in (psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING,
                      psutil.STATUS_DISK_SLEEP, psutil.STATUS_IDLE,
                      psutil.STATUS_WAKING, psutil.STATUS_WAITING,
                      psutil.STATUS_LOCKED, psutil.STATUS_PARKED)


def _signal_job(job, signum):
    descendants = _tree_processes(job)
    delivered = False
    if not IS_UNIX:
        if signum == getattr(signal, "SIGKILL", 9) and job.get("controller") is not None:
            job["controller"].terminate()
            return
        operation = ("suspend" if signum == getattr(signal, "SIGSTOP", -1) else
                     "resume" if signum == getattr(signal, "SIGCONT", -2) else
                     "kill" if signum == getattr(signal, "SIGKILL", 9) else "terminate")
        for pid in job["pids"]:
            try:
                descendants[pid] = psutil.Process(pid)
            except psutil.NoSuchProcess:
                pass
        for process in descendants.values():
            try:
                getattr(process, operation)()
                delivered = True
            except psutil.NoSuchProcess:
                pass
        if not delivered:
            raise ProcessLookupError("job has no live processes")
        return
    # A partial launch must never signal the shell's own group. Also signal
    # tracked processes which escaped it; group membership is not ownership.
    group_signalled = False
    if job["pgid"] > 0 and job["pgid"] != os.getpgrp():
        try:
            os.killpg(job["pgid"], signum)
            group_signalled = True
            delivered = True
        except ProcessLookupError:
            pass
    for pid, process in job["processes"].items():
        if process["state"] == "exited":
            continue
        try:
            if not group_signalled or os.getpgid(pid) != job["pgid"]:
                os.kill(pid, signum)
                delivered = True
        except ProcessLookupError:
            pass
    for process in descendants.values():
        try:
            if not group_signalled or os.getpgid(process.pid) != job["pgid"]:
                process.send_signal(signum)
                delivered = True
        except (ProcessLookupError, psutil.NoSuchProcess):
            pass
    if not delivered:
        raise ProcessLookupError("job has no live processes")


def _refresh_job(job_id, job):
    old_state = job["status"]
    processes = list(job["processes"].values())
    if all(process["state"] == "exited" for process in processes):
        job["status"] = "done"
        job["last_status"] = job["processes"][job["pids"][-1]]["status"]
        if job.get("pipefail"):
            job["last_status"] = next((job["processes"][pid]["status"]
                                       for pid in reversed(job["pids"])
                                       if job["processes"][pid]["status"]), 0)
        if old_state != "done":
            job["completed_at"] = time.monotonic()
            job["audited"] = bool(_audit_state(job_id, job, "completed"))
    elif all(process["state"] in ("stopped", "exited") for process in processes):
        job["status"] = "stopped"
    else:
        job["status"] = "running"
    if job["status"] != old_state and job["status"] != "done":
        _audit_state(job_id, job, job["status"])
    return old_state != "done" and job["status"] == "done"


def _record_wait(job_id, job, pid, status):
    process = job["processes"].get(pid)
    if process is None or process["state"] == "exited":
        return
    if os.WIFEXITED(status):
        process.update(state="exited", status=os.WEXITSTATUS(status))
    elif os.WIFSIGNALED(status):
        process.update(state="exited", status=128 + os.WTERMSIG(status))
    elif hasattr(os, "WIFCONTINUED") and os.WIFCONTINUED(status):
        process.update(state="running", stop_signal=None)
        job["stop_requested"] = False
    elif os.WIFSTOPPED(status):
        # A stop report can predate an external SIGCONT. Check the current
        # process state before propagating a stale stop to the entire job.
        if _is_active_status(_process_status(pid)):
            process.update(state="running", stop_signal=None)
            job["stop_requested"] = False
            _refresh_job(job_id, job)
            return
        process.update(state="stopped", stop_signal=os.WSTOPSIG(status))
        # A pipeline is one job: stop siblings as well, and wait for their
        # actual stop/exit events before returning the terminal to the prompt.
        if not job["stop_requested"]:
            job["stop_requested"] = True
            try:
                _signal_job(job, signal.SIGSTOP)
            except ProcessLookupError:
                pass
            except OSError as exc:
                _error(f"cannot stop job %{job_id}: {exc}")
    _refresh_job(job_id, job)


def _lost_child(job_id, job, pid):
    # ECHILD is not proof of successful completion. Never fabricate success if
    # another consumer has taken a wait status or SIGCHLD was ignored.
    _error(f"job %{job_id}: child {pid} wait status is unavailable (status 127)")
    job["processes"][pid].update(state="exited", status=127)
    _refresh_job(job_id, job)


def update_jobs():
    """Reap without blocking or printing; safe for prompt idle callbacks."""
    finished_jobs = []
    flags = getattr(os, "WNOHANG", 0) | getattr(os, "WUNTRACED", 0) | getattr(os, "WCONTINUED", 0)
    for job_id, job in list(jobs.items()):
        if job["status"] == "done":
            continue
        _tree_processes(job)
        for pid, process in job["processes"].items():
            if not IS_UNIX:
                handle = job["handles"].get(pid)
                if handle is None:
                    _lost_child(job_id, job, pid)
                    continue
                if process["state"] == "exited":
                    continue
                status = handle.poll()
                if status is not None:
                    process.update(state="exited", status=status if status >= 0 else 128 - status)
                else:
                    try:
                        suspended = psutil.Process(pid).status() == psutil.STATUS_STOPPED
                        process["state"] = "stopped" if suspended else "running"
                    except psutil.NoSuchProcess:
                        pass
                _refresh_job(job_id, job)
                continue
            while process["state"] != "exited":
                handle = job["handles"].get(pid)
                if handle is not None and handle.returncode is not None:
                    status = handle.returncode
                    process.update(state="exited", status=status if status >= 0 else 128 - status)
                    _refresh_job(job_id, job)
                    break
                try:
                    waited_pid, status = os.waitpid(pid, flags)
                except InterruptedError:
                    continue
                except ChildProcessError:
                    _lost_child(job_id, job, pid)
                    break
                except OSError as exc:
                    if exc.errno == errno.ECHILD:
                        _lost_child(job_id, job, pid)
                    else:
                        _error(f"cannot reap job %{job_id}, child {pid}: {exc}")
                    break
                if waited_pid == 0:
                    break
                _record_wait(job_id, job, waited_pid, status)
                handle = job["handles"].get(pid)
                if handle is not None and process["state"] == "exited":
                    handle.returncode = os.waitstatus_to_exitcode(status)
            if process["state"] == "stopped" and _is_active_status(_process_status(pid)):
                # Some POSIX waitpid implementations do not report resumes.
                # Only an observed active state proves an external SIGCONT;
                # disappearance/zombie status still requires the real wait.
                process.update(state="running", stop_signal=None)
                job["stop_requested"] = False
                _refresh_job(job_id, job)
        if job["status"] == "done":
            if not job["disowned"]:
                finished_jobs.append(job_id)
            controller = job.get("controller")
            if controller is not None:
                # No KILL_ON_CLOSE: daemonized/disowned descendants are not
                # accidentally terminated by releasing a bookkeeping handle.
                controller.close()
                job["controller"] = None
    _prune_completed()
    return finished_jobs


def job_status_name(status):
    return {"running": "Running", "stopped": "Stopped", "done": "Done"}.get(status, status)


def job_status_color(status):
    return {"running": BRIGHT_GREEN, "stopped": BRIGHT_YELLOW,
            "done": BRIGHT_BLACK}.get(status, "\033[97m")


def wait_for_job(job_id):
    """Wait for tracked PIDs, never indefinitely on an escaped process group."""
    job = jobs.get(job_id)
    if job is None:
        return 1
    while job["status"] == "running":
        update_jobs()
        hook = job.get("signal_hook")
        if hook is not None:
            hook()
        if job["status"] == "running":
            time.sleep(0.01)
    if job["status"] == "stopped":
        print(f"\n{BRIGHT_YELLOW}[{job_id}] Stopped{RESET}")
        return 128 + next(process["stop_signal"] or getattr(signal, "SIGSTOP", 19)
                          for process in job["processes"].values()
                          if process["state"] == "stopped")
    _prune_completed()
    job["waited"] = True
    return job["last_status"]


def _continue_job(job_id, job):
    try:
        _signal_job(job, getattr(signal, "SIGCONT", -2))
    except OSError as exc:
        _error(f"cannot continue job %{job_id}: {exc}")
        return False
    for process in job["processes"].values():
        if process["state"] == "stopped":
            process.update(state="running", stop_signal=None)
    job["stop_requested"] = False
    _refresh_job(job_id, job)
    return True


def foreground_job(job_id=None):
    """Foreground without changing launch metadata or inserting audit rows."""
    job_id = select_job(job_id)
    job = jobs.get(job_id)
    if job is None:
        _error(f"no such job %{job_id}")
        return 1
    if job["status"] == "done":
        job["waited"] = True
        return job["last_status"]
    job["selection"] = max(item["selection"] for item in jobs.values()) + 1
    if not give_terminal_to(job["pgid"]):
        give_terminal_to_shell()
        return 1
    try:
        if job["status"] == "stopped" and not _continue_job(job_id, job):
            return 1
        return wait_for_job(job_id)
    finally:
        give_terminal_to_shell()


def background_job(job_id=None):
    """Continue a job, returning a meaningful shell status on every path."""
    job_id = select_job(job_id)
    job = jobs.get(job_id)
    if job is None:
        _error(f"no such job %{job_id}")
        return 1
    if job["status"] == "done":
        _error(f"job %{job_id} has finished")
        return 1
    job["selection"] = max(item["selection"] for item in jobs.values()) + 1
    if not _continue_job(job_id, job):
        return 1
    print(f"{BRIGHT_CYAN}[{job_id}]{RESET} continued in background")
    return 0


def shutdown_jobs(*, grace_period=0.5):
    """Bounded HUP/CONT then tree termination; disowned jobs are untouched."""
    try:
        owned = [(job_id, job) for job_id, job in list(jobs.items()) if not job["disowned"]]
        for _, job in owned:
            if job["status"] == "done":
                continue
            signals = ((signal.SIGHUP, signal.SIGCONT) if IS_UNIX else (signal.SIGTERM,))
            for signum in signals:
                try:
                    _signal_job(job, signum)
                except OSError as exc:
                    _error(f"cannot signal job during shutdown: {exc}")
        deadline = time.monotonic() + max(0, grace_period)
        while any(job["status"] != "done" for _, job in owned):
            update_jobs()
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        for job_id, job in owned:
            # Remembered descendants can outlive every direct pipeline stage.
            for process in _tree_processes(job).values():
                try:
                    process.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if job["status"] == "done":
                continue
            try:
                _signal_job(job, getattr(signal, "SIGKILL", 9))
            except OSError as exc:
                _error(f"cannot kill job %{job_id} during shutdown: {exc}")
            for pid, process in job["processes"].items():
                if process["state"] != "exited":
                    # Direct kill covers changed groups and stopped children.
                    try:
                        if IS_UNIX:
                            os.kill(pid, signal.SIGKILL)
                        else:
                            job["handles"][pid].kill()
                    except (ProcessLookupError, OSError):
                        pass
        # Nonblocking per-PID reaping has a hard deadline. Never call blocking
        # waitpid(-pgid) on children which may have escaped that process group.
        deadline = time.monotonic() + 2
        while any(job["status"] != "done" for _, job in owned):
            update_jobs()
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        _prune_completed()
    finally:
        give_terminal_to_shell()


def select_job(selector=None):
    """Resolve current/previous, numeric, prefix and substring job selectors."""
    eligible = [(job_id, job) for job_id, job in jobs.items() if not job["disowned"]]
    active = sorted(((job_id, job) for job_id, job in eligible if job["status"] != "done"),
                    key=lambda item: item[1]["selection"], reverse=True)
    if selector is None or selector in ("%", "%+", "%%"):
        return active[0][0] if active else None
    if selector == "%-":
        return active[1][0] if len(active) > 1 else None
    text = str(selector)
    if text.startswith("%"):
        text = text[1:]
    if text.isdecimal():
        number = int(text)
        if not str(selector).startswith("%"):
            if isinstance(selector, int) and any(job_id == number for job_id, _ in eligible):
                return number
            by_pid = sorted(((job_id, job) for job_id, job in eligible if number in job["pids"]),
                            key=lambda item: item[1]["selection"], reverse=True)
            if by_pid:
                return by_pid[0][0]
        return number if any(job_id == number for job_id, _ in eligible) else None
    matches = [job_id for job_id, job in eligible
               if (text[1:] in job["command"] if text.startswith("?") else job["command"].startswith(text))]
    if len(matches) > 1:
        _error(f"ambiguous job selector {selector}")
        return None
    return matches[0] if matches else None


def wait_job(selector=None):
    job_id = select_job(selector)
    if job_id is None:
        _error("no matching job")
        return 127
    status = wait_for_job(job_id)
    text = str(selector)
    if not text.startswith("%") and text.isdecimal():
        process = jobs[job_id]["processes"].get(int(text))
        if process is not None and process["state"] == "exited":
            return process["status"]
    return status


def disown_job(selector=None):
    job_id = select_job(selector)
    if job_id is None:
        _error("no matching job")
        return 1
    jobs[job_id]["disowned"] = True
    return 0


def parse_job_number(argument):
    return select_job(argument)
