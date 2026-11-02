"""Behavioral regressions for child state, audit lifecycle, and terminal control."""

from collections import deque
from contextlib import ExitStack, closing, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from argus import audit, database
from argus import jobs as job_control


def exited(code):
    return code << 8


def stopped(signum=getattr(signal, "SIGTSTP", 19)):
    return (signum << 8) | 0x7f


def continued():
    """Use the host's wait encoding (Darwin does not use Linux's 0xffff)."""
    for status in (0xffff, stopped(signal.SIGCONT)):
        if os.WIFCONTINUED(status):
            return status
    raise AssertionError("no continued wait status for this POSIX host")


class JobStateFixture(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(job_control.jobs, {}, clear=True))
        self.stack.enter_context(patch.object(job_control, "next_job_id", 1))
        self.stack.enter_context(patch.object(job_control, "shell_pid", job_control.shell_pid))
        self.stack.enter_context(patch.object(job_control, "shell_pgid", job_control.shell_pgid))
        self.stack.enter_context(patch.object(job_control, "_terminal_initialized", True))
        self.stack.enter_context(patch.object(job_control, "_terminal_fd", None))
        self.stack.enter_context(patch.object(job_control, "_shell_termios", None))
        self.stack.enter_context(patch.object(job_control, "_terminal_owner", None))
        self.stack.enter_context(patch.object(job_control, "get_current_directory", return_value="/launch"))
        self.stack.enter_context(patch.object(job_control.psutil, "Process",
                                             side_effect=job_control.psutil.NoSuchProcess(-1)))
        self.stack.enter_context(patch.object(job_control.os, "getpgid", side_effect=lambda pid: next(
            (job["pgid"] for job in job_control.jobs.values() if pid in job["pids"]),
            job_control.shell_pgid)))
        self.killpg = self.stack.enter_context(patch.object(job_control.os, "killpg"))
        self.kill = self.stack.enter_context(patch.object(job_control.os, "kill"))

    def pending(self, events):
        """Each PID has independent queued wait events, then remains running."""
        pending = {pid: deque(values) for pid, values in events.items()}

        def waitpid(pid, flags):
            self.assertGreater(pid, 0)
            values = pending.get(pid)
            if values:
                return pid, values.popleft()
            return 0, 0

        return patch.object(job_control.os, "waitpid", side_effect=waitpid)


@unittest.skipUnless(job_control.IS_UNIX, "POSIX wait statuses")
class JobsTests(JobStateFixture):
    def setUp(self):
        super().setUp()
        self.audit = self.stack.enter_context(patch.object(job_control, "update_audit", return_value=True))

    def test_foreground_status_follows_last_stage_in_both_wait_orders(self):
        cases = [([(2101, exited(7)), (2102, exited(0))], 0),
                 ([(2102, exited(9)), (2101, exited(0))], 9)]
        for events, expected in cases:
            with self.subTest(events=events):
                job_id = job_control.create_job(2101, [2101, 2102], "upstream | last", audit_id=12)
                with patch.object(job_control.os, "waitpid", side_effect=events):
                    result = job_control.wait_for_job(job_id)
                self.assertEqual(result, expected)
                job = job_control.jobs[job_id]
                self.assertEqual(job["status"], "done")
                self.assertEqual(job["processes"][2102]["status"], expected)
                self.assertEqual(job["last_status"], expected)
                job_control.mark_job_notified(job_id)

    def test_background_retains_reaped_stages_across_updates(self):
        for first, last in [(7, 0), (0, 9)]:
            with self.subTest(first=first, last=last):
                job_id = job_control.create_job(2201, [2201, 2202], "first | last", background=True)
                with self.pending({2202: [exited(last)]}):
                    self.assertEqual(job_control.update_jobs(), [])
                self.assertEqual(job_control.jobs[job_id]["processes"][2202]["state"], "exited")
                with self.pending({2201: [exited(first)]}):
                    self.assertEqual(job_control.update_jobs(), [job_id])
                self.assertEqual(job_control.jobs[job_id]["last_status"], last)
                with patch.object(job_control.os, "waitpid") as wait:
                    self.assertEqual(job_control.update_jobs(), [])
                    wait.assert_not_called()
                job_control.mark_job_notified(job_id)

    def test_signal_status_uses_final_stage(self):
        job_id = job_control.create_job(2301, [2301, 2302], "a | b")
        with patch.object(job_control.os, "waitpid", side_effect=[(2302, signal.SIGTERM), (2301, exited(0))]):
            self.assertEqual(job_control.wait_for_job(job_id), 128 + signal.SIGTERM)

    def test_pipeline_stop_waits_for_siblings_without_finalizing(self):
        job_id = job_control.create_job(2401, [2401, 2402], "a | b", audit_id=44)
        with self.pending({2401: [stopped()], 2402: [stopped(signal.SIGSTOP)]}):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(job_control.wait_for_job(job_id), 128 + signal.SIGTSTP)
        job = job_control.jobs[job_id]
        self.assertEqual(job["status"], "stopped")
        self.assertFalse(job["audited"])
        self.assertIsNone(job["processes"][2402]["status"])
        self.killpg.assert_called_once_with(2401, signal.SIGSTOP)
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list], ["running", "stopped"])
        for call in self.audit.call_args_list:
            self.assertNotIn("exit_status", call.kwargs)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(job_control.background_job(job_id), 0)
        with self.pending({2401: [continued(), exited(2)], 2402: [continued(), exited(11)]}):
            self.assertEqual(job_control.update_jobs(), [job_id])
        self.assertEqual(job["last_status"], 11)
        self.assertTrue(job["audited"])
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list],
                         ["running", "stopped", "running", "completed"])

    def test_external_continue_changes_stopped_state(self):
        job_id = job_control.create_job(2501, [2501], "sleep", status="stopped", audit_id=55)
        with self.pending({2501: [continued()]}):
            job_control.update_jobs()
        self.assertEqual(job_control.jobs[job_id]["status"], "running")
        self.assertEqual(self.audit.call_args.kwargs["state"], "running")

    def test_external_continue_without_wait_event_requires_active_os_state(self):
        job_id = job_control.create_job(2511, [2511], "sleep", status="stopped", audit_id=56)
        job = job_control.jobs[job_id]
        job["stop_requested"] = True
        for status in (job_control.psutil.STATUS_STOPPED, job_control.psutil.STATUS_TRACING_STOP,
                       job_control.psutil.STATUS_ZOMBIE, job_control.psutil.STATUS_DEAD, None, "?"):
            with self.subTest(status=status), self.pending({}), \
                 patch.object(job_control, "_process_status", return_value=status):
                self.assertEqual(job_control.update_jobs(), [])
            self.assertEqual(job["status"], "stopped")
            self.assertIsNone(job["processes"][2511]["status"])
        with self.pending({}), patch.object(job_control, "_process_status",
                                          return_value=job_control.psutil.STATUS_SLEEPING):
            self.assertEqual(job_control.update_jobs(), [])
            self.assertEqual(job_control.update_jobs(), [])
        self.assertEqual(job["status"], "running")
        self.assertFalse(job["stop_requested"])
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list],
                         ["stopped", "running"])
        self.killpg.assert_not_called()
        with self.pending({2511: [exited(9)]}):
            self.assertEqual(job_control.update_jobs(), [job_id])
        self.assertEqual(job["last_status"], 9)
        self.assertEqual(self.audit.call_args.kwargs["exit_status"], 9)

    def test_unavailable_process_status_is_not_resume_evidence(self):
        job_id = job_control.create_job(2521, [2521], "sleep", status="stopped", audit_id=57)
        for error in (job_control.psutil.NoSuchProcess(2521), job_control.psutil.AccessDenied(2521)):
            with self.subTest(error=error), self.pending({}), \
                 patch.object(job_control.psutil, "Process", side_effect=error):
                self.assertEqual(job_control.update_jobs(), [])
            self.assertEqual(job_control.jobs[job_id]["status"], "stopped")
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list], ["stopped"])

    def test_stale_stop_after_continue_does_not_stop_running_pipeline(self):
        job_id = job_control.create_job(2531, [2531, 2532], "a | b", status="stopped", audit_id=58)
        job = job_control.jobs[job_id]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(job_control.background_job(job_id), 0)
        self.killpg.assert_called_once_with(2531, signal.SIGCONT)
        with self.pending({2531: [stopped(signal.SIGSTOP)]}), \
             patch.object(job_control, "_process_status", return_value=job_control.psutil.STATUS_RUNNING):
            self.assertEqual(job_control.update_jobs(), [])
        self.assertEqual(job["status"], "running")
        self.assertTrue(all(process["state"] == "running" for process in job["processes"].values()))
        self.killpg.assert_called_once_with(2531, signal.SIGCONT)
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list],
                         ["stopped", "running"])
        # A real later stop must still suspend the whole process group.
        with self.pending({2531: [stopped()], 2532: [stopped(signal.SIGSTOP)]}), \
             patch.object(job_control, "_process_status", return_value=job_control.psutil.STATUS_STOPPED):
            self.assertEqual(job_control.update_jobs(), [])
        self.assertEqual(job["status"], "stopped")
        self.assertEqual(self.killpg.call_args.args, (2531, signal.SIGSTOP))
        self.assertEqual([call.kwargs["state"] for call in self.audit.call_args_list],
                         ["stopped", "running", "stopped"])

    def test_foreground_resume_hands_off_before_continuing(self):
        job_id = job_control.create_job(2601, [2601], "sleep", status="stopped",
                                        background=True, cwd="/original", audit_id=66)
        order = []
        self.killpg.side_effect = lambda *args: order.append("continue")
        with patch.object(job_control, "give_terminal_to", side_effect=lambda pgid: order.append("handoff") or True), \
             patch.object(job_control, "give_terminal_to_shell", side_effect=lambda: order.append("reclaim") or True), \
             patch.object(job_control.os, "waitpid", return_value=(2601, exited(8))):
            self.assertEqual(job_control.foreground_job(job_id), 8)
        self.assertEqual(order, ["handoff", "continue", "reclaim"])
        self.assertTrue(job_control.jobs[job_id]["background"])
        self.assertEqual(job_control.jobs[job_id]["cwd"], "/original")
        self.assertEqual(job_control.foreground_job(job_id), 8)
        completed = [call for call in self.audit.call_args_list if call.kwargs["state"] == "completed"]
        self.assertEqual(len(completed), 1)

    def test_handoff_failure_does_not_continue_or_wait(self):
        job_id = job_control.create_job(2701, [2701], "sleep", status="stopped")
        with patch.object(job_control, "give_terminal_to", return_value=False), \
             patch.object(job_control, "give_terminal_to_shell") as reclaim, \
             patch.object(job_control.os, "waitpid") as wait:
            self.assertEqual(job_control.foreground_job(job_id), 1)
        self.killpg.assert_not_called()
        wait.assert_not_called()
        reclaim.assert_called_once()
        self.assertEqual(job_control.jobs[job_id]["status"], "stopped")

    def test_background_failures_return_nonzero(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(job_control.background_job(999), 1)
            job_id = job_control.create_job(2801, [2801], "sleep", status="stopped")
            self.killpg.side_effect = ProcessLookupError("already exited")
            self.kill.side_effect = ProcessLookupError("already exited")
            self.assertEqual(job_control.background_job(job_id), 1)
        self.assertEqual(job_control.jobs[job_id]["status"], "stopped")

    def test_completed_retention_is_bounded_without_pruning_active_jobs(self):
        active = job_control.create_job(2901, [2901], "active")
        paused = job_control.create_job(2902, [2902], "paused", status="stopped")
        for pid in range(3000, 3130):
            job_id = job_control.create_job(pid, [pid], "true")
            with self.pending({pid: [exited(0)]}):
                self.assertEqual(job_control.wait_for_job(job_id), 0)
        done = [job_id for job_id, job in job_control.jobs.items() if job["status"] == "done"]
        self.assertEqual(len(done), 64)
        self.assertIn(active, job_control.jobs)
        self.assertIn(paused, job_control.jobs)
        job_control.mark_job_notified(done[-1])
        self.assertTrue(job_control.jobs[done[-1]]["notified"])
        self.assertEqual(job_control.wait_job(f"%{done[-1]}"), 0)
        job_control.mark_job_notified(paused)
        self.assertIn(paused, job_control.jobs)

    def test_duration_uses_prelaunch_monotonic_start_despite_wall_clock_jump(self):
        with patch.object(job_control.time, "time", return_value=100000):
            job_id = job_control.create_job(3201, [3201], "true", audit_id=77, start_time=50.0)
        with patch.object(job_control.time, "time", return_value=-100000), \
             patch.object(job_control.time, "monotonic", return_value=52.5), \
             patch.object(job_control.os, "waitpid", return_value=(3201, exited(0))):
            job_control.wait_for_job(job_id)
        self.assertEqual(self.audit.call_args.kwargs["duration_ms"], 2500.0)

    def test_idle_reaper_does_not_print_notifications_or_repeat_completion(self):
        job_id = job_control.create_job(3301, [3301], "untrusted\x1b[2J", audit_id=88, background=True)
        output = io.StringIO()
        with redirect_stdout(output), self.pending({3301: [exited(3)]}):
            self.assertEqual(job_control.update_jobs(), [job_id])
            self.assertEqual(job_control.update_jobs(), [])
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(job_control.jobs[job_id]["last_status"], 3)
        self.assertEqual(len([call for call in self.audit.call_args_list
                              if call.kwargs["state"] == "completed"]), 1)

    def test_unavailable_child_status_is_not_reported_as_success(self):
        job_id = job_control.create_job(3401, [3401], "child", audit_id=99)
        output = io.StringIO()
        with redirect_stderr(output), patch.object(job_control.os, "waitpid", side_effect=ChildProcessError):
            self.assertEqual(job_control.wait_for_job(job_id), 127)
        self.assertIn("status is unavailable", output.getvalue())
        self.assertEqual(self.audit.call_args.kwargs["exit_status"], 127)

    def test_shutdown_continues_stopped_jobs_then_kills_and_reaps_survivors(self):
        job_id = job_control.create_job(3501, [3501], "paused", status="stopped", audit_id=100)
        with patch.object(job_control.os, "waitpid", side_effect=[(0, 0), (3501, signal.SIGKILL)]), \
             patch.object(job_control, "give_terminal_to_shell") as reclaim:
            job_control.shutdown_jobs(grace_period=0)
        self.assertEqual([call.args[1] for call in self.killpg.call_args_list],
                         [signal.SIGHUP, signal.SIGCONT, signal.SIGKILL])
        self.kill.assert_called_once_with(3501, signal.SIGKILL)
        self.assertEqual(job_control.jobs[job_id]["status"], "done")
        self.assertEqual(job_control.jobs[job_id]["last_status"], 128 + signal.SIGKILL)
        reclaim.assert_called_once()

    def test_shutdown_never_signals_shell_process_group(self):
        pgid = os.getpgrp()
        job_id = job_control.create_job(pgid, [3601], "partial launch")
        with self.pending({3601: [exited(1)]}), patch.object(job_control, "give_terminal_to_shell"):
            job_control.shutdown_jobs(grace_period=0)
        self.killpg.assert_not_called()
        self.assertEqual([call.args for call in self.kill.call_args_list],
                         [(3601, signal.SIGHUP), (3601, signal.SIGCONT)])
        self.assertEqual(job_control.jobs[job_id]["status"], "done")

    def test_shutdown_reaps_child_that_left_its_original_group(self):
        job_id = job_control.create_job(3701, [3701], "escaped stopped child", status="stopped")
        self.killpg.side_effect = ProcessLookupError
        with patch.object(job_control.os, "waitpid", side_effect=[(0, 0), (3701, signal.SIGKILL)]), \
             patch.object(job_control, "give_terminal_to_shell"):
            job_control.shutdown_jobs(grace_period=0)
        signals = [call.args for call in self.kill.call_args_list]
        self.assertIn((3701, signal.SIGKILL), signals)
        self.assertEqual(job_control.jobs[job_id]["status"], "done")


@unittest.skipUnless(job_control.IS_UNIX, "POSIX job controls")
class SelectorTests(JobStateFixture):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.object(job_control, "update_audit", return_value=True))

    def test_all_selector_forms_and_ambiguity(self):
        first = job_control.create_job(7001, [7001], "sleep alpha")
        second = job_control.create_job(7002, [7002], "python beta")
        self.assertEqual(job_control.select_job(), second)
        for selector in ("%+", "%%", "%"):
            self.assertEqual(job_control.select_job(selector), second)
        self.assertEqual(job_control.select_job("%-"), first)
        self.assertEqual(job_control.select_job("%1"), first)
        self.assertEqual(job_control.select_job("7001"), first)
        self.assertEqual(job_control.select_job("%sleep"), first)
        self.assertEqual(job_control.select_job("%?beta"), second)
        third = job_control.create_job(7003, [7003], "sleep gamma")
        with redirect_stderr(io.StringIO()):
            self.assertIsNone(job_control.select_job("%sleep"))
        self.assertEqual(job_control.select_job("%?gamma"), third)
        self.assertIsNone(job_control.select_job("%999"))

    def test_wait_accepts_last_background_process_pid(self):
        job_id = job_control.create_job(7401, [7401, 7402], "first | last", background=True)
        with self.pending({7401: [exited(7)], 7402: [exited(13)]}):
            self.assertEqual(job_control.wait_job("7402"), 13)
        self.assertEqual(job_control.jobs[job_id]["status"], "done")

    def test_disown_excludes_shutdown_but_keeps_exact_wait_status(self):
        job_id = job_control.create_job(7101, [7101], "detached", audit_id=12)
        self.assertEqual(job_control.disown_job(), 0)
        self.assertIsNone(job_control.select_job())
        with patch.object(job_control, "give_terminal_to_shell"), self.pending({}):
            job_control.shutdown_jobs(grace_period=0)
        self.kill.assert_not_called()
        self.killpg.assert_not_called()
        with self.pending({7101: [exited(6)]}):
            self.assertEqual(job_control.update_jobs(), [])
        self.assertEqual(job_control.jobs[job_id]["last_status"], 6)

    def test_wait_selector_and_safe_point_hook(self):
        callbacks = []
        job_id = job_control.create_job(7201, [7201], "escaped",
                                        signal_hook=lambda: callbacks.append("safe"))
        with self.pending({7201: [exited(17)]}):
            self.assertEqual(job_control.wait_job("%escaped"), 17)
        self.assertEqual(callbacks, ["safe"])
        self.assertEqual(job_control.jobs[job_id]["status"], "done")
        self.assertTrue(job_control.jobs[job_id]["waited"])
        with redirect_stderr(io.StringIO()):
            self.assertEqual(job_control.wait_job("%missing"), 127)

    def test_pipefail_uses_rightmost_nonzero_stage(self):
        job_id = job_control.create_job(7301, [7301, 7302, 7303], "a | b | c", pipefail=True)
        with self.pending({7301: [exited(7)], 7302: [exited(9)], 7303: [exited(0)]}):
            self.assertEqual(job_control.wait_for_job(job_id), 9)


@unittest.skipUnless(job_control.IS_UNIX and job_control.termios is not None, "POSIX terminal control")
class TerminalTests(JobStateFixture):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.object(job_control, "_terminal_initialized", False))
        self.stack.enter_context(patch.object(job_control, "update_audit", return_value=True))
        self.stdin = self.stack.enter_context(patch.object(job_control.sys, "stdin"))
        self.stdin.isatty.return_value = True
        self.stdin.fileno.return_value = 17
        self.stack.enter_context(patch.object(job_control.os, "isatty", return_value=True))

    def test_noninteractive_input_has_no_fileno_or_terminal_operations(self):
        with patch.object(job_control.sys, "stdin", io.StringIO("input")), \
             patch.object(job_control.os, "tcsetpgrp") as handoff:
            self.assertTrue(job_control.initialize_terminal())
            self.assertTrue(job_control.give_terminal_to(5001))
            self.assertTrue(job_control.give_terminal_to_shell())
        handoff.assert_not_called()

    def test_nested_background_shell_waits_for_foreground_before_own_group(self):
        events = []
        self.killpg.side_effect = lambda pgid, sig: events.append(("suspend", pgid, sig))
        with patch.object(job_control.os, "getpid", return_value=5001), \
             patch.object(job_control.os, "getpgrp", side_effect=[4000, 4000, 4000, 4000, 5001]), \
             patch.object(job_control.os, "tcgetpgrp", side_effect=[3000, 4000]), \
             patch.object(job_control.os, "setpgid", side_effect=lambda *args: events.append(("setpgid", *args))), \
             patch.object(job_control.os, "tcsetpgrp", side_effect=lambda *args: events.append(("terminal", *args))), \
             patch.object(job_control.termios, "tcgetattr", return_value=["shell"]), \
             patch.object(job_control.signal, "signal", return_value=signal.SIG_DFL):
            self.assertTrue(job_control.initialize_terminal())
        self.assertEqual(events, [("suspend", 4000, signal.SIGTTIN),
                                  ("setpgid", 5001, 5001), ("terminal", 17, 5001)])
        self.assertEqual(job_control.shell_pgid, 5001)

    def test_initialization_failure_is_visible_and_retryable(self):
        output = io.StringIO()
        with patch.object(job_control.os, "tcgetpgrp", side_effect=OSError("no controlling terminal")), \
             redirect_stderr(output):
            self.assertFalse(job_control.initialize_terminal())
        self.assertIn("cannot initialize terminal", output.getvalue())
        self.assertFalse(job_control._terminal_initialized)

    def test_stopped_job_modes_survive_handoff_and_shell_modes_restore(self):
        self.stack.enter_context(patch.object(job_control, "_terminal_initialized", True))
        self.stack.enter_context(patch.object(job_control, "_terminal_fd", 17))
        self.stack.enter_context(patch.object(job_control, "_terminal_owner", job_control.shell_pgid))
        job_id = job_control.create_job(5101, [5101], "interactive", status="stopped")
        mode_changes = []
        with patch.object(job_control, "_set_terminal_group") as handoff, \
             patch.object(job_control.termios, "tcgetattr", side_effect=[["shell"], ["job"], ["shell"]]), \
             patch.object(job_control.termios, "tcsetattr", side_effect=lambda fd, when, modes: mode_changes.append(modes)):
            self.assertTrue(job_control.give_terminal_to(5101))
            self.assertTrue(job_control.give_terminal_to_shell())
            self.assertEqual(job_control.jobs[job_id]["terminal_modes"], ["job"])
            self.assertTrue(job_control.give_terminal_to(5101))
        self.assertEqual([call.args[0] for call in handoff.call_args_list],
                         [5101, job_control.shell_pgid, 5101])
        self.assertEqual(mode_changes, [["shell"], ["job"]])

    def test_handoff_and_reclaim_errors_are_visible(self):
        self.stack.enter_context(patch.object(job_control, "_terminal_initialized", True))
        self.stack.enter_context(patch.object(job_control, "_terminal_fd", 17))
        self.stack.enter_context(patch.object(job_control, "_terminal_owner", 5201))
        output = io.StringIO()
        with patch.object(job_control, "_set_terminal_group", side_effect=OSError("denied")), \
             redirect_stderr(output):
            self.assertFalse(job_control.give_terminal_to(5201))
            self.assertFalse(job_control.give_terminal_to_shell())
        self.assertIn("cannot give terminal", output.getvalue())
        self.assertIn("cannot return terminal", output.getvalue())

    def test_termios_specific_error_is_reported_without_escaping(self):
        self.stack.enter_context(patch.object(job_control, "_terminal_initialized", True))
        self.stack.enter_context(patch.object(job_control, "_terminal_fd", 17))
        self.stack.enter_context(patch.object(job_control, "_terminal_owner", job_control.shell_pgid))
        output = io.StringIO()
        with patch.object(job_control.termios, "tcgetattr",
                          side_effect=job_control.termios.error(25, "inappropriate ioctl")), \
             redirect_stderr(output):
            self.assertFalse(job_control.give_terminal_to(5301))
        self.assertIn("cannot give terminal", output.getvalue())


@unittest.skipUnless(job_control.IS_UNIX, "POSIX audit lifecycle")
class JobAuditIntegrationTests(JobStateFixture):
    def setUp(self):
        super().setUp()
        directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.dict(os.environ, {
            "HOME": directory, "XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory,
            "XDG_STATE_HOME": directory, "ARGUS_CONFIG_HOME": directory,
            "ARGUS_STATE_HOME": directory, "ARGUS_DATA_HOME": directory}))
        self.stack.enter_context(patch.object(database, "ARGUS_DATA_DIR", directory))
        self.stack.enter_context(patch.object(database, "ARGUS_DATABASE", str(Path(directory) / "audit.db")))
        self.assertTrue(database.initialize_database())

    def read_record(self, audit_id):
        with closing(database.get_database_connection()) as connection:
            record = dict(connection.execute("SELECT * FROM command_audit WHERE id=?", (audit_id,)).fetchone())
            states = [row[0] for row in connection.execute(
                "SELECT state FROM command_events WHERE audit_id=? ORDER BY id", (audit_id,))]
            count = connection.execute("SELECT COUNT(*) FROM command_audit").fetchone()[0]
        return record, states, count

    def test_real_audit_preserves_one_command_through_stop_resume_and_completion(self):
        audit_id = audit.audit_command("first | last", cwd="/launch", background=True,
                                       risk_score=31, risk_reasons=["launch reason"], state="running")
        self.assertIsNotNone(audit_id)
        job_id = job_control.create_job(6101, [6101, 6102], "first | last", background=True,
                                        cwd="/launch", audit_id=audit_id, start_time=10.0)
        with self.pending({6101: [stopped()], 6102: [stopped()]}):
            self.assertEqual(job_control.update_jobs(), [])
        record, states, count = self.read_record(audit_id)
        self.assertEqual(record["state"], "stopped")
        self.assertIsNone(record["exit_status"])
        self.assertIsNone(record["completed_at"])
        self.assertNotIn("completed", states)
        self.assertEqual(count, 1)
        with patch.object(job_control.time, "monotonic", return_value=12.0), \
             patch.object(job_control, "give_terminal_to", return_value=True), \
             patch.object(job_control, "give_terminal_to_shell", return_value=True), \
             patch.object(job_control.os, "waitpid", side_effect=[(6102, exited(5)), (6101, exited(0))]):
            self.assertEqual(job_control.foreground_job(job_id), 5)
        self.assertEqual(job_control.foreground_job(job_id), 5)
        job_control.update_jobs()
        record, states, count = self.read_record(audit_id)
        self.assertEqual(count, 1)
        self.assertEqual(record["state"], "completed")
        self.assertEqual(record["exit_status"], 5)
        self.assertEqual(record["duration_ms"], 2000.0)
        self.assertEqual(record["cwd"], "/launch")
        self.assertEqual(record["background"], 1)
        self.assertEqual(record["risk_score"], 31)
        self.assertEqual(record["risk_reasons"], "launch reason")
        self.assertEqual(states.count("completed"), 1)
        self.assertIn("stopped", states)


if __name__ == "__main__":
    unittest.main()
