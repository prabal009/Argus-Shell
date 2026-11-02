"""Observable builtin regressions; no commands under analysis are executed."""

import copy
import importlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

from argus.history import History
from argus.language import ShellRuntime, ShellState


class BuiltinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import-time HOME must never point at a developer's real Argus files.
        cls.import_home = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {"HOME": cls.import_home.name,
                "ARGUS_DATA_HOME": cls.import_home.name + "/data",
                "ARGUS_CONFIG_HOME": cls.import_home.name + "/config",
                "ARGUS_STATE_HOME": cls.import_home.name + "/state"}):
            cls.b = importlib.import_module("argus.builtins")
            cls.security = importlib.import_module("argus.security")
            cls.suspicious = importlib.import_module("argus.suspicious")

    @classmethod
    def tearDownClass(cls):
        cls.import_home.cleanup()

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.db_path = Path(self.home.name) / "events.sqlite3"
        self.policy_path = Path(self.home.name) / "policy.json"
        self.saved_policy = copy.deepcopy(self.b.security_policy)
        self.saved_buffer = list(self.suspicious.suspicious_buffer)
        self.saved_cooldowns = dict(self.suspicious.suspicious_cooldowns)
        self.addCleanup(self.restore_globals)
        self.b.security_policy.clear()
        self.b.security_policy.update(copy.deepcopy(self.b.DEFAULT_SECURITY_POLICY))
        self.b.security_policy["denylist"] = []
        self.suspicious.suspicious_buffer.clear()
        self.suspicious.suspicious_cooldowns.clear()
        for target, attribute, value in (
            (self.b, "get_database_connection", self.connect),
            (self.suspicious, "get_database_connection", self.connect),
            (self.security, "get_database_connection", self.connect),
            (self.security, "ARGUS_POLICY_FILE", str(self.policy_path)),
        ):
            patcher = patch.object(target, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = patch.dict(os.environ, {"HOME": self.home.name})
        env.start()
        self.addCleanup(env.stop)
        self.runtime = ShellRuntime(lambda commands, background, runtime: 0,
                                    state=ShellState())
        self.history = History(Path(self.home.name) / "history")
        self.b.configure_runtime(self.runtime, SimpleNamespace(history=self.history))
        self.addCleanup(self.b.configure_runtime, None)
        with closing(self.connect()) as connection, connection:
            connection.executescript("""
                CREATE TABLE command_audit (
                    id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, cwd TEXT,
                    command TEXT, command_name TEXT, pid INTEGER, background INTEGER,
                    exit_status INTEGER, duration_ms REAL, command_type TEXT, job_id INTEGER,
                    risk_score INTEGER, risk_reasons TEXT, security_action TEXT,
                    state TEXT DEFAULT 'completed', session_id TEXT
                );
                CREATE TABLE suspicious_events (
                    id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, cwd TEXT,
                    session_id TEXT, rule_name TEXT, severity TEXT, reason TEXT,
                    matched_command TEXT, context TEXT
                );
                CREATE TABLE security_actions (
                    id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, cwd TEXT,
                    session_id TEXT, mode TEXT, action TEXT, reason TEXT, command TEXT,
                    risk_score INTEGER, suspicious_rules TEXT
                );
            """)
            connection.execute("""
                INSERT INTO command_audit
                    (id, timestamp, username, cwd, command, command_name, background,
                     exit_status, duration_ms, risk_score, risk_reasons, security_action)
                VALUES (1, '2026-01-01', 'tester', '/tmp', 'printf visible', 'printf',
                        0, 0, 2.0, 80, 'visible risk reason', 'allow')
            """)
            for session in (self.suspicious.suspicious_session_id, "other-session"):
                connection.execute("""
                    INSERT INTO suspicious_events
                        (timestamp, username, cwd, session_id, rule_name, severity,
                         reason, matched_command)
                    VALUES ('2026-01-01', 'tester', '/tmp', ?, 'visible_rule', 'high',
                            'visible reason', 'printf suspicious')
                """, (session,))

    def restore_globals(self):
        self.b.security_policy.clear()
        self.b.security_policy.update(self.saved_policy)
        self.suspicious.suspicious_buffer.clear()
        self.suspicious.suspicious_buffer.extend(self.saved_buffer)
        self.suspicious.suspicious_cooldowns.clear()
        self.suspicious.suspicious_cooldowns.update(self.saved_cooldowns)

    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def capture(self, function, *args):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            status = function(*args)
        return status, output.getvalue()

    def counts(self):
        with closing(self.connect()) as connection:
            return tuple(connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                         for table in ("command_audit", "suspicious_events", "security_actions"))

    def test_nonempty_reports_render_to_completion(self):
        for function, args, expected in (
            (self.b.builtin_audit, (["audit"],), "printf visible"),
            (self.b.builtin_audit, (["audit", "risky"],), "visible risk reason"),
            (self.b.builtin_audit_stats, (), "printf"),
            (self.b.builtin_suspicious, (["suspicious"],), "visible_rule"),
            (self.b.builtin_suspicious_stats, (), "visible_rule"),
            (self.b.builtin_risk, (["risk", "printf visible"],), "SUSPICIOUS CHECKS"),
        ):
            with self.subTest(function=function.__name__, args=args):
                status, output = self.capture(function, *args)
                self.assertEqual(status, 0)
                self.assertIn(expected, output)

    def test_failed_builtins_return_nonzero(self):
        for function, args in (
            (self.b.builtin_cd, ["cd", str(Path(self.home.name) / "missing")]),
            (self.b.builtin_security, ["security", "typo"]),
            (self.b.builtin_security, ["security", "mode", "unknown"]),
            (self.b.builtin_security, ["security", "threshold", "bad"]),
            (self.b.builtin_audit, ["audit", "risky", "bad"]),
            (self.b.builtin_suspicious, ["suspicious", "typo"]),
            (self.b.builtin_allow, ["allow", "printf", "ignored"]),
            (self.b.builtin_deny, ["deny", "--help"]),
        ):
            with self.subTest(args=args):
                status, _ = self.capture(function, args)
                self.assertIsInstance(status, int)
                self.assertNotEqual(status, 0)

    def test_no_argument_builtins_reject_extra_arguments(self):
        for name in ("pwd", "env", "history", "jobs", "audit_stats", "suspicious_stats",
                     "allowlist", "help"):
            function = getattr(self.b, "builtin_" + name)
            with self.subTest(name=name):
                status, _ = self.capture(function, [name, "unexpected"])
                self.assertNotEqual(status, 0)

    def test_database_errors_are_failures(self):
        with patch.object(self.b, "get_database_connection", side_effect=sqlite3.OperationalError("unavailable")):
            for function, args in (
                (self.b.builtin_audit, (["audit"],)),
                (self.b.builtin_audit, (["audit", "risky"],)),
                (self.b.builtin_audit_stats, ()),
                (self.b.builtin_suspicious, (["suspicious"],)),
                (self.b.builtin_suspicious_stats, ()),
            ):
                with self.subTest(function=function.__name__, args=args):
                    status, output = self.capture(function, *args)
                    self.assertNotEqual(status, 0)
                    self.assertIn("unavailable", output)

    def test_database_connections_close_after_query_failure(self):
        opened = []

        def empty_database():
            connection = sqlite3.connect(":memory:")
            opened.append(connection)
            self.addCleanup(connection.close)
            return connection

        with patch.object(self.b, "get_database_connection", empty_database):
            for function, args in (
                (self.b.builtin_audit, (["audit"],)),
                (self.b.builtin_audit, (["audit", "risky"],)),
                (self.b.builtin_audit_stats, ()),
                (self.b.builtin_suspicious, (["suspicious"],)),
                (self.b.builtin_suspicious_stats, ()),
            ):
                with self.subTest(function=function.__name__, args=args):
                    status, _ = self.capture(function, *args)
                    self.assertNotEqual(status, 0)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        opened[-1].execute("SELECT 1")

    def test_clear_help_typos_and_extra_arguments_do_not_delete(self):
        before = self.counts()
        for function, args in (
            (self.b.builtin_suspicious_clear, ["suspicious-clear", "--help"]),
            (self.b.builtin_suspicious_clear, ["suspicious-clear", "typo"]),
            (self.b.builtin_suspicious_clear, ["suspicious-clear", "all", "typo"]),
            (self.b.builtin_audit, ["audit", "clear", "typo"]),
            (self.b.builtin_audit, ["audit", "--help"]),
        ):
            with self.subTest(args=args), patch("builtins.input", side_effect=AssertionError("must not prompt")):
                self.capture(function, args)
                self.assertEqual(self.counts(), before)

    def test_clear_confirmation_and_session_scope(self):
        with patch("builtins.input", return_value="no"):
            status, _ = self.capture(self.b.builtin_suspicious_clear, ["suspicious-clear"])
        self.assertNotEqual(status, 0)
        self.assertEqual(self.counts()[1], 2)
        with patch("builtins.input", return_value=" y "):
            status, output = self.capture(self.b.builtin_suspicious_clear, ["suspicious-clear"])
        self.assertEqual(status, 0)
        self.assertIn("unchanged", output)
        with closing(self.connect()) as connection:
            remaining = connection.execute("SELECT session_id FROM suspicious_events").fetchall()
        self.assertEqual([row[0] for row in remaining], ["other-session"])
        with patch("builtins.input", return_value="y"):
            status, _ = self.capture(self.b.builtin_suspicious_clear, ["suspicious-clear", "all"])
        self.assertEqual(status, 0)
        self.assertEqual(self.counts()[1], 0)

    def test_runtime_redo_replays_shell_state_and_preserves_status(self):
        from argus import main

        def execute(commands, background, runtime):
            self.assertFalse(background)
            self.assertEqual(len(commands), 1)
            return main.dispatch_builtin(commands[0].argv, runtime)

        runtime = ShellRuntime(execute, state=ShellState(),
                               stdout=io.StringIO(), stderr=io.StringIO())
        self.assertNotEqual(main.dispatch_builtin(["redo"], runtime), 0)
        runtime.state.last_command = "set -- replayed; false"
        self.assertEqual(main.dispatch_builtin(["redo"], runtime), 1)
        self.assertEqual(runtime.state.positional, ["replayed"])
        self.assertEqual(runtime.state.last_status, 1)
        self.assertNotEqual(main.dispatch_builtin(["redo", "extra"], runtime), 0)
        runtime.state.variables["ARGUS_TEST_REDO"] = "redo"
        for source in ("redo", "'redo'", '"redo"', "$ARGUS_TEST_REDO"):
            runtime.state.last_command = source
            with self.subTest(source=source):
                self.assertNotEqual(main.dispatch_builtin(["redo"], runtime), 0)

    def test_risk_requires_one_raw_subject_and_preserves_operator_identity(self):
        for args in (["risk"], ["risk", "printf", "literal"], ["risk", "printf |"]):
            status, _ = self.capture(self.b.builtin_risk, args)
            self.assertNotEqual(status, 0)
        self.b.security_policy.update(mode="allowlist", allowlist=["printf"], denylist=[])
        status, output = self.capture(self.b.builtin_risk, ["risk", 'printf "%s" "|"'])
        self.assertEqual(status, 0)
        self.assertIn('printf "%s" "|"', output)
        self.assertIn(f"{self.b.BRIGHT_WHITE}allow{self.b.RESET}", output)
        status, output = self.capture(self.b.builtin_risk, ["risk", "printf x | cat"])
        self.assertEqual(status, 0)
        self.assertIn("deny", output)

    def test_risk_uses_suspicious_checks_without_state_or_database_mutation(self):
        self.capture(self.suspicious.detect_suspicious, "whoami")
        before_buffer = copy.deepcopy(list(self.suspicious.suspicious_buffer))
        before_cooldowns = dict(self.suspicious.suspicious_cooldowns)
        before_rows = self.counts()
        self.b.security_policy.update(mode="block", risk_threshold=100,
                                      block_on_suspicious=True, suspicious_min_severity="high")
        status, output = self.capture(self.b.builtin_risk, ["risk", "base64 -d"])
        self.assertEqual(status, 0)
        self.assertIn("obfuscated_shell", output)
        self.assertIn("deny", output)
        self.assertEqual(list(self.suspicious.suspicious_buffer), before_buffer)
        self.assertEqual(self.suspicious.suspicious_cooldowns, before_cooldowns)
        self.assertEqual(self.counts(), before_rows)
        target = Path(self.home.name) / "must-not-exist"
        self.capture(self.b.builtin_risk, ["risk", "touch " + str(target)])
        self.assertFalse(target.exists())
        self.assertEqual(self.counts(), before_rows)

    def test_security_save_load_missing_and_invalid_are_honest(self):
        status, output = self.capture(self.b.builtin_security, ["security", "load"])
        self.assertNotEqual(status, 0)
        self.assertIn("no policy file", output)
        self.b.security_policy["risk_threshold"] = 81
        status, output = self.capture(self.b.builtin_security, ["security", "save"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(self.policy_path.read_text())["risk_threshold"], 81)
        self.b.security_policy["risk_threshold"] = 12
        status, output = self.capture(self.b.builtin_security, ["security", "load"])
        self.assertEqual(status, 0)
        self.assertEqual(self.b.security_policy["risk_threshold"], 81)
        before = copy.deepcopy(self.b.security_policy)
        self.policy_path.write_text('{"mode": "off", "risk_threshold": "bad"}')
        status, output = self.capture(self.b.builtin_security, ["security", "load"])
        self.assertNotEqual(status, 0)
        self.assertEqual(self.b.security_policy, before)

    def test_security_io_errors_and_typos_do_not_claim_success(self):
        before = copy.deepcopy(self.b.security_policy)
        for args in (["security", "mode", "off", "extra"], ["security", "reset", "extra"],
                     ["security", "save", "extra"], ["allow", "printf", "extra"]):
            function = self.b.builtin_allow if args[0] == "allow" else self.b.builtin_security
            status, _ = self.capture(function, args)
            self.assertNotEqual(status, 0)
            self.assertEqual(self.b.security_policy, before)
        with patch.object(self.b, "load_policy_from_disk", side_effect=PermissionError("unreadable")):
            status, output = self.capture(self.b.builtin_security, ["security", "load"])
        self.assertNotEqual(status, 0)
        self.assertIn("unreadable", output)
        with patch.object(self.b, "save_policy_to_disk", return_value=False):
            status, output = self.capture(self.b.builtin_security, ["security", "save"])
        self.assertNotEqual(status, 0)
        self.assertIn("not saved", output)

    def test_policy_crud_keeps_shared_identity_and_rejects_partial_updates(self):
        shared = self.security.security_policy
        for function, args in (
            (self.b.builtin_allow, ["allow", "printf"]),
            (self.b.builtin_deny, ["deny", "blocked"]),
            (self.b.builtin_security, ["security", "set", "block_on_suspicious", "false"]),
            (self.b.builtin_security, ["security", "set", "resource_limits.cpu_seconds", "7"]),
            (self.b.builtin_security, ["security", "rule", "set", "printf",
                                      '{"allowed_args":["ok"],"output_roots":[]}']),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.capture(function, args)[0], 0)
                self.assertIs(self.security.security_policy, shared)
        self.assertEqual(shared["allowlist"].count("printf"), 1)
        self.assertIn("blocked", shared["denylist"])
        self.assertFalse(shared["block_on_suspicious"])
        self.assertEqual(shared["resource_limits"]["cpu_seconds"], 7)
        before = copy.deepcopy(shared)
        for args in (
            ["security", "set", "risk_threshold", "true"],
            ["security", "set", "resource_limits", '{"enabled":"yes"}'],
            ["security", "rule", "set", "printf", '{"output_roots":["relative"]}'],
            ["security", "rule", "remove", "absent"],
        ):
            self.assertNotEqual(self.capture(self.b.builtin_security, args)[0], 0)
            self.assertEqual(shared, before)
        with patch("builtins.input", return_value='{"denied_args":["bad"]}'):
            self.assertEqual(self.capture(self.b.builtin_security,
                ["security", "rule", "edit", "printf"])[0], 0)
        status, output = self.capture(self.b.builtin_security, ["security", "rule", "list"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["printf"], {"denied_args": ["bad"]})
        for function, args in (
            (self.b.builtin_allow, ["allow", "remove", "printf"]),
            (self.b.builtin_deny, ["deny", "remove", "blocked"]),
            (self.b.builtin_security, ["security", "rule", "remove", "printf"]),
        ):
            self.assertEqual(self.capture(function, args)[0], 0)
        self.assertNotIn("printf", shared["allowlist"])
        self.assertNotIn("blocked", shared["denylist"])
        self.assertNotIn("printf", shared["command_rules"])

    def test_risk_preview_preserves_language_state_and_never_executes_dynamic_input(self):
        marker = Path(self.home.name) / "no-preview-execution"
        self.runtime.state.variables["ARGUS_PREVIEW"] = "printf"
        before = self.runtime.state.snapshot()
        before_rows = self.counts()
        with patch.object(self.runtime, "executor", side_effect=AssertionError("executed")):
            status, output = self.capture(self.b.builtin_risk,
                ["risk", '$ARGUS_PREVIEW "$(touch ' + str(marker) + ')" "${NEW:=changed}"'])
        self.assertEqual(status, 0)
        self.assertIn("unknown", output.lower())
        self.assertFalse(marker.exists())
        self.assertEqual(self.runtime.state.snapshot(), before)
        self.assertEqual(self.counts(), before_rows)

    def test_metadata_is_escaped_without_changing_environment_data(self):
        raw = "value\x1b]0;forged-title\x07\nsecond-line"
        with patch.dict(self.runtime.state.variables, {"ARGUS_BUILTIN_TEST": raw}):
            self.runtime.state.exported.add("ARGUS_BUILTIN_TEST")
            status, output = self.capture(self.b.builtin_env)
            self.assertEqual(status, 0)
            self.assertNotIn(raw, output)
            self.assertIn(self.b.safe_text(raw), output)
            self.assertEqual(self.runtime.state.variables["ARGUS_BUILTIN_TEST"], raw)
            self.assertEqual(self.runtime.run_builtin(["export", "ARGUS_EXPORTED_TEST=" + raw]), 0)
            self.assertEqual(self.runtime.state.environment()["ARGUS_EXPORTED_TEST"], raw)
            self.assertNotIn("ARGUS_EXPORTED_TEST", os.environ)
            self.assertEqual(self.runtime.run_builtin(["unset", "ARGUS_EXPORTED_TEST"]), 0)
            self.assertNotIn("ARGUS_EXPORTED_TEST", self.runtime.state.environment())
        with closing(self.connect()) as connection, connection:
            connection.execute("UPDATE suspicious_events SET rule_name = ?, matched_command = ?", (raw, raw))
            connection.execute("UPDATE command_audit SET command_name = ?, risk_reasons = ?", (raw, raw))
        for function, args in (
            (self.b.builtin_suspicious, (["suspicious"],)),
            (self.b.builtin_suspicious_stats, ()),
            (self.b.builtin_audit_stats, ()),
            (self.b.builtin_audit, (["audit", "risky"],)),
        ):
            with self.subTest(function=function.__name__):
                status, output = self.capture(function, *args)
                self.assertEqual(status, 0)
                self.assertNotIn(raw, output)
                self.assertNotIn("\x1b]0;", output)

    def test_clear_database_failures_and_audit_confirmation_statuses(self):
        before = self.counts()
        with patch("builtins.input", return_value="n"):
            status, _ = self.capture(self.b.builtin_audit, ["audit", "clear"])
        self.assertNotEqual(status, 0)
        self.assertEqual(self.counts(), before)
        with patch("builtins.input", return_value="y"):
            with patch.object(self.b, "get_database_connection", side_effect=OSError("read-only")):
                for function, args in (
                    (self.b.builtin_audit, ["audit", "clear"]),
                    (self.b.builtin_suspicious_clear, ["suspicious-clear"]),
                ):
                    with self.subTest(args=args):
                        status, output = self.capture(function, args)
                        self.assertNotEqual(status, 0)
                        self.assertIn("read-only", output)
        self.assertEqual(self.counts(), before)
        with patch("builtins.input", return_value="y"):
            status, _ = self.capture(self.b.builtin_audit, ["audit", "clear"])
        self.assertEqual(status, 0)
        self.assertEqual(self.counts(), (0, before[1], before[2]))

    def test_history_and_job_metadata_are_escaped(self):
        raw = "printf forged\x1b]0;title\x07\nsecond-line"
        self.history.add(raw)
        status, output = self.capture(self.b.builtin_history)
        self.assertEqual(status, 0)
        self.assertIn(self.b.safe_text(raw), output)
        self.assertNotIn(raw, output)
        with patch.dict(self.b.jobs, {1: {"command": raw, "status": "running"}}, clear=True):
            with patch.object(self.b, "update_jobs", return_value=[]):
                status, output = self.capture(self.b.builtin_jobs)
        self.assertEqual(status, 0)
        self.assertIn(self.b.safe_text(raw), output)
        self.assertNotIn(raw, output)


if __name__ == "__main__":
    unittest.main()
