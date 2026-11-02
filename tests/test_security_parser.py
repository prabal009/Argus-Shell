"""Behavior regressions for structured parsing, policy, and detector state."""

import copy
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from argus import language, resource, security, suspicious
from argus.config import DEFAULT_SECURITY_POLICY


class ParserTests(unittest.TestCase):
    def test_preview_preserves_quoted_operators_as_words(self):
        commands, uncertainties = language.preview(r'''printf '%s' '|' \| "&" '>' "<" pre"mid"'post' '' ''')
        self.assertEqual(commands[0].argv,
                         ["printf", "%s", "|", "|", "&", ">", "<", "premidpost", ""])
        self.assertEqual(commands[0].redirections, [])
        self.assertFalse(uncertainties)

    def test_preview_supports_assignments_lists_and_fd_redirections(self):
        commands, uncertainties = language.preview('A=value printf x 2>>"error file"; cat <input')
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0].assignments, {"A": "value"})
        self.assertEqual(commands[0].redirections,
                         [language.Redirection(2, ">>", "error file")])
        self.assertEqual(commands[1].redirections, [language.Redirection(0, "<", "input")])

    def test_dynamic_preview_never_runs_substitutions_or_mutates_state(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "untouched"
            state = language.ShellState()
            before = state.snapshot()
            commands, uncertainties = language.preview(
                'printf "$(touch ' + str(marker) + ')" "${NEW:=changed}"', state)
            self.assertTrue(uncertainties)
            self.assertFalse(marker.exists())
            self.assertEqual(state.snapshot(), before)

    def test_preview_exposes_every_control_flow_executable(self):
        commands, uncertainties = language.preview("if true; then printf yes; else denied; fi")
        names = [command.argv[0] for command in commands if command.argv]
        self.assertIn("true", names)
        self.assertIn("printf", names)
        self.assertIn("denied", names)

    def test_malformed_input_has_no_filesystem_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "untouched"
            for source in ("'unclosed", "cat |", "printf safe > " + str(marker) + " |"):
                with self.subTest(source=source), self.assertRaises((ValueError, SyntaxError)):
                    language.preview(source)
                self.assertFalse(marker.exists())


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.original = copy.deepcopy(security.security_policy)
        security.security_policy.clear()
        security.security_policy.update(copy.deepcopy(DEFAULT_SECURITY_POLICY))
        security.security_policy["mode"] = "block"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.home_patch = patch.dict(os.environ, {"HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / "config"), "XDG_DATA_HOME": str(self.home / "data"),
            "XDG_STATE_HOME": str(self.home / "state"), "ARGUS_CONFIG_HOME": str(self.home / "config"),
            "ARGUS_DATA_HOME": str(self.home / "data"), "ARGUS_STATE_HOME": str(self.home / "state")})
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.path_patch = patch.object(security, "ARGUS_POLICY_FILE", str(self.home / "policy.json"))
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.addCleanup(self.restore_policy)

    def restore_policy(self):
        security.security_policy.clear()
        security.security_policy.update(self.original)

    def decide(self, text, hits=(), score=0, **kwargs):
        commands, uncertainties = language.preview(text)
        return security.evaluate_security(text, score, hits, stages=commands, **kwargs)[0]

    def make_executable(self, name):
        target = self.home / name
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o700)
        return target

    def test_deny_every_stage_quoted_expanded_and_explicit_path(self):
        target = self.make_executable("denied-command")
        security.security_policy["denylist"] = ["denied-command"]
        with patch.dict(os.environ, {"PATH": str(self.home), "ARGUS_DENIED": "denied-command"}):
            for text in ("denied-command", "'denied-command'", "$ARGUS_DENIED", str(target),
                         "printf x | denied-command", "printf x | " + str(target)):
                with self.subTest(text=text):
                    self.assertEqual(self.decide(text), "deny")

    def test_symlink_aliases_resolve_both_policy_and_executable_identity(self):
        target = self.make_executable("real-target")
        policy_alias = self.home / "policy-name"
        policy_alias.symlink_to(target)
        alias = self.home / "innocent-alias"
        alias.symlink_to(target)
        with patch.dict(os.environ, {"PATH": str(self.home)}):
            for entry in ("policy-name", str(policy_alias), "real-target", str(target)):
                security.security_policy["denylist"] = [entry]
                self.assertEqual(self.decide(str(alias)), "deny")
            security.security_policy["denylist"] = []
            security.security_policy["mode"] = "allowlist"
            security.security_policy["allowlist"] = ["policy-name"]
            self.assertEqual(self.decide(str(alias)), "allow")
            self.assertEqual(self.decide("unknown-command | " + str(alias)), "deny")

    def test_policy_alias_resolution_uses_effective_shell_and_command_path(self):
        target = self.make_executable("real-target")
        policy_alias = self.home / "policy-name"
        policy_alias.symlink_to(target)
        alias = self.home / "friendly-name"
        alias.symlink_to(target)
        security.security_policy.update(mode="allowlist", allowlist=["policy-name"], denylist=[])
        commands = [language.Command([str(alias)], {}, [])]
        with patch.dict(os.environ, {"PATH": "/not-the-shell-path"}):
            self.assertEqual(security.evaluate_security(
                str(alias), 0, [], stages=commands, environment={"PATH": str(self.home)})[0], "allow")
            commands[0].assignments["PATH"] = str(self.home)
            self.assertEqual(security.evaluate_security(
                str(alias), 0, [], stages=commands, environment={"PATH": "/elsewhere"})[0], "allow")
            security.security_policy.update(mode="block", denylist=["policy-name"])
            self.assertEqual(security.evaluate_security(
                str(alias), 0, [], stages=commands, environment={"PATH": "/elsewhere"})[0], "deny")

    def test_descriptor_and_heredoc_redirections_do_not_become_filesystem_paths(self):
        security.security_policy["command_rules"] = {
            "printf": {"input_roots": [], "output_roots": []}}
        for redirection in (language.Redirection(1, ">&", "2"),
                            language.Redirection(4, "<&", "0-"),
                            language.Redirection(5, ">&", "-"),
                            language.Redirection(0, "<<", "literal body"),
                            language.Redirection(0, "<<<", "literal text")):
            commands = [language.Command(["printf", "ok"], {}, [redirection])]
            with self.subTest(redirection=redirection):
                self.assertEqual(security.evaluate_security(
                    "printf ok", 0, [], stages=commands)[0], "allow")
        for redirection in (language.Redirection(1, ">&", "file"),
                            language.Redirection(0, "<>", str(self.home / "rw"))):
            commands = [language.Command(["printf", "ok"], {}, [redirection])]
            self.assertEqual(security.evaluate_security("printf ok", 0, [], stages=commands)[0], "deny")

    def test_allowlist_does_not_skip_risk_or_suspicious_checks(self):
        security.security_policy.update(mode="allowlist", allowlist=["printf", "rm"])
        self.assertEqual(self.decide("printf x", score=90), "deny")
        self.assertEqual(self.decide("printf x", hits=[("example", "critical", "reason")]), "deny")
        self.assertEqual(self.decide("printf x"), "allow")
        with patch.dict(os.environ, {"ARGUS_OPTION": "-rf"}):
            self.assertEqual(self.decide("rm $ARGUS_OPTION /"), "deny")
        security.security_policy["denylist"] = ["printf"]
        self.assertEqual(self.decide("printf x"), "deny")

    def test_allowlist_scores_resolved_aliases_and_expanded_pipeline_structure(self):
        target = self.make_executable("rm")
        alias = self.home / "friendly-name"
        alias.symlink_to(target)
        security.security_policy.update(mode="allowlist", allowlist=["rm", "curl", "sh"])
        self.assertEqual(self.decide(str(alias) + " -rf /"), "deny")
        downloader = self.make_executable("curl")
        interpreter = self.make_executable("sh")
        with patch.dict(os.environ, {"ARGUS_DOWNLOADER": str(downloader), "ARGUS_INTERPRETER": str(interpreter)}):
            self.assertEqual(self.decide("$ARGUS_DOWNLOADER example | $ARGUS_INTERPRETER"), "deny")

    def test_explicit_argument_and_canonical_redirect_rules(self):
        permitted = self.home / "allowed"
        permitted.mkdir()
        outside = self.home / "outside"
        outside.mkdir()
        (permitted / "escape").symlink_to(outside, target_is_directory=True)
        security.security_policy["command_rules"] = {
            "printf": {"allowed_args": ["ok", "forbidden"], "denied_args": ["forbidden"],
                       "input_roots": [], "output_roots": [str(permitted)]}}
        self.assertEqual(self.decide("printf ok > " + str(permitted / "output")), "allow")
        for text in ("printf other", "printf forbidden", "printf ok < input",
                     "printf ok > " + str(outside / "output"),
                     "printf ok > " + str(permitted / "escape" / "output"),
                     "printf ok > " + str(permitted.parent / "allowed-sibling")):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text), "deny")

    def test_advisory_modes_and_confirm_semantics_are_retained(self):
        security.security_policy["denylist"] = ["printf"]
        for mode in ("off", "warn"):
            security.security_policy["mode"] = mode
            self.assertEqual(self.decide("printf x", score=100), "allow")
        security.security_policy.update(mode="confirm", denylist=[])
        self.assertEqual(self.decide("printf x", score=100), "confirm")
        self.assertEqual(self.decide("printf x", hits=[("rule", "high", "reason")]), "confirm")

    def test_admin_exemptions_are_single_nonredirected_and_preview_safe(self):
        security.security_policy["mode"] = "dry-run"
        for text in ("security", "security mode warn", "pwd", "audit 2", "help", "exit"):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text, administrative=True), "allow")
        for text in ("security reset", "security save", "security load", "deny printf", "export X=x",
                     "unset X", "cd /", "suspicious-clear", "audit clear", "audit CLEAR",
                     "pwd > output", "pwd | printf x", "printf x"):
            with self.subTest(text=text):
                self.assertEqual(self.decide(text, administrative=True), "deny")
        self.assertEqual(self.decide("pwd"), "deny")

    def test_saved_policy_is_private_atomic_and_preserves_shared_identity(self):
        shared = security.security_policy
        security.security_policy.update(mode="allowlist", allowlist=["printf"], risk_threshold=45)
        security.security_policy["resource_limits"]["cpu_seconds"] = 9
        self.assertTrue(security.save_policy_to_disk())
        target = self.home / "policy.json"
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        old_inode = target.stat().st_ino
        security.security_policy["risk_threshold"] = 46
        self.assertTrue(security.save_policy_to_disk())
        self.assertNotEqual(old_inode, target.stat().st_ino)
        security.security_policy.update(mode="off", allowlist=[])
        self.assertTrue(security.load_policy_from_disk())
        self.assertIs(shared, security.security_policy)
        self.assertEqual(shared["mode"], "allowlist")
        self.assertEqual(shared["allowlist"], ["printf"])
        self.assertEqual(shared["risk_threshold"], 46)
        self.assertEqual(shared["resource_limits"]["cpu_seconds"], 9)
        self.assertEqual(self.decide("unknown-command"), "deny")

    def test_invalid_loads_do_not_partially_mutate_or_fall_back(self):
        invalid = ([], None, {"mode": "typo"}, {"risk_threshold": "70"}, {"risk_threshold": True},
                   {"risk_threshold": 101}, {"block_on_suspicious": 1},
                   {"suspicious_min_severity": []}, {"allowlist": [{}]}, {"denylist": [""]},
                   {"resource_limits": []}, {"resource_limits": {"enabled": "yes"}},
                   {"resource_limits": {"cpu_seconds": -1}}, {"resource_limits": {"typo": 1}},
                   {"command_rules": []}, {"command_rules": {"printf": {"typo": []}}},
                   {"command_rules": {"printf": {"output_roots": ["relative"]}}},
                   {"command_rules": {"printf": {"allowed_args": "bad"}}},
                   {"schema_version": 2}, {"unknown": 1})
        before = copy.deepcopy(security.security_policy)
        for value in invalid:
            (self.home / "policy.json").write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(ValueError):
                security.load_policy_from_disk()
            self.assertEqual(security.security_policy, before)
        (self.home / "policy.json").write_text("{not JSON", encoding="utf-8")
        with self.assertRaises(ValueError):
            security.load_policy_from_disk()
        self.assertEqual(security.security_policy, before)

    def test_missing_and_unsafe_policy_paths_are_distinct(self):
        self.assertFalse(security.load_policy_from_disk())
        victim = self.home / "victim"
        victim.write_text("untouched", encoding="utf-8")
        (self.home / "policy.json").symlink_to(victim)
        with self.assertRaises(OSError):
            security.load_policy_from_disk()
        with redirect_stderr(io.StringIO()) as errors:
            self.assertFalse(security.save_policy_to_disk())
        self.assertIn("could not save policy", errors.getvalue())
        self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")

    def test_failed_atomic_replace_keeps_old_policy(self):
        self.assertTrue(security.save_policy_to_disk())
        original = (self.home / "policy.json").read_text(encoding="utf-8")
        security.security_policy["mode"] = "off"
        with patch("argus.storage.os.replace", side_effect=OSError("replace failed")), redirect_stderr(io.StringIO()):
            self.assertFalse(security.save_policy_to_disk())
        self.assertEqual((self.home / "policy.json").read_text(encoding="utf-8"), original)
        self.assertEqual(sorted(item.name for item in self.home.iterdir()), ["policy.json"])


class SuspiciousTests(unittest.TestCase):
    def setUp(self):
        self.old_buffer = list(suspicious.suspicious_buffer)
        self.old_cooldowns = dict(suspicious.suspicious_cooldowns)
        suspicious.reset_suspicious_state()
        self.addCleanup(self.restore_state)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = str(Path(self.temporary.name) / "events.db")
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("""CREATE TABLE suspicious_events (
                id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, cwd TEXT,
                session_id TEXT, rule_name TEXT, severity TEXT, reason TEXT,
                matched_command TEXT, context TEXT)""")
        self.connection_patch = patch.object(suspicious, "get_database_connection", lambda: sqlite3.connect(self.db))
        self.connection_patch.start()
        self.addCleanup(self.connection_patch.stop)
        self.now = 1000.0
        self.clock_patch = patch.object(suspicious.time, "monotonic", lambda: self.now)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

    def restore_state(self):
        suspicious.suspicious_buffer.clear()
        suspicious.suspicious_buffer.extend(self.old_buffer)
        suspicious.suspicious_cooldowns.clear()
        suspicious.suspicious_cooldowns.update(self.old_cooldowns)

    def detect(self, text):
        with redirect_stdout(io.StringIO()):
            result = suspicious.detect_suspicious(text)
        self.now += 1
        return result

    def test_sequence_completes_on_current_input_not_following_input(self):
        self.assertNotIn("download_then_exec", [hit[0] for hit in self.detect("curl example")])
        self.assertNotIn("download_then_exec", [hit[0] for hit in self.detect("chmod +x payload")])
        self.assertIn("download_then_exec", [hit[0] for hit in self.detect("./payload")])
        self.assertNotIn("download_then_exec", [hit[0] for hit in self.detect("printf unrelated")])
        with closing(sqlite3.connect(self.db)) as connection:
            rows = connection.execute("SELECT matched_command, context FROM suspicious_events WHERE rule_name='download_then_exec'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "./payload")
        self.assertEqual(rows[0][1].splitlines(), ["curl example", "chmod +x payload", "./payload"])

    def test_rule_specific_sequence_window_is_respected(self):
        rule = ("short", "high", [re.compile("first"), re.compile("last")], 2, "short window")
        with patch.object(suspicious, "SUSPICIOUS_SEQUENCE_RULES", [rule]):
            self.detect("first")
            self.now += 3
            self.assertNotIn("short", [hit[0] for hit in self.detect("last")])

    def test_pure_analysis_leaves_context_cooldowns_and_database_unchanged(self):
        self.detect("curl example")
        self.detect("chmod +x payload")
        before_buffer = list(suspicious.suspicious_buffer)
        before_cooldowns = dict(suspicious.suspicious_cooldowns)
        with patch.object(suspicious, "get_database_connection", side_effect=AssertionError("analysis wrote database")), redirect_stdout(io.StringIO()) as output:
            first = suspicious.analyze_suspicious("./payload")
            second = suspicious.analyze_suspicious("./payload")
        self.assertEqual(first, second)
        self.assertIn("download_then_exec", [hit[0] for hit in first])
        self.assertEqual(list(suspicious.suspicious_buffer), before_buffer)
        self.assertEqual(suspicious.suspicious_cooldowns, before_cooldowns)
        self.assertEqual(output.getvalue(), "")
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM suspicious_events").fetchone()[0], 0)

    def test_command_local_hits_and_cooldown_do_not_hide_decision(self):
        self.assertIn("obfuscated_shell", [hit[0] for hit in self.detect("printf 'base64 -d'")])
        self.assertIn("obfuscated_shell", [hit[0] for hit in self.detect("printf 'base64 -d'")])
        self.assertEqual(self.detect("printf harmless"), [])
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM suspicious_events WHERE rule_name='obfuscated_shell'").fetchone()[0], 1)

    def test_repetition_counts_current_input_once(self):
        for _ in range(suspicious.SUSPICIOUS_REPEAT_COUNT - 1):
            self.assertNotIn("rapid_repetition", [hit[0] for hit in self.detect("printf repeated")])
        self.assertIn("rapid_repetition", [hit[0] for hit in self.detect("printf repeated")])

    def test_persistence_failure_is_visible_and_metadata_is_terminal_safe(self):
        pattern = ("rule\x1b[2J", "high", re.compile("trigger"), "reason\x1b[2J")
        with patch.object(suspicious, "SUSPICIOUS_PATTERNS", [pattern]), patch.object(suspicious, "get_database_connection", side_effect=sqlite3.OperationalError("locked")), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            hits = suspicious.detect_suspicious("trigger")
        self.assertTrue(hits)
        self.assertIn("could not persist suspicious event", errors.getvalue())
        self.assertNotIn("reason\x1b[2J", output.getvalue())
        self.assertNotIn("rule\x1b[2J", output.getvalue())


class ResourceTests(unittest.TestCase):
    def test_disabled_limits_do_not_apply_anything(self):
        with patch.object(resource, "HAVE_RESOURCE", False):
            resource.apply_resource_limits({"resource_limits": {"enabled": False}})

    def test_unavailable_requested_limits_are_visible_and_fatal(self):
        with patch.object(resource, "HAVE_RESOURCE", False), redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(resource.ResourceLimitError):
                resource.apply_resource_limits({"resource_limits": {"enabled": True}})
        self.assertIn("child resource setup failed", errors.getvalue())

    @unittest.skipUnless(resource.HAVE_RESOURCE, "requires Unix resource module")
    def test_one_failed_requested_limit_aborts_setup_instead_of_silently_continuing(self):
        limits = copy.deepcopy(DEFAULT_SECURITY_POLICY["resource_limits"])
        limits["enabled"] = True
        with patch.object(resource.resource, "setrlimit", side_effect=OSError("permission denied")) as setter, redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(resource.ResourceLimitError):
                resource.apply_resource_limits({"resource_limits": limits})
        self.assertEqual(setter.call_count, 1)
        self.assertIn("cpu_seconds", errors.getvalue())

    @unittest.skipUnless(resource.HAVE_RESOURCE, "requires Unix resource module")
    def test_all_limits_are_validated_before_setting_any_hard_limit(self):
        for invalid in (-1, True, "10", 2**31):
            limits = {"enabled": True, "cpu_seconds": 1, "open_files": invalid}
            with self.subTest(invalid=invalid), patch.object(
                    resource.resource, "setrlimit") as setter, redirect_stderr(io.StringIO()):
                with self.assertRaises(resource.ResourceLimitError):
                    resource.apply_resource_limits({"resource_limits": limits})
                setter.assert_not_called()

    @unittest.skipUnless(resource.HAVE_RESOURCE, "requires Unix resource module")
    def test_effective_requested_values_and_explicit_nproc_opt_in(self):
        limits = {"enabled": True, "cpu_seconds": 2, "memory_mb": 3,
                  "max_processes": 0, "file_size_mb": 4, "open_files": 5}
        applied = []
        with patch.object(resource.resource, "setrlimit", lambda kind, values: applied.append((kind, values))):
            resource.apply_resource_limits({"resource_limits": limits})
        self.assertEqual(applied, [(resource.resource.RLIMIT_CPU, (2, 2)),
                                   (resource.resource.RLIMIT_AS, (3 * 1024**2, 3 * 1024**2)),
                                   (resource.resource.RLIMIT_FSIZE, (4 * 1024**2, 4 * 1024**2)),
                                   (resource.resource.RLIMIT_NOFILE, (5, 5))])


if __name__ == "__main__":
    unittest.main()
