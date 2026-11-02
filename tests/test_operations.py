"""Consumer coverage for filtered exports, live settings, and fail-closed vaults."""

import copy
import csv
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from argus import config, database, operations, utils
from argus.language import ShellRuntime, ShellState


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "records.db"
        with patch.object(database, "initialize_argus_data_directory"), patch.object(
                database, "get_database_connection", self.connect):
            self.assertTrue(database.initialize_database())
        with closing(self.connect()) as connection, connection:
            for ident, session, cwd, command, risk, timestamp in (
                (1, "one", "/work", "printf same", 80, "2026-01-01T12:00:00+02:00"),
                (2, "two", "/work", "printf same", 5, "2026-01-01T10:01:00Z"),
                (3, "one", "/else", "printf same", 90, "2026-01-01T10:02:00Z"),
                (4, "one", "/work", "printf literal%_", 50, "2026-01-01T10:03:00Z"),
            ):
                connection.execute("""INSERT INTO command_audit
                    (id,timestamp,username,cwd,session_id,command,risk_score,state)
                    VALUES (?,?, 'tester',?,?,?,?, 'completed')""",
                    (ident, timestamp, cwd, session, command, risk))
            for session, cwd, command, severity in (
                ("one", "/work", "printf same", "high"),
                ("two", "/work", "printf same", "low"),
                ("one", "/else", "printf same", "critical"),
                ("unassociated", "/work", "printf same", "medium"),
            ):
                connection.execute("""INSERT INTO suspicious_events
                    (timestamp,username,cwd,session_id,rule_name,severity,reason,matched_command)
                    VALUES ('2026-01-01T10:00:00Z','tester',?,?,'rule',?,'reason',?)""",
                    (cwd, session, severity, command))
            connection.execute("""INSERT INTO security_actions
                (timestamp,username,cwd,session_id,mode,action,reason,command,risk_score)
                VALUES ('2026-01-01T10:00:00Z','tester','/work','one','block','deny',
                        'reason','printf same',80)""")
            for state in ("running", "completed"):
                connection.execute("""INSERT INTO command_events(audit_id,timestamp,state)
                    VALUES (1,'2026-01-01T10:00:00Z',?)""", (state,))

    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def query(self, kind, **options):
        return operations.query_records(kind, options, connect=self.connect)

    def test_composable_filters_match_exact_session_cwd_and_time_instants(self):
        columns, records = self.query("audit", session="one", cwd="/work", severity="high",
            risk=70, since="2026-01-01T09:59:00Z", until="2026-01-01T10:00:30Z")
        self.assertEqual([record["id"] for record in records], [1])
        self.assertEqual(records[0]["query_risk"], 80)
        self.assertIn("query_severity", columns)
        self.assertEqual(self.query("audit", session="two", severity="high")[1], [])
        self.assertEqual([row["id"] for row in self.query("audit", limit=1, offset=1)[1]], [3])

    def test_event_and_security_action_queries_preserve_association_boundaries(self):
        rows = self.query("suspicious", session="one", cwd="/work", risk=70, severity="high")[1]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["query_risk"], 80)
        self.assertEqual(self.query("suspicious", session="unassociated", risk=1)[1], [])
        rows = self.query("security-actions", session="one", cwd="/work", severity="high", risk=70)[1]
        self.assertEqual([row["action"] for row in rows], ["deny"])

    def test_search_is_literal_and_query_parameters_cannot_change_sql(self):
        self.assertEqual([row["id"] for row in self.query("audit", search="%_")[1]], [4])
        self.assertEqual(self.query("audit", session="one' OR 1=1 --")[1], [])
        self.assertEqual(len(self.query("audit")[1]), 4)

    def test_detail_export_contains_lifecycle_records(self):
        columns, records = self.query("audit", detail=1)
        output = io.StringIO()
        operations.render_records("audit", columns, records, "json", stream=output)
        document = json.loads(output.getvalue())
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["kind"], "audit")
        self.assertEqual([event["state"] for event in document["records"][0]["events"]],
                         ["running", "completed"])
        self.assertEqual(self.query("audit", detail=99)[1], [])

    def test_export_redacts_nested_values_and_escapes_terminal_and_csv_formulas(self):
        value = "vault-value-unique"
        utils.register_secret(value)
        self.addCleanup(utils.unregister_secret, value)
        records = [{"command": "=formula\x1b[2J " + value, "events": [{"text": value}]}]
        for format in ("json", "csv", "table"):
            output = io.StringIO()
            operations.render_records("audit", ["command", "events"], records, format, stream=output)
            text = output.getvalue()
            self.assertNotIn(value, text)
            self.assertNotIn("\x1b", text)
            self.assertIn("[REDACTED]", text)
            if format == "csv":
                row = list(csv.reader(io.StringIO(text)))[1]
                self.assertTrue(row[0].startswith("'=formula"))
        self.assertIn(value, records[0]["command"])

    def test_invalid_filters_are_rejected_before_opening_storage(self):
        for args in (["--limit", "0"], ["--limit", "1", "--limit", "2"],
                     ["--offset", "-1"], ["--risk", "101"], ["--detail", "0"],
                     ["--since", "not-a-date"], ["--format", "xml"], ["--cwd"]):
            connect = Mock(side_effect=AssertionError("opened storage"))
            with self.subTest(args=args), redirect_stderr(io.StringIO()):
                self.assertNotEqual(operations.builtin_query(["audit", *args], connect=connect), 0)
            connect.assert_not_called()


class SettingsTests(unittest.TestCase):
    def test_saved_settings_reconfigure_active_history_after_success_only(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = copy.deepcopy(config.get_settings())
            history = SimpleNamespace(set_private=Mock(), ignore=[])
            operations.configure_runtime(None, SimpleNamespace(history=history))
            self.addCleanup(operations.configure_runtime, None)
            with patch.object(config, "_settings", settings), patch.object(
                    config, "SETTINGS_FILE", str(Path(directory) / "settings.json")):
                self.assertEqual(operations.builtin_settings(
                    ["settings", "set", "history_private", "true"]), 0)
                history.set_private.assert_called_with(True)
                self.assertTrue(config.get_settings()["history_private"])
                self.assertEqual(operations.builtin_settings(
                    ["settings", "set", "history_ignore", '["private *"]']), 0)
                self.assertEqual(history.ignore, ["private *"])
                before = copy.deepcopy(config.get_settings())
                with redirect_stderr(io.StringIO()):
                    self.assertNotEqual(operations.builtin_settings(
                        ["settings", "set", "history_private", '"yes"']), 0)
                self.assertEqual(config.get_settings(), before)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.runtime = ShellRuntime(lambda *_: 0, state=ShellState(variables={}, exported=set()))
        operations.configure_runtime(self.runtime)
        self.addCleanup(operations.configure_runtime, None)

    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = operations.builtin_vault(["vault", *args])
        return status, output.getvalue(), errors.getvalue()

    def backend(self, module, **attributes):
        return type("Backend", (), {"__module__": module, "priority": 1, **attributes})()

    def test_plaintext_null_unknown_and_insecure_chainers_fail_closed(self):
        import keyring
        secure = self.backend("keyring.backends.SecretService")
        insecure = self.backend("keyrings.alt.file")
        for backend in (insecure, self.backend("keyring.backends.fail"),
                        self.backend("keyring.backends.null"), self.backend("custom.plaintext"),
                        self.backend("keyring.backends.chainer", backends=[]),
                        self.backend("keyring.backends.chainer", backends=[secure, insecure])):
            with self.subTest(backend=type(backend).__module__), patch.object(
                    keyring, "get_keyring", return_value=backend), patch.object(
                    keyring, "get_password") as getter, patch.object(
                    keyring, "set_password") as setter, patch.object(
                    operations.getpass, "getpass") as prompt:
                status, output, errors = self.invoke("set", "service")
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
                self.assertTrue(errors)
                getter.assert_not_called()
                setter.assert_not_called()
                prompt.assert_not_called()

    def test_backend_failures_are_visible_and_never_mutate_environment(self):
        import keyring
        with patch.object(keyring, "get_keyring", return_value=self.backend("keyring.backends.SecretService")), patch.object(
                keyring, "get_password", side_effect=RuntimeError("keyring locked")):
            status, output, errors = self.invoke("env", "service", "CREDENTIAL")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")
        self.assertIn("keyring locked", errors)
        self.assertNotIn("CREDENTIAL", self.runtime.state.variables)

    def test_vault_crud_and_export_use_only_keyring_and_shell_state(self):
        values = {}
        ring = SimpleNamespace(
            get_password=lambda service, name: values.get((service, name)),
            set_password=lambda service, name, value: values.__setitem__((service, name), value),
            delete_password=lambda service, name: values.pop((service, name)))
        secret = "test-vault-credential-unique"
        self.addCleanup(utils.unregister_secret, secret)
        with patch.object(operations, "_keyring", return_value=ring), patch.object(
                operations.getpass, "getpass", return_value=secret):
            self.assertEqual(self.invoke("set", "service")[0], 0)
            self.assertEqual(self.invoke("list")[:2], (0, "service\n"))
            self.assertEqual(self.invoke("get", "service")[:2], (0, secret + "\n"))
            self.assertEqual(self.invoke("env", "service", "CREDENTIAL")[0], 0)
            self.assertEqual(self.runtime.state.environment()["CREDENTIAL"], secret)
            self.assertEqual(self.invoke("delete", "service")[0], 0)
            self.assertEqual(self.invoke("list")[:2], (0, ""))
            self.assertNotEqual(self.invoke("get", "service")[0], 0)

    def test_secret_is_redacted_when_backend_write_fails(self):
        secret = "failing-vault-credential-unique"
        self.addCleanup(utils.unregister_secret, secret)
        ring = SimpleNamespace(get_password=lambda *_: None,
            set_password=Mock(side_effect=RuntimeError("could not save " + secret)))
        with patch.object(operations, "_keyring", return_value=ring), patch.object(
                operations.getpass, "getpass", return_value=secret):
            status, output, errors = self.invoke("set", "service")
        self.assertNotEqual(status, 0)
        self.assertNotIn(secret, output + errors)
        self.assertIn("[REDACTED]", errors)


if __name__ == "__main__":
    unittest.main()
