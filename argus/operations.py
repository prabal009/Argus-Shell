"""Bound queries/exports and user-owned settings and operating-system vault access."""

import csv
import getpass
import json
import re
import sqlite3
import sys
from contextlib import closing
from datetime import datetime

from .database import get_database_connection
from .utils import redact_text, safe_text

_RUNTIME = None
_SESSION = None
_TABLES = {"audit": "command_audit", "suspicious": "suspicious_events",
           "security-actions": "security_actions"}


def configure_runtime(runtime, session=None):
    global _RUNTIME, _SESSION
    _RUNTIME, _SESSION = runtime, session


def _error(error):
    print("Argus: " + safe_text(redact_text(error)), file=sys.stderr)
    return 1


def parse_query_options(args):
    """Parse composable query options; values never become SQL syntax."""
    options = {"limit": 20, "offset": 0, "format": "table"}
    accepted = {"session", "cwd", "since", "until", "severity", "risk", "limit",
                "offset", "format", "search", "detail"}
    index, seen = 0, set()
    while index < len(args):
        name = args[index]
        if not name.startswith("--") or name[2:] not in accepted or index + 1 >= len(args):
            raise ValueError("expected --session/--cwd/--since/--until/--severity/--risk/--limit/--offset/--format/--search/--detail VALUE")
        key, value = name[2:], args[index + 1]
        if key in seen:
            raise ValueError("duplicate filter: " + name)
        seen.add(key)
        if key in {"risk", "limit", "offset", "detail"}:
            try:
                value = int(value)
            except ValueError as error:
                raise ValueError(name + " requires an integer") from error
            if value < 0 or (key == "risk" and value > 100) or (key == "limit" and not 1 <= value <= 10000) or (key == "detail" and value == 0):
                raise ValueError("invalid " + name)
        if key in {"since", "until"}:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        if key == "severity" and value not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid severity")
        if key == "format" and value not in {"table", "json", "csv"}:
            raise ValueError("format must be table, json or csv")
        options[key] = value
        index += 2
    return options


def _query_source(kind):
    table = _TABLES[kind]
    command = "matched_command" if kind == "suspicious" else "command"
    if kind == "suspicious":
        risk = "COALESCE((SELECT MAX(a.risk_score) FROM command_audit a WHERE a.session_id=t.session_id AND a.cwd=t.cwd AND a.command=t.matched_command), 0)"
        severity = "t.severity"
    else:
        risk = "COALESCE(t.risk_score, 0)"
        severity = "(SELECT e.severity FROM suspicious_events e WHERE e.session_id=t.session_id AND e.cwd=t.cwd AND e.matched_command=t.command ORDER BY CASE e.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC LIMIT 1)"
    return f"SELECT t.*, {risk} AS query_risk, {severity} AS query_severity, t.{command} AS query_command FROM {table} t"


def query_records(kind, options=None, *, connect=None):
    """Return full records including shared query risk/severity metadata.

    Event risk/severity associations use exact session/cwd/command equality,
    never a cross-session fuzzy match. Unassociated event risk is zero.
    """
    if kind not in _TABLES:
        raise ValueError("unknown record kind")
    options = dict(options or {})
    unknown = options.keys() - {"session", "cwd", "since", "until", "severity", "risk", "limit", "offset", "format", "search", "detail"}
    if unknown:
        raise ValueError("unknown query options")
    # Reuse CLI validation for programmatic consumers too.
    validated = parse_query_options([part for key, value in options.items()
                                     for part in ("--" + key, str(value))])
    clauses, parameters = [], []
    fields = {"session": "session_id", "cwd": "cwd", "since": "timestamp",
              "until": "timestamp", "severity": "query_severity", "risk": "query_risk",
              "detail": "id"}
    for key, field in fields.items():
        if key in validated:
            operator = ">=" if key in {"since", "risk"} else "<=" if key == "until" else "="
            clauses.append((f"julianday({field}) {operator} julianday(?)"
                            if key in {"since", "until"} else field + " " + operator + " ?"))
            parameters.append(validated[key])
    if "search" in validated:
        # A search is literal text, not caller-controlled LIKE wildcards.
        escaped = validated["search"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(query_command LIKE ? ESCAPE '\\' OR cwd LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')")
        parameters.extend(["%" + escaped + "%"] * 3)
    sql = "SELECT * FROM (" + _query_source(kind) + ")"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    parameters.extend((validated["limit"], validated["offset"]))
    with closing((connect or get_database_connection)()) as connection:
        cursor = connection.execute(sql, parameters)
        columns = [item[0] for item in cursor.description]
        records = [dict(zip(columns, row)) for row in cursor.fetchall()]
        if kind == "audit" and "detail" in validated:
            for record in records:
                events = connection.execute("SELECT * FROM command_events WHERE audit_id=? ORDER BY id", (record["id"],))
                event_columns = [item[0] for item in events.description]
                record["events"] = [dict(zip(event_columns, row)) for row in events.fetchall()]
            columns.append("events")
    return columns, records


def render_records(kind, columns, records, format="table", *, stream=None):
    stream = stream or sys.stdout
    # Redact at the export boundary as well as on insertion (rules may change).
    def clean(value):
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()}
        return value
    records = clean(records)
    if format == "json":
        print(json.dumps({"schema_version": 1, "kind": kind, "columns": columns,
                          "records": records}, ensure_ascii=True), file=stream)
    elif format == "csv":
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(columns)
        for record in records:
            values = []
            for column in columns:
                value = record.get(column)
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=True)
                if isinstance(value, str):
                    value = safe_text(value)
                    # Prevent spreadsheet formulas when exported data is opened.
                    if value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                values.append(value)
            writer.writerow(values)
    elif format == "table":
        print(" | ".join(columns), file=stream)
        for record in records:
            print(" | ".join(safe_text(json.dumps(record.get(column), ensure_ascii=True))
                             if isinstance(record.get(column), (dict, list)) else
                             safe_text("" if record.get(column) is None else record[column])
                             for column in columns), file=stream)
    else:
        raise ValueError("unknown export format")


def builtin_query(args, *, connect=None):
    try:
        kind = args[0]
        options = parse_query_options(args[1:])
        columns, records = query_records(kind, options, connect=connect)
        render_records(kind, columns, records, options["format"])
        return 0
    except (ValueError, OSError, sqlite3.Error) as error:
        return _error(error)


def builtin_security_actions(args):
    return builtin_query(args)


def builtin_settings(args):
    from . import config
    try:
        settings = config.get_settings()
        if len(args) == 1 or args[1:] == ["list"]:
            print(json.dumps(settings, ensure_ascii=True, indent=2))
        elif len(args) == 3 and args[1] == "get":
            print(json.dumps(settings[args[2]], ensure_ascii=True))
        elif len(args) == 4 and args[1] == "set":
            candidate = dict(settings)
            if args[2] not in candidate:
                raise ValueError("unknown setting")
            candidate[args[2]] = json.loads(args[3])
            if config.save_settings(candidate) is False:
                raise ValueError("settings were not saved")
            if _SESSION is not None:
                active = config.get_settings()
                history = _SESSION.history
                history.set_private(active["history_private"])
                history.ignore = list(active["history_ignore"])
        else:
            raise ValueError("usage: settings [list|get NAME|set NAME JSON]")
        return 0
    except (KeyError, ValueError, OSError) as error:
        return _error(error)


def builtin_redaction(args):
    from . import config
    try:
        settings = config.get_settings()
        patterns = list(settings["redaction_patterns"])
        if len(args) == 1 or args[1:] == ["list"]:
            for number, pattern in enumerate(patterns, 1):
                print(str(number) + " " + safe_text(pattern))
            return 0
        if len(args) == 3 and args[1] == "add":
            re.compile(args[2])
            if args[2] not in patterns:
                patterns.append(args[2])
        elif len(args) == 3 and args[1] == "remove":
            number = int(args[2])
            if not 1 <= number <= len(patterns):
                raise ValueError("pattern number out of range")
            del patterns[number - 1]
        elif len(args) == 2 and args[1] == "test":
            print(safe_text(redact_text(getpass.getpass("Text to test (hidden): "))))
            return 0
        else:
            raise ValueError("usage: redaction [list|add REGEX|remove NUMBER|test]")
        candidate = dict(settings, redaction_patterns=patterns)
        if config.save_settings(candidate) is False:
            raise ValueError("patterns were not saved")
        return 0
    except (ValueError, OSError, re.error, EOFError) as error:
        return _error(error)


_VAULT_SERVICE = "argus-shell"
_VAULT_INDEX = "__argus_vault_index__"


def _keyring():
    import keyring
    backend = keyring.get_keyring()
    # keyrings.alt plaintext and fail/null backends are not a secret vault.
    def trusted(candidate):
        module = type(candidate).__module__.lower()
        if module == "keyring.backends.chainer":
            children = list(candidate.backends)
            return bool(children) and all(trusted(child) for child in children)
        secure_modules = {"keyring.backends.secretservice", "keyring.backends.kwallet",
                          "keyring.backends.macos", "keyring.backends.windows",
                          "keyring.backends.libsecret"}
        return module in secure_modules and getattr(candidate, "priority", 0) > 0
    if not trusted(backend):
        raise RuntimeError("no secure OS keyring backend available; no plaintext fallback")
    return keyring


def builtin_vault(args):
    from .utils import register_secret
    try:
        if len(args) < 2:
            raise ValueError("usage: vault set|get|delete NAME; vault list; vault env NAME VARIABLE")
        action = args[1]
        expected = 2 if action == "list" else 4 if action == "env" else 3
        if action not in {"set", "get", "delete", "list", "env"} or len(args) != expected:
            raise ValueError("usage: vault set|get|delete NAME; vault list; vault env NAME VARIABLE")
        if action != "list" and (not args[2] or args[2] == _VAULT_INDEX or "\x00" in args[2]):
            raise ValueError("invalid vault name")
        if action == "env" and (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args[3]) or _RUNTIME is None):
            raise ValueError("vault env needs a valid variable and active shell runtime")
        keyring = _keyring()
        encoded = keyring.get_password(_VAULT_SERVICE, _VAULT_INDEX)
        names = json.loads(encoded) if encoded else []
        if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
            raise ValueError("invalid vault index")
        if action == "list":
            for name in sorted(names):
                print(safe_text(name))
        elif action == "set":
            value = getpass.getpass("Secret (hidden): ")
            register_secret(value)
            keyring.set_password(_VAULT_SERVICE, args[2], value)
            if args[2] not in names:
                names.append(args[2])
                keyring.set_password(_VAULT_SERVICE, _VAULT_INDEX, json.dumps(names))
        elif action == "delete":
            keyring.delete_password(_VAULT_SERVICE, args[2])
            names = [name for name in names if name != args[2]]
            keyring.set_password(_VAULT_SERVICE, _VAULT_INDEX, json.dumps(names))
        else:
            value = keyring.get_password(_VAULT_SERVICE, args[2])
            if value is None:
                raise ValueError("vault secret does not exist")
            register_secret(value)
            if action == "get":
                print(value)
            else:
                _RUNTIME.state.variables[args[3]] = value
                _RUNTIME.state.exported.add(args[3])
        return 0
    except (Exception,) as error:
        # Keyring backend-specific errors must be honest failures, not a disk fallback.
        return _error(error)


def builtin_audit_integrity(args):
    """Verify with an explicit external trust input, or archive through audit."""
    from dataclasses import asdict
    from pathlib import Path
    from . import audit, config, integrity
    try:
        action = args[1]
        if action == "verify":
            path = args[2] if len(args) > 2 and not args[2].startswith("--") else config.get_settings()["audit_chain"]
            start = 3 if len(args) > 2 and not args[2].startswith("--") else 2
            options = {}
            for index in range(start, len(args), 2):
                if args[index] not in {"--public-key", "--anchor"} or index + 1 >= len(args):
                    raise ValueError("usage: audit verify [PATH] [--public-key FILE] [--anchor FILE]")
                key, value = args[index], args[index + 1]
                if key in options:
                    raise ValueError("duplicate verification option")
                options[key] = value
            public_key = Path(options["--public-key"]) if "--public-key" in options else None
            anchor = json.loads(Path(options["--anchor"]).read_text(encoding="utf-8")) if "--anchor" in options else None
            result = integrity.verify(path, public_key=public_key, anchor=anchor)
            print(json.dumps(asdict(result), ensure_ascii=True))
            return 0 if result.valid else 1
        if action == "archive" and len(args) >= 3:
            destination = args[2]
            options = {"encrypted": config.get_settings()["archive_encrypted"]}
            index = 3
            while index < len(args):
                name = args[index]
                if name == "--encrypt":
                    options["encrypted"] = True
                    index += 1
                    continue
                if name not in {"--key-id", "--since", "--until"} or index + 1 >= len(args):
                    raise ValueError("usage: audit archive DEST [--encrypt] [--key-id NAME] [--since ISO] [--until ISO]")
                value = args[index + 1]
                if name in {"--since", "--until"}:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                options[name[2:].replace("-", "_")] = value
                index += 2
            metadata = audit.archive_records(destination, **options)
            print(json.dumps(metadata, ensure_ascii=True))
            return 0
        raise ValueError("usage: audit verify [PATH] [--public-key FILE --anchor FILE] | archive DEST [--encrypt --key-id NAME]")
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
        return _error(error)
