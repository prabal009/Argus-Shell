"""
Command audit logging and database operations.
"""

import os
import sqlite3
import json
from pathlib import Path
import tempfile
from datetime import datetime
from contextlib import closing
from .colors import BRIGHT_RED, BRIGHT_GREEN, BRIGHT_BLACK, BRIGHT_YELLOW, BRIGHT_BLUE, BRIGHT_CYAN, BRIGHT_PURPLE, BRIGHT_WHITE, BOLD, RESET
from .database import get_database_connection, prune_records
from .risk import score_command, risk_color
from .utils import get_timestamp, get_identity, get_current_directory, get_command_name, SESSION_ID, safe_text, redact_text
from .storage import storage_warning
from .config import get_settings, ARGUS_DATA_DIR


def _signed_event(record):
    settings = get_settings()
    if not settings["audit_sign"]:
        return
    try:
        from .integrity import append_record
        from .storage import private_directory
        path = settings["audit_chain"]
        private_directory(os.path.dirname(path))
        append_record(path, record)
    except (OSError, ValueError, RuntimeError) as error:
        storage_warning("signed audit append failed", error)


def audit_command(
    command, command_name=None, pid=None, background=False, exit_status=None,
    duration_ms=None, command_type=None, job_id=None, cwd=None,
    risk_score=None, risk_reasons=None, security_action=None, state=None,
):
    """Persist a command start/outcome. Failure is visible and best-effort."""
    if not command:
        return None
    identity = get_identity()
    if risk_score is None:
        risk_score, computed = score_command(command)
        if risk_reasons is None:
            risk_reasons = computed
    state = state or ("running" if exit_status is None else "completed")
    timestamp = get_timestamp()
    try:
        with closing(get_database_connection()) as connection, connection:
            cursor = connection.execute(
                """INSERT INTO command_audit (
                    timestamp, username, cwd, command, command_name, pid, background,
                    exit_status, duration_ms, command_type, job_id, risk_score,
                    risk_reasons, security_action, state, completed_at, session_id, uid, euid, sid
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (timestamp, identity["username"], cwd or get_current_directory(),
                 redact_text(command), command_name or get_command_name(command.split()),
                 pid if pid is not None else os.getpid(), int(background), exit_status,
                 duration_ms, command_type, job_id, risk_score,
                 " | ".join(risk_reasons or []), security_action, state,
                 timestamp if state not in ("running", "stopped") else None,
                 SESSION_ID, identity["uid"], identity["euid"], identity.get("sid")),
            )
            audit_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO command_events(audit_id,timestamp,state,exit_status) VALUES(?,?,?,?)",
                (audit_id, timestamp, state, exit_status),
            )
            prune_records(connection, "command_audit")
            prune_records(connection, "command_events")
        _signed_event({"event": "command", "audit_id": audit_id, "timestamp": timestamp,
                       "session_id": SESSION_ID, "identity": identity,
                       "command": redact_text(command), "state": state,
                       "risk_score": risk_score, "exit_status": exit_status})
        return audit_id
    except (sqlite3.Error, OSError) as error:
        storage_warning("command audit write failed", error)
        return None


def update_audit(audit_id, *, exit_status=None, duration_ms=None, state="completed", pid=None, job_id=None):
    """Update the same command and append a separate lifecycle event."""
    if audit_id is None:
        return False
    timestamp = get_timestamp()
    try:
        with closing(get_database_connection()) as connection, connection:
            result = connection.execute(
                """UPDATE command_audit SET exit_status=?, duration_ms=?, state=?,
                    completed_at=?, pid=COALESCE(?,pid), job_id=COALESCE(?,job_id)
                    WHERE id=?""",
                (exit_status, duration_ms, state,
                 timestamp if state not in ("running", "stopped") else None,
                 pid, job_id, audit_id),
            )
            if result.rowcount != 1:
                raise sqlite3.DatabaseError("command start record is missing")
            connection.execute(
                "INSERT INTO command_events(audit_id,timestamp,state,exit_status) VALUES(?,?,?,?)",
                (audit_id, timestamp, state, exit_status),
            )
            prune_records(connection, "command_events")
            if state not in ("running", "stopped"):
                prune_records(connection, "command_audit")
        _signed_event({"event": "lifecycle", "audit_id": audit_id, "timestamp": timestamp,
                       "session_id": SESSION_ID, "state": state, "exit_status": exit_status,
                       "duration_ms": duration_ms})
        return True
    except (sqlite3.Error, OSError) as error:
        storage_warning("command lifecycle write failed", error)
        return False


def print_audit_row(row):
    """Print a formatted audit log row."""
    audit_id = row["id"]
    timestamp = row["timestamp"]
    command = safe_text(row["command"])
    status = row["exit_status"]
    duration = row["duration_ms"]
    background = row["background"]

    try:
        stored_risk = row["risk_score"]
    except (IndexError, KeyError):
        stored_risk = None

    if stored_risk is None:
        computed_risk, _ = score_command(command)
        stored_risk = computed_risk

    try:
        security_action = row["security_action"]
    except (IndexError, KeyError):
        security_action = None

    risk_display_color = risk_color(stored_risk)

    if status is None:
        status_text = "RUN"
        status_color = BRIGHT_YELLOW
    elif status == 0:
        status_text = "OK"
        status_color = BRIGHT_GREEN
    else:
        status_text = str(status)
        status_color = BRIGHT_RED

    bg_text = "BG" if background else "FG"

    if duration is None:
        duration_text = "-"
    else:
        duration_text = f"{duration:.2f}ms"

    if len(command) > 40:
        command = command[:37] + "..."

    if security_action:
        sec_text = security_action[:6]
    else:
        sec_text = "-"

    print(
        f"{BRIGHT_CYAN}{audit_id:5}{RESET}"
        " "
        f"{BRIGHT_BLACK}{safe_text(timestamp)}{RESET}"
        " "
        f"{BRIGHT_WHITE}{command:<40}{RESET}"
        " "
        f"{status_color}{status_text:<4}{RESET}"
        " "
        f"{duration_text:<12}"
        " "
        f"{bg_text:<2}"
        " "
        f"{risk_display_color}{stored_risk:>3}{RESET}"
        " "
        f"{BRIGHT_BLUE}{sec_text}{RESET}"
    )


def print_audit_header():
    """Print the audit log header."""
    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS AUDIT LOG{RESET}")
    print()
    print(
        f"{BRIGHT_BLACK}"
        " ID    TIMESTAMP                 "
        "COMMAND                                  "
        "STAT DURATION      MODE RISK SEC"
        f"{RESET}"
    )
    print(f"{BRIGHT_BLACK}{'─' * 112}{RESET}")


def archive_records(destination=None, *, since=None, until=None, encrypted=None, key_id="default"):
    """Export a consistent database snapshot; encryption requires a secure keyring."""
    from .storage import atomic_write, private_directory
    settings = get_settings()
    if encrypted is None:
        encrypted = settings["archive_encrypted"]
    if destination is None:
        private_directory(settings["archive_dir"])
        destination = os.path.join(settings["archive_dir"], datetime.now().strftime("audit-%Y%m%d-%H%M%S") + (".aesgcm" if encrypted else ".json"))
    destination = os.path.abspath(destination)
    private_directory(os.path.dirname(destination))
    constraints, values = [], []
    for value, operator in ((since, ">="), (until, "<=")):
        if value is not None:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            constraints.append("julianday(timestamp) " + operator + " julianday(?)")
            values.append(value)
    archive = {"schema_version": 1, "created_at": get_timestamp(), "tables": {}}
    with closing(get_database_connection()) as connection, connection:
        connection.execute("BEGIN")
        for table in ("command_audit", "command_events", "suspicious_events", "security_actions"):
            query = "SELECT * FROM " + table + (" WHERE " + " AND ".join(constraints) if constraints else "") + " ORDER BY id"
            archive["tables"][table] = [dict(row) for row in connection.execute(query, values)]
    content = json.dumps(archive, ensure_ascii=False, indent=2) + "\n"
    if not encrypted:
        atomic_write(destination, content)
    else:
        from .integrity import encrypt_archive
        fd, temporary = tempfile.mkstemp(prefix="archive-", suffix=".json", dir=ARGUS_DATA_DIR)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            encrypt_archive(temporary, destination, key_id=key_id)
        finally:
            os.unlink(temporary)
    return {"path": destination, "encrypted": bool(encrypted),
            "counts": {table: len(rows) for table, rows in archive["tables"].items()}}
