"""
Database operations for Argus command audit and suspicious event tracking.
"""

import os
import sqlite3
from .config import ARGUS_DATA_DIR, ARGUS_DATABASE, get_settings
from .storage import private_directory, open_private, storage_warning


def initialize_argus_data_directory():
    """Reject unsafe pre-existing storage rather than trusting its permissions."""
    private_directory(ARGUS_DATA_DIR)


def get_database_connection():
    """Open private local storage with bounded lock waiting."""
    try:
        initialize_argus_data_directory()
        fd = open_private(ARGUS_DATABASE)
        os.close(fd)
        connection = sqlite3.connect(ARGUS_DATABASE, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except OSError as error:
        raise sqlite3.OperationalError(str(error)) from error


def prune_records(connection, table, limit=None):
    """Apply configurable count/age retention, never deleting unfinished starts."""
    if table not in {"command_audit", "command_events", "suspicious_events", "security_actions"}:
        raise ValueError("unsupported retention table")
    settings = get_settings()
    limit = settings["retention_records"] if limit is None else limit
    if type(limit) is not int or limit < 0:
        raise ValueError("retention limit must be nonnegative")
    active = "state NOT IN ('running', 'stopped')" if table == "command_audit" else "1=1"
    if limit:
        connection.execute(
            f"DELETE FROM {table} WHERE id < "
            f"(SELECT id FROM {table} WHERE {active} ORDER BY id DESC LIMIT 1 OFFSET ?)"
            f" AND {active}", (limit - 1,),
        )
    days = settings["retention_days"]
    if days:
        connection.execute(
            f"DELETE FROM {table} WHERE julianday(timestamp) < julianday('now', ?) AND {active}",
            (f"-{days} days",),
        )


def initialize_database():
    """Initialize the database tables and indexes."""
    try:
        initialize_argus_data_directory()
        connection = get_database_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS command_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                cwd TEXT NOT NULL,
                command TEXT NOT NULL,
                command_name TEXT,
                pid INTEGER,
                background INTEGER NOT NULL DEFAULT 0,
                exit_status INTEGER,
                duration_ms REAL,
                command_type TEXT,
                job_id INTEGER
            )
            """
        )

        existing_columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(command_audit)"
            ).fetchall()
        }

        if "risk_score" not in existing_columns:
            cursor.execute(
                "ALTER TABLE command_audit ADD COLUMN risk_score INTEGER"
            )

        if "risk_reasons" not in existing_columns:
            cursor.execute(
                "ALTER TABLE command_audit ADD COLUMN risk_reasons TEXT"
            )

        if "security_action" not in existing_columns:
            cursor.execute(
                "ALTER TABLE command_audit ADD COLUMN security_action TEXT"
            )

        audit_columns = {
            "state": "TEXT NOT NULL DEFAULT 'completed'",
            "completed_at": "TEXT",
            "session_id": "TEXT",
            "uid": "INTEGER",
            "euid": "INTEGER",
            "sid": "TEXT",
        }
        for name, declaration in audit_columns.items():
            if name not in existing_columns:
                cursor.execute(f"ALTER TABLE command_audit ADD COLUMN {name} {declaration}")
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS command_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id INTEGER NOT NULL REFERENCES command_audit(id) ON DELETE CASCADE,
                timestamp TEXT NOT NULL,
                state TEXT NOT NULL,
                exit_status INTEGER
            )"""
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_command_audit_timestamp
            ON command_audit(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_command_audit_command_name
            ON command_audit(command_name)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_command_audit_username
            ON command_audit(username)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_command_audit_risk_score
            ON command_audit(risk_score)
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS suspicious_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                cwd TEXT NOT NULL,
                session_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                matched_command TEXT NOT NULL,
                context TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_suspicious_events_timestamp
            ON suspicious_events(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_suspicious_events_severity
            ON suspicious_events(severity)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_suspicious_events_rule
            ON suspicious_events(rule_name)
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                cwd TEXT NOT NULL,
                session_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL,
                command TEXT NOT NULL,
                risk_score INTEGER,
                suspicious_rules TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_actions_timestamp
            ON security_actions(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_actions_action
            ON security_actions(action)
            """
        )

        for table in ("command_audit", "command_events", "suspicious_events", "security_actions"):
            prune_records(connection, table)
        connection.commit()
        return True
    except (sqlite3.Error, OSError) as error:
        storage_warning("database initialization failed", error)
        return False
    finally:
        if "connection" in locals():
            connection.close()
