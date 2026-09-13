"""
Database operations for Argus command audit and suspicious event tracking.
"""

import os
import sqlite3
from .colors import BRIGHT_RED, RESET
from .config import ARGUS_DATA_DIR, ARGUS_DATABASE


def initialize_argus_data_directory():
    """Create the Argus data directory if it doesn't exist."""
    try:
        os.makedirs(ARGUS_DATA_DIR, mode=0o700, exist_ok=True)
    except OSError as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: could not create data directory: {error}"
            f"{RESET}"
        )


def get_database_connection():
    """Get a database connection with row factory enabled."""
    connection = sqlite3.connect(ARGUS_DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Initialize the database tables and indexes."""
    initialize_argus_data_directory()

    try:
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

        connection.commit()
        connection.close()

    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: database initialization error: {error}"
            f"{RESET}"
        )
