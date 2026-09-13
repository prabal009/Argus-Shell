"""
Command audit logging and database operations.
"""

import os
import sqlite3
from .colors import BRIGHT_RED, BRIGHT_GREEN, BRIGHT_BLACK, BRIGHT_YELLOW, BRIGHT_BLUE, BRIGHT_CYAN, BRIGHT_PURPLE, BOLD, RESET
from .config import RISK_MAX
from .database import get_database_connection
from .risk import score_command, risk_color
from .utils import get_timestamp, get_current_username, get_current_directory, get_command_name


def audit_command(
    command,
    command_name=None,
    pid=None,
    background=False,
    exit_status=None,
    duration_ms=None,
    command_type=None,
    job_id=None,
    cwd=None,
    risk_score=None,
    risk_reasons=None,
    security_action=None
):
    """Log a command to the audit database."""
    if not command:
        return

    if command_name is None:
        command_name = get_command_name(command.split())

    if pid is None:
        pid = os.getpid()

    if cwd is None:
        cwd = get_current_directory()

    username = get_current_username()
    timestamp = get_timestamp()
    background_value = 1 if background else 0

    if risk_score is None:
        risk_score, computed_reasons = score_command(command)
        if risk_reasons is None:
            risk_reasons = computed_reasons

    if risk_reasons is None:
        risk_reasons = []

    risk_reasons_text = (
        " | ".join(risk_reasons)
        if risk_reasons
        else None
    )

    try:
        connection = get_database_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO command_audit
            (
                timestamp, username, cwd, command, command_name,
                pid, background, exit_status, duration_ms,
                command_type, job_id, risk_score, risk_reasons,
                security_action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp, username, cwd, command, command_name,
                pid, background_value, exit_status, duration_ms,
                command_type, job_id, risk_score, risk_reasons_text,
                security_action
            )
        )

        connection.commit()
        connection.close()

    except sqlite3.Error:
        pass


def print_audit_row(row):
    """Print a formatted audit log row."""
    audit_id = row["id"]
    timestamp = row["timestamp"]
    command = row["command"]
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
        f"{BRIGHT_BLACK}{timestamp}{RESET}"
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
