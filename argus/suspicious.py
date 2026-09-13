"""
Suspicious activity detection with patterns, sequences, and repetition tracking.
"""

import sqlite3
import time
from collections import deque
from datetime import datetime
from .colors import BOLD, BRIGHT_BLACK, BRIGHT_PURPLE, RESET
from .config import (
    SUSPICIOUS_WINDOW_SIZE,
    SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
    SUSPICIOUS_COOLDOWN_SECONDS,
    SUSPICIOUS_REPEAT_COUNT,
    SUSPICIOUS_REPEAT_SECONDS,
    SUSPICIOUS_SEQUENCE_RULES,
    SUSPICIOUS_PATTERNS,
)
from .database import get_database_connection
from .utils import get_timestamp, get_current_username, get_current_directory


# Global state
suspicious_buffer = deque(maxlen=SUSPICIOUS_WINDOW_SIZE)
suspicious_cooldowns = {}
suspicious_session_id = datetime.now().strftime("%Y%m%d%H%M%S")
current_suspicious_hits = []


def severity_color(severity):
    """Get the ANSI color code for a severity level."""
    if severity == "critical":
        return "\033[95m"  # BRIGHT_PURPLE
    if severity == "high":
        return "\033[91m"  # BRIGHT_RED
    if severity == "medium":
        return "\033[93m"  # BRIGHT_YELLOW
    if severity == "low":
        return "\033[96m"  # BRIGHT_CYAN
    return "\033[97m"  # BRIGHT_WHITE


def suspicious_rule_on_cooldown(rule_name):
    """Check if a suspicious rule is on cooldown."""
    now = time.time()
    last = suspicious_cooldowns.get(rule_name, 0)
    if now - last < SUSPICIOUS_COOLDOWN_SECONDS:
        return True
    suspicious_cooldowns[rule_name] = now
    return False


def record_suspicious_event(
    rule_name,
    severity,
    reason,
    matched_command,
    context_lines=None
):
    """Record a suspicious event to the database and print notification."""
    global current_suspicious_hits
    
    current_suspicious_hits.append((rule_name, severity, reason))

    if suspicious_rule_on_cooldown(rule_name):
        return

    timestamp = get_timestamp()
    username = get_current_username()
    cwd = get_current_directory()

    context_text = None
    if context_lines:
        context_text = "\n".join(context_lines)

    try:
        connection = get_database_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO suspicious_events
            (
                timestamp, username, cwd, session_id,
                rule_name, severity, reason,
                matched_command, context
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                username,
                cwd,
                suspicious_session_id,
                rule_name,
                severity,
                reason,
                matched_command,
                context_text
            )
        )

        connection.commit()
        connection.close()

    except sqlite3.Error:
        pass

    color = severity_color(severity)

    print(
        f"{color}{BOLD}"
        f"⚠  SUSPICIOUS [{severity.upper()}]: {reason}"
        f"{RESET}"
    )

    print(
        f"{BRIGHT_BLACK}"
        f"   rule: {rule_name}"
        f"{RESET}"
    )


def check_suspicious_patterns(command_line):
    """Check command against suspicious patterns."""
    if not command_line:
        return

    for rule_name, severity, pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(command_line):
            record_suspicious_event(
                rule_name,
                severity,
                reason,
                command_line
            )


def check_suspicious_sequences(command_line):
    """Check for suspicious command sequences."""
    if not command_line:
        return

    now = time.time()

    recent = [
        entry
        for entry in suspicious_buffer
        if now - entry[0] <= SUSPICIOUS_SEQUENCE_WINDOW_SECONDS
    ]

    for rule_name, severity, compiled_patterns, window, reason in SUSPICIOUS_SEQUENCE_RULES:

        index = 0
        matched_commands = []

        for compiled in compiled_patterns:

            found = False

            while index < len(recent):

                _ts, candidate = recent[index]

                if compiled.search(candidate):

                    matched_commands.append(candidate)

                    found = True
                    index += 1
                    break

                index += 1

            if not found:
                break

        if len(matched_commands) == len(compiled_patterns):

            context_lines = [f"  → {c}" for c in matched_commands]

            record_suspicious_event(
                rule_name,
                severity,
                reason,
                command_line,
                context_lines
            )


def check_suspicious_repetition(command_line):
    """Check for rapidly repeated commands."""
    if not command_line:
        return

    now = time.time()

    count = 0

    for ts, entry in suspicious_buffer:
        if now - ts > SUSPICIOUS_REPEAT_SECONDS:
            continue
        if entry.strip() == command_line.strip():
            count += 1

    if count + 1 >= SUSPICIOUS_REPEAT_COUNT:

        record_suspicious_event(
            "rapid_repetition",
            "medium",
            f"command repeated {count + 1} times in "
            f"{SUSPICIOUS_REPEAT_SECONDS}s",
            command_line
        )


def detect_suspicious(command_line):
    """Main detector that runs all suspicious checks."""
    if not command_line:
        return

    check_suspicious_patterns(command_line)
    check_suspicious_sequences(command_line)
    check_suspicious_repetition(command_line)

    suspicious_buffer.append((time.time(), command_line))
