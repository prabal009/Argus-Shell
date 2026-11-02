"""Heuristic detection with command-local results and bounded session context."""

import sqlite3
import time
from collections import deque

from .colors import BOLD, BRIGHT_BLACK, RESET
from .config import (SUSPICIOUS_WINDOW_SIZE, SUSPICIOUS_COOLDOWN_SECONDS,
                     SUSPICIOUS_REPEAT_COUNT, SUSPICIOUS_REPEAT_SECONDS,
                     SUSPICIOUS_SEQUENCE_RULES, SUSPICIOUS_PATTERNS)
from .database import get_database_connection, prune_records
from .storage import storage_warning
from .utils import (SESSION_ID, get_timestamp, get_current_username,
                    get_current_directory, redact_text, safe_text)


suspicious_buffer = deque(maxlen=SUSPICIOUS_WINDOW_SIZE)
suspicious_cooldowns = {}
suspicious_session_id = SESSION_ID


def severity_color(severity):
    return {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
            "low": "\033[96m"}.get(severity, "\033[97m")


def reset_suspicious_state():
    """Explicitly clear detector memory, independently of persisted event deletion."""
    suspicious_buffer.clear()
    suspicious_cooldowns.clear()


def _analyze(command_line, now):
    """Return (hit, context) pairs without changing any detector state."""
    if not command_line:
        return []
    results = []
    for rule, severity, pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(command_line):
            results.append(((rule, severity, reason), None))
    for rule, severity, patterns, window, reason in SUSPICIOUS_SEQUENCE_RULES:
        # The final pattern MUST match this input; old completed sequences never
        # become an event attributed to an unrelated following command.
        if not patterns or not patterns[-1].search(command_line):
            continue
        recent = [(ts, text) for ts, text in suspicious_buffer if 0 <= now - ts <= window]
        matched = []
        index = len(recent) - 1
        for pattern in reversed(patterns[:-1]):
            while index >= 0 and not pattern.search(recent[index][1]):
                index -= 1
            if index < 0:
                break
            matched.append(recent[index][1])
            index -= 1
        if len(matched) == len(patterns) - 1:
            context = list(reversed(matched)) + [command_line]
            results.append(((rule, severity, reason), context))
    count = 1 + sum(1 for ts, text in suspicious_buffer
                    if 0 <= now - ts <= SUSPICIOUS_REPEAT_SECONDS
                    and text.strip() == command_line.strip())
    if count >= SUSPICIOUS_REPEAT_COUNT:
        results.append((("rapid_repetition", "medium",
                         "command repeated %s times in %ss" % (count, SUSPICIOUS_REPEAT_SECONDS)), None))
    return results


def analyze_suspicious(command_line):
    """Preview heuristic hits against current context, with no writes/notifications."""
    return [hit for hit, _context in _analyze(command_line, time.monotonic())]


def record_suspicious_event(rule_name, severity, reason, matched_command, context_lines=None):
    """Best-effort persistence/notification; cooldown never suppresses policy hits."""
    now = time.monotonic()
    previous = suspicious_cooldowns.get(rule_name)
    if previous is not None and now - previous < SUSPICIOUS_COOLDOWN_SECONDS:
        return
    suspicious_cooldowns[rule_name] = now
    connection = None
    try:
        connection = get_database_connection()
        connection.execute(
            """INSERT INTO suspicious_events
            (timestamp, username, cwd, session_id, rule_name, severity, reason,
             matched_command, context) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (get_timestamp(), get_current_username(), get_current_directory(),
             suspicious_session_id, rule_name, severity, redact_text(reason),
             redact_text(matched_command),
             redact_text("\n".join(context_lines)) if context_lines else None))
        prune_records(connection, "suspicious_events")
        connection.commit()
    except (sqlite3.Error, OSError) as error:
        storage_warning("could not persist suspicious event", safe_text(error))
    finally:
        if connection is not None:
            connection.close()
    color = severity_color(severity)
    print(f"{color}{BOLD}SUSPICIOUS [{safe_text(severity.upper())}]: {safe_text(reason)}{RESET}")
    print(f"{BRIGHT_BLACK}   rule: {safe_text(rule_name)}{RESET}")


def detect_suspicious(command_line):
    """Return this command's hits, then advance context and report new events."""
    if not command_line:
        return []
    now = time.monotonic()
    results = _analyze(command_line, now)
    suspicious_buffer.append((now, command_line))
    for (rule, severity, reason), context in results:
        record_suspicious_event(rule, severity, reason, command_line, context)
    return [hit for hit, _context in results]
