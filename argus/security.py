"""
Security policy management and enforcement.
"""

import json
import os
import sqlite3
from .colors import BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN, BRIGHT_BLACK, BRIGHT_PURPLE, BOLD, RESET
from .config import (
    ARGUS_POLICY_FILE,
    DEFAULT_SECURITY_POLICY,
    SEVERITY_RANK,
)
from .database import get_database_connection
from .utils import get_timestamp, get_current_username, get_current_directory


# Global security policy state
security_policy = dict(DEFAULT_SECURITY_POLICY)
security_policy["allowlist"] = list(DEFAULT_SECURITY_POLICY["allowlist"])
security_policy["denylist"] = list(DEFAULT_SECURITY_POLICY["denylist"])
security_policy["resource_limits"] = dict(DEFAULT_SECURITY_POLICY["resource_limits"])


def load_policy_from_disk():
    """Load security policy from disk."""
    global security_policy

    if not os.path.exists(ARGUS_POLICY_FILE):
        return False

    try:
        with open(ARGUS_POLICY_FILE, "r") as handle:
            data = json.load(handle)

    except (OSError, json.JSONDecodeError) as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: could not read policy file: {error}"
            f"{RESET}"
        )
        return False

    merged = dict(DEFAULT_SECURITY_POLICY)
    merged["allowlist"] = list(DEFAULT_SECURITY_POLICY["allowlist"])
    merged["denylist"] = list(DEFAULT_SECURITY_POLICY["denylist"])
    merged["resource_limits"] = dict(DEFAULT_SECURITY_POLICY["resource_limits"])

    for key in ("mode", "risk_threshold", "block_on_suspicious",
                "suspicious_min_severity"):
        if key in data:
            merged[key] = data[key]

    if isinstance(data.get("allowlist"), list):
        merged["allowlist"] = list(data["allowlist"])

    if isinstance(data.get("denylist"), list):
        merged["denylist"] = list(data["denylist"])

    if isinstance(data.get("resource_limits"), dict):
        for k, v in data["resource_limits"].items():
            merged["resource_limits"][k] = v

    security_policy = merged

    return True


def save_policy_to_disk():
    """Save security policy to disk."""
    try:
        with open(ARGUS_POLICY_FILE, "w") as handle:
            json.dump(security_policy, handle, indent=2)
    except OSError as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: could not save policy: {error}"
            f"{RESET}"
        )
        return False

    return True


def log_security_action(
    mode,
    action,
    reason,
    command_line,
    risk_score=None,
    suspicious_rules=None,
    session_id=None
):
    """Log a security action to the database."""
    try:
        connection = get_database_connection()
        cursor = connection.cursor()

        rules_text = None
        if suspicious_rules:
            rules_text = ",".join(r[0] for r in suspicious_rules)

        cursor.execute(
            """
            INSERT INTO security_actions
            (
                timestamp, username, cwd, session_id,
                mode, action, reason,
                command, risk_score, suspicious_rules
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                get_timestamp(),
                get_current_username(),
                get_current_directory(),
                session_id or "unknown",
                mode,
                action,
                reason,
                command_line,
                risk_score,
                rules_text
            )
        )

        connection.commit()
        connection.close()

    except sqlite3.Error:
        pass


def evaluate_security(
    command_line,
    risk_score,
    suspicious_hits
):
    """
    Evaluate whether a command should be allowed based on policy.
    
    Returns:
        tuple: (decision, reason) where decision is "allow", "deny", or "confirm"
    """
    mode = security_policy.get("mode", "warn")

    if mode == "off" or mode == "warn":
        return ("allow", "mode=" + mode)

    if mode == "dry-run":
        return ("deny", "dry-run mode (not executed)")

    command_name = ""
    stripped = command_line.strip()
    if stripped:
        first = stripped.split(None, 1)[0]
        command_name = first

    allowlist = set(security_policy.get("allowlist", []))
    denylist = set(security_policy.get("denylist", []))

    if command_name in denylist:
        return ("deny", f"'{command_name}' is in denylist")

    if mode == "allowlist":
        if command_name not in allowlist:
            return (
                "deny",
                f"'{command_name}' not in allowlist "
                f"(mode=allowlist)"
            )
        return ("allow", "in allowlist")

    threshold = int(security_policy.get("risk_threshold", 70))

    if risk_score >= threshold:
        if mode == "block":
            return (
                "deny",
                f"risk {risk_score} >= threshold {threshold}"
            )
        if mode == "confirm":
            return (
                "confirm",
                f"risk {risk_score} >= threshold {threshold}"
            )

    if security_policy.get("block_on_suspicious", True):
        min_sev = security_policy.get("suspicious_min_severity", "high")
        min_rank = SEVERITY_RANK.get(min_sev, 3)

        for rule_name, severity, reason in suspicious_hits:
            if SEVERITY_RANK.get(severity, 0) >= min_rank:
                if mode == "block":
                    return (
                        "deny",
                        f"suspicious rule '{rule_name}' ({severity})"
                    )
                if mode == "confirm":
                    return (
                        "confirm",
                        f"suspicious rule '{rule_name}' ({severity})"
                    )

    return ("allow", "no policy violation")
