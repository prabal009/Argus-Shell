"""
Built-in shell commands for Argus.
"""

import os
import sqlite3

# readline is Unix/Linux/macOS only; optional on Windows
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

from .colors import (
    BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN,
    BRIGHT_BLACK, BRIGHT_PURPLE, BOLD, RESET
)
from .config import RISK_MAX, SECURITY_MODES
from .database import get_database_connection
from .audit import audit_command, print_audit_row, print_audit_header
from .risk import score_command, risk_level_name, risk_color
from .suspicious import current_suspicious_hits
from .security import security_policy, save_policy_to_disk, load_policy_from_disk
from .jobs import jobs, parse_job_number, foreground_job, background_job, job_status_name, job_status_color, update_jobs
from .utils import get_current_directory, get_current_username


def builtin_cd(args):
    """Change directory."""
    previous_directory = get_current_directory()

    if len(args) == 1:
        target_directory = os.path.expanduser("~")
    elif args[1] == "-":
        target_directory = os.environ.get("OLDPWD", previous_directory)
        print(target_directory)
    else:
        target_directory = os.path.expanduser(args[1])

    try:
        os.chdir(target_directory)
        os.environ["OLDPWD"] = previous_directory
        os.environ["PWD"] = os.getcwd()

    except FileNotFoundError:
        print(f"{BRIGHT_RED}Argus: directory not found: {target_directory}{RESET}")
    except NotADirectoryError:
        print(f"{BRIGHT_RED}Argus: not a directory: {target_directory}{RESET}")
    except PermissionError:
        print(f"{BRIGHT_RED}Argus: permission denied: {target_directory}{RESET}")
    except OSError as error:
        print(f"{BRIGHT_RED}Argus: {error}{RESET}")


def builtin_pwd():
    """Print current directory."""
    print(get_current_directory())


def builtin_export(args):
    """Export environment variables."""
    if len(args) == 1:
        for key, value in sorted(os.environ.items()):
            print(f"{key}={value}")
        return

    import re
    for assignment in args[1:]:
        if "=" not in assignment:
            print(
                f"{BRIGHT_RED}"
                f"Argus: export: invalid assignment: {assignment}"
                f"{RESET}"
            )
            continue

        name, value = assignment.split("=", 1)

        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            print(
                f"{BRIGHT_RED}"
                f"Argus: invalid variable name: {name}"
                f"{RESET}"
            )
            continue

        os.environ[name] = value


def builtin_unset(args):
    """Unset environment variables."""
    for name in args[1:]:
        os.environ.pop(name, None)


def builtin_env():
    """Show environment variables."""
    for key, value in sorted(os.environ.items()):
        print(f"{key}={value}")


def builtin_history():
    """Show command history."""
    if not HAS_READLINE:
        print(f"{BRIGHT_BLACK}Argus: readline not available on this platform.{RESET}")
        return
    
    history_length = readline.get_current_history_length()

    for number in range(1, history_length + 1):
        command = readline.get_history_item(number)
        if command:
            print(f"{BRIGHT_BLACK}{number:5}{RESET}  {command}")


def builtin_redo(args, last_command, execute_func):
    """Re-run the last command."""
    if not last_command:
        print(f"{BRIGHT_BLACK}Argus: nothing to redo.{RESET}")
        return 0

    print(
        f"{BRIGHT_BLACK}"
        f"Argus: re-running: {last_command}"
        f"{RESET}"
    )

    command_to_rerun = last_command
    execute_func(command_to_rerun)

    return 0


def builtin_jobs():
    """Show active jobs."""
    update_jobs()

    if not jobs:
        print(f"{BRIGHT_BLACK}No active jobs.{RESET}")
        return

    for job_id in sorted(jobs.keys()):
        job = jobs[job_id]
        status = job_status_name(job["status"])
        color = job_status_color(job["status"])

        print(
            f"{BRIGHT_CYAN}[{job_id}]{RESET}"
            " "
            f"{color}{status:<8}{RESET}"
            " "
            f"{job['command']}"
        )


def builtin_audit(args):
    """Show audit log."""
    if len(args) >= 2 and args[1].lower() == "risky":
        threshold = 40
        if len(args) >= 3:
            try:
                threshold = int(args[2])
            except ValueError:
                threshold = 40
        threshold = max(0, min(threshold, RISK_MAX))
        return audit_risky(threshold)

    if len(args) >= 2 and args[1].lower() == "clear":
        confirm = input(
            f"{BRIGHT_YELLOW}"
            "Argus: clear entire audit log? [y/N] "
            f"{RESET}"
        )

        if confirm.lower() != "y":
            print(f"{BRIGHT_CYAN}Audit log was not cleared.{RESET}")
            return

        try:
            connection = get_database_connection()
            connection.execute("DELETE FROM command_audit")
            connection.commit()
            connection.close()
            print(f"{BRIGHT_GREEN}Argus: audit log cleared.{RESET}")
        except sqlite3.Error as error:
            print(
                f"{BRIGHT_RED}"
                f"Argus: could not clear audit log: {error}"
                f"{RESET}"
            )
        return

    search_term = None
    if len(args) >= 3 and args[1].lower() == "search":
        search_term = " ".join(args[2:])

    limit = 20
    if len(args) == 2 and args[1].isdigit():
        try:
            limit = int(args[1])
        except ValueError:
            limit = 20

    limit = max(1, min(limit, 500))

    try:
        connection = get_database_connection()

        if search_term:
            rows = connection.execute(
                """
                SELECT *
                FROM command_audit
                WHERE command LIKE ?
                   OR cwd LIKE ?
                   OR username LIKE ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (
                    f"%{search_term}%",
                    f"%{search_term}%",
                    f"%{search_term}%",
                    limit
                )
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM command_audit
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        connection.close()

    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: audit database error: {error}"
            f"{RESET}"
        )
        return

    if not rows:
        print(f"{BRIGHT_BLACK}Argus: no audit records found.{RESET}")
        return

    print_audit_header()

    for row in reversed(rows):
        print_audit_row(row)

    print()


def audit_risky(threshold):
    """Show risky commands from audit log."""
    try:
        connection = get_database_connection()

        rows = connection.execute(
            """
            SELECT *
            FROM command_audit
            WHERE risk_score IS NOT NULL
              AND risk_score >= ?
            ORDER BY id DESC
            LIMIT 200
            """,
            (threshold,)
        ).fetchall()

        connection.close()

    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: audit risky error: {error}"
            f"{RESET}"
        )
        return 0

    if not rows:
        print(
            f"{BRIGHT_BLACK}"
            f"Argus: no commands with risk >= {threshold}."
            f"{RESET}"
        )
        return 0

    print()
    print(
        f"{BRIGHT_PURPLE}{BOLD}"
        f"ARGUS RISKY COMMANDS (score >= {threshold})"
        f"{RESET}"
    )
    print()

    for row in reversed(rows):
        print_audit_row(row)

        reasons = row["risk_reasons"]

        if reasons:
            print(
                f"{BRIGHT_BLACK}"
                f"      ↳ {reasons}"
                f"{RESET}"
            )

    print()

    return 0


def builtin_risk(args):
    """Score a command without executing it."""
    if len(args) < 2:
        print(
            f"{BRIGHT_YELLOW}"
            "Argus: usage: risk <command>"
            f"{RESET}"
        )
        return 0

    command_text = " ".join(args[1:])

    score, reasons = score_command(command_text)

    level = risk_level_name(score)
    color = risk_color(score)

    from .security import evaluate_security
    decision, reason = evaluate_security(command_text, score, [])

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS RISK ANALYSIS{RESET}")
    print()

    print(f"{BRIGHT_CYAN}Command:{RESET} {command_text}")

    print(
        f"{BRIGHT_CYAN}Score:{RESET}"
        f" {color}{BOLD}{score}{RESET} / {RISK_MAX}"
    )

    print(
        f"{BRIGHT_CYAN}Level:{RESET}"
        f" {color}{BOLD}{level}{RESET}"
    )

    print(
        f"{BRIGHT_CYAN}Enforcement:{RESET}"
        f" {BRIGHT_WHITE}{decision}{RESET}"
        f" ({reason})"
    )

    print()

    if reasons:
        print(f"{BRIGHT_PURPLE}{BOLD}MATCHED RULES{RESET}")
        print()
        for reason in reasons:
            print(f"{BRIGHT_RED}  • {RESET}{reason}")
    else:
        print(f"{BRIGHT_GREEN}No risk rules matched.{RESET}")

    print()

    return 0


def builtin_suspicious(args):
    """Show suspicious events."""
    search_term = None
    if len(args) >= 3 and args[1].lower() == "search":
        search_term = " ".join(args[2:])

    severity_filter = None
    if len(args) == 2 and args[1].lower() in (
        "low", "medium", "high", "critical"
    ):
        severity_filter = args[1].lower()

    limit = 20
    if len(args) == 2 and args[1].isdigit():
        try:
            limit = int(args[1])
        except ValueError:
            limit = 20

    limit = max(1, min(limit, 500))

    try:
        connection = get_database_connection()

        query = "SELECT * FROM suspicious_events WHERE 1=1"
        params = []

        if severity_filter:
            query += " AND severity = ?"
            params.append(severity_filter)

        if search_term:
            query += " AND (rule_name LIKE ? OR reason LIKE ? OR matched_command LIKE ?)"
            params.extend([
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%",
            ])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = connection.execute(query, params).fetchall()
        connection.close()

    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: suspicious query error: {error}"
            f"{RESET}"
        )
        return 0

    if not rows:
        print(f"{BRIGHT_BLACK}Argus: no suspicious events found.{RESET}")
        return 0

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS SUSPICIOUS EVENTS{RESET}")
    print()
    print(
        f"{BRIGHT_BLACK}"
        " ID    TIMESTAMP                 SEVERITY RULE                         COMMAND"
        f"{RESET}"
    )
    print(f"{BRIGHT_BLACK}{'─' * 105}{RESET}")

    from .suspicious import severity_color as sus_severity_color

    for row in reversed(rows):
        event_id = row["id"]
        timestamp = row["timestamp"]
        rule_name = row["rule_name"]
        severity = row["severity"]
        matched_command = row["matched_command"]

        color = sus_severity_color(severity)

        if len(matched_command) > 45:
            matched_command = matched_command[:42] + "..."

        print(
            f"{BRIGHT_CYAN}{event_id:5}{RESET}"
            " "
            f"{BRIGHT_BLACK}{timestamp}{RESET}"
            " "
            f"{color}{severity:<8}{RESET}"
            " "
            f"{BRIGHT_WHITE}{rule_name:<28}{RESET}"
            " "
            f"{matched_command}"
        )

    print()

    return 0


def builtin_suspicious_stats():
    """Show suspicious event statistics."""
    from .suspicious import suspicious_session_id, severity_color as sus_severity_color
    
    try:
        connection = get_database_connection()

        total = connection.execute(
            "SELECT COUNT(*) FROM suspicious_events"
        ).fetchone()[0]

        by_severity = connection.execute(
            """
            SELECT severity, COUNT(*) AS total
            FROM suspicious_events
            GROUP BY severity
            ORDER BY total DESC
            """
        ).fetchall()

        by_rule = connection.execute(
            """
            SELECT rule_name, COUNT(*) AS total
            FROM suspicious_events
            GROUP BY rule_name
            ORDER BY total DESC
            LIMIT 10
            """
        ).fetchall()

        session_total = connection.execute(
            """
            SELECT COUNT(*) FROM suspicious_events
            WHERE session_id = ?
            """,
            (suspicious_session_id,)
        ).fetchone()[0]

        connection.close()

    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: suspicious stats error: {error}"
            f"{RESET}"
        )
        return 0

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS SUSPICIOUS STATISTICS{RESET}")
    print()
    print(f"{BRIGHT_CYAN}Total events:{RESET} {total}")
    print(f"{BRIGHT_CYAN}This session:{RESET} {session_total}")
    print(f"{BRIGHT_CYAN}Session ID:{RESET} {suspicious_session_id}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}BY SEVERITY{RESET}")
    print()

    if not by_severity:
        print(f"{BRIGHT_BLACK}No events recorded.{RESET}")
    else:
        for row in by_severity:
            color = sus_severity_color(row["severity"])
            print(
                f"{color}{row['severity']:<10}{RESET}"
                f"{BRIGHT_WHITE}{row['total']}{RESET}"
            )

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}TOP RULES{RESET}")
    print()

    if not by_rule:
        print(f"{BRIGHT_BLACK}No rules triggered.{RESET}")
    else:
        for number, row in enumerate(by_rule, start=1):
            print(
                f"{BRIGHT_CYAN}{number:2}.{RESET}"
                " "
                f"{row['rule_name']:<30}"
                f"{BRIGHT_WHITE}{row['total']}{RESET}"
            )

    print()

    return 0


def builtin_suspicious_clear(args):
    """Clear suspicious events."""
    from .suspicious import suspicious_session_id
    
    if len(args) >= 2 and args[1].lower() == "all":
        confirm = input(
            f"{BRIGHT_YELLOW}"
            "Argus: clear ALL suspicious events? [y/N] "
            f"{RESET}"
        )
        if confirm.lower() != "y":
            print(f"{BRIGHT_CYAN}Not cleared.{RESET}")
            return 0

        try:
            connection = get_database_connection()
            connection.execute("DELETE FROM suspicious_events")
            connection.commit()
            connection.close()
            print(f"{BRIGHT_GREEN}Argus: all events cleared.{RESET}")
        except sqlite3.Error as error:
            print(
                f"{BRIGHT_RED}"
                f"Argus: clear error: {error}"
                f"{RESET}"
            )
        return 0

    try:
        connection = get_database_connection()
        cursor = connection.execute(
            "DELETE FROM suspicious_events WHERE session_id = ?",
            (suspicious_session_id,)
        )
        deleted = cursor.rowcount
        connection.commit()
        connection.close()
        print(
            f"{BRIGHT_GREEN}"
            f"Argus: cleared {deleted} events from this session."
            f"{RESET}"
        )
    except sqlite3.Error as error:
        print(
            f"{BRIGHT_RED}"
            f"Argus: clear error: {error}"
            f"{RESET}"
        )

    return 0


def builtin_audit_stats():
    """Show audit statistics."""
    try:
        connection = get_database_connection()

        total = connection.execute(
            "SELECT COUNT(*) FROM command_audit"
        ).fetchone()[0]

        successful = connection.execute(
            "SELECT COUNT(*) FROM command_audit WHERE exit_status = 0"
        ).fetchone()[0]

        failed = connection.execute(
            """
            SELECT COUNT(*) FROM command_audit
            WHERE exit_status IS NOT NULL AND exit_status != 0
            """
        ).fetchone()[0]

        background = connection.execute(
            "SELECT COUNT(*) FROM command_audit WHERE background = 1"
        ).fetchone()[0]

        average_duration = connection.execute(
            """
            SELECT AVG(duration_ms) FROM command_audit
            WHERE duration_ms IS NOT NULL
            """
        ).fetchone()[0]

        average_risk = connection.execute(
            """
            SELECT AVG(risk_score) FROM command_audit
            WHERE risk_score IS NOT NULL
            """
        ).fetchone()[0]

        max_risk = connection.execute(
            """
            SELECT MAX(risk_score) FROM command_audit
            WHERE risk_score IS NOT NULL
            """
        ).fetchone()[0]

        high_risk_count = connection.execute(
            """
            SELECT COUNT(*) FROM command_audit
            WHERE risk_score >= 70
            """
        ).fetchone()[0]

        denied_count = connection.execute(
            """
            SELECT COUNT(*) FROM security_actions
            WHERE action = 'deny'
            """
        ).fetchone()[0]

        confirmed_count = connection.execute(
            """
            SELECT COUNT(*) FROM security_actions
            WHERE action = 'confirm-denied'
            """
        ).fetchone()[0]

        top_commands = connection.execute(
            """
            SELECT command_name, COUNT(*) AS total
            FROM command_audit
            WHERE command_name IS NOT NULL
            GROUP BY command_name
            ORDER BY total DESC
            LIMIT 10
            """
        ).fetchall()

        connection.close()

    except sqlite3.Error as error:
        print(f"{BRIGHT_RED}Argus: statistics error: {error}{RESET}")
        return

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS AUDIT STATISTICS{RESET}")
    print()
    print(f"{BRIGHT_CYAN}Total commands:{RESET} {total}")
    print(f"{BRIGHT_CYAN}Successful:{RESET} {successful}")
    print(f"{BRIGHT_CYAN}Failed:{RESET} {failed}")
    print(f"{BRIGHT_CYAN}Background:{RESET} {background}")

    if average_duration is None:
        average_text = "N/A"
    else:
        average_text = f"{average_duration:.2f} ms"

    print(f"{BRIGHT_CYAN}Average execution:{RESET} {average_text}")

    if average_risk is None:
        average_risk_text = "N/A"
    else:
        average_risk_text = f"{average_risk:.2f}"

    if max_risk is None:
        max_risk_text = "N/A"
    else:
        max_risk_text = str(max_risk)

    print(f"{BRIGHT_CYAN}Average risk:{RESET} {average_risk_text}")
    print(f"{BRIGHT_CYAN}Max risk:{RESET} {max_risk_text}")
    print(f"{BRIGHT_CYAN}High-risk (>=70):{RESET} {high_risk_count}")
    print(f"{BRIGHT_CYAN}Denied:{RESET} {denied_count}")
    print(f"{BRIGHT_CYAN}Confirm-denied:{RESET} {confirmed_count}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}TOP COMMANDS{RESET}")
    print()

    if not top_commands:
        print(f"{BRIGHT_BLACK}No command statistics available.{RESET}")
    else:
        for number, row in enumerate(top_commands, start=1):
            print(
                f"{BRIGHT_CYAN}{number:2}.{RESET}"
                " "
                f"{row['command_name']:<20}"
                f"{BRIGHT_WHITE}{row['total']}{RESET}"
            )

    print()


def builtin_security(args):
    """Manage security policy."""
    if len(args) >= 3 and args[1].lower() == "mode":

        new_mode = args[2].lower()

        if new_mode not in SECURITY_MODES:

            print(
                f"{BRIGHT_RED}"
                f"Argus: unknown mode '{new_mode}'. "
                f"Valid: {', '.join(SECURITY_MODES)}"
                f"{RESET}"
            )
            return 0

        security_policy["mode"] = new_mode

        color = BRIGHT_RED if new_mode in ("block", "allowlist") else BRIGHT_YELLOW

        print(
            f"{BRIGHT_GREEN}"
            f"Argus: security mode set to "
            f"{color}{BOLD}{new_mode}{RESET}"
        )

        return 0

    if len(args) >= 3 and args[1].lower() == "threshold":

        try:
            new_threshold = int(args[2])
        except ValueError:
            print(f"{BRIGHT_RED}Argus: threshold must be an integer{RESET}")
            return 0

        new_threshold = max(0, min(new_threshold, RISK_MAX))
        security_policy["risk_threshold"] = new_threshold

        print(
            f"{BRIGHT_GREEN}"
            f"Argus: risk threshold set to {new_threshold}"
            f"{RESET}"
        )
        return 0

    if len(args) >= 2 and args[1].lower() == "save":

        if save_policy_to_disk():
            print(
                f"{BRIGHT_GREEN}"
                f"Argus: policy saved to {ARGUS_POLICY_FILE}"
                f"{RESET}"
            )
        return 0

    if len(args) >= 2 and args[1].lower() == "load":

        if load_policy_from_disk():
            print(
                f"{BRIGHT_GREEN}"
                f"Argus: policy loaded from {ARGUS_POLICY_FILE}"
                f"{RESET}"
            )
        else:
            print(
                f"{BRIGHT_YELLOW}"
                f"Argus: no policy file found at {ARGUS_POLICY_FILE}"
                f"{RESET}"
            )
        return 0

    if len(args) >= 2 and args[1].lower() == "reset":

        from .config import DEFAULT_SECURITY_POLICY
        security_policy["mode"] = DEFAULT_SECURITY_POLICY["mode"]
        security_policy["risk_threshold"] = DEFAULT_SECURITY_POLICY["risk_threshold"]
        security_policy["block_on_suspicious"] = DEFAULT_SECURITY_POLICY["block_on_suspicious"]
        security_policy["suspicious_min_severity"] = DEFAULT_SECURITY_POLICY["suspicious_min_severity"]
        security_policy["allowlist"] = list(DEFAULT_SECURITY_POLICY["allowlist"])
        security_policy["denylist"] = list(DEFAULT_SECURITY_POLICY["denylist"])
        security_policy["resource_limits"] = dict(DEFAULT_SECURITY_POLICY["resource_limits"])

        print(f"{BRIGHT_GREEN}Argus: policy reset to defaults.{RESET}")
        return 0

    from .config import ARGUS_POLICY_FILE
    mode = security_policy.get("mode", "warn")
    color = BRIGHT_RED if mode in ("block", "allowlist") else (
        BRIGHT_YELLOW if mode == "confirm" else BRIGHT_GREEN
    )

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS SECURITY POLICY{RESET}")
    print()

    print(
        f"{BRIGHT_CYAN}Mode:{RESET} "
        f"{color}{BOLD}{mode}{RESET}"
    )

    print(
        f"{BRIGHT_CYAN}Risk threshold:{RESET} "
        f"{security_policy.get('risk_threshold', 70)}"
    )

    print(
        f"{BRIGHT_CYAN}Block on suspicious:{RESET} "
        f"{security_policy.get('block_on_suspicious', True)}"
    )

    print(
        f"{BRIGHT_CYAN}Suspicious min severity:{RESET} "
        f"{security_policy.get('suspicious_min_severity', 'high')}"
    )

    print(
        f"{BRIGHT_CYAN}Policy file:{RESET} "
        f"{ARGUS_POLICY_FILE}"
        f" "
        f"{BRIGHT_BLACK}"
        f"({'exists' if os.path.exists(ARGUS_POLICY_FILE) else 'not found'})"
        f"{RESET}"
    )

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ALLOWLIST{RESET}")
    print()

    allowlist = security_policy.get("allowlist", [])
    if allowlist:
        line = "  "
        for name in sorted(allowlist):
            if len(line) + len(name) > 78:
                print(line)
                line = "  "
            line += f"{BRIGHT_CYAN}{name}{RESET}  "
        if line.strip():
            print(line)
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}DENYLIST{RESET}")
    print()

    denylist = security_policy.get("denylist", [])
    if denylist:
        for name in sorted(denylist):
            print(f"  {BRIGHT_RED}{name}{RESET}")
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}RESOURCE LIMITS{RESET}")
    print()

    limits = security_policy.get("resource_limits", {})

    enabled = limits.get("enabled", False)
    enabled_color = BRIGHT_GREEN if enabled else BRIGHT_BLACK

    print(
        f"{BRIGHT_CYAN}Enabled:{RESET} "
        f"{enabled_color}{enabled}{RESET}"
    )
    print(f"{BRIGHT_CYAN}CPU seconds:{RESET} {limits.get('cpu_seconds', 60)}")
    print(f"{BRIGHT_CYAN}Memory (MB):{RESET} {limits.get('memory_mb', 512)}")
    print(f"{BRIGHT_CYAN}Max processes:{RESET} {limits.get('max_processes', 0)}")
    print(f"{BRIGHT_CYAN}File size (MB):{RESET} {limits.get('file_size_mb', 100)}")
    print(f"{BRIGHT_CYAN}Open files:{RESET} {limits.get('open_files', 256)}")

    print()

    from .resource import HAVE_RESOURCE
    if not HAVE_RESOURCE:
        print(
            f"{BRIGHT_YELLOW}"
            "Note: resource module not available on this platform. "
            "Resource limits will be ignored."
            f"{RESET}"
        )
        print()

    return 0


def builtin_allow(args):
    """Add a command to the allowlist."""
    if len(args) < 2:
        print(f"{BRIGHT_YELLOW}Argus: usage: allow <command>{RESET}")
        return 0

    name = args[1]

    if name in security_policy["allowlist"]:
        print(f"{BRIGHT_BLACK}Argus: '{name}' already allowed.{RESET}")
        return 0

    security_policy["allowlist"].append(name)

    print(f"{BRIGHT_GREEN}Argus: allowed '{name}'.{RESET}")
    return 0


def builtin_deny(args):
    """Add a command to the denylist."""
    if len(args) < 2:
        print(f"{BRIGHT_YELLOW}Argus: usage: deny <command>{RESET}")
        return 0

    name = args[1]

    if name in security_policy["denylist"]:
        print(f"{BRIGHT_BLACK}Argus: '{name}' already denied.{RESET}")
        return 0

    security_policy["denylist"].append(name)

    print(f"{BRIGHT_RED}Argus: denied '{name}'.{RESET}")
    return 0


def builtin_allowlist():
    """Show allowlist and denylist."""
    allowlist = security_policy.get("allowlist", [])
    denylist = security_policy.get("denylist", [])

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS ALLOWLIST{RESET}")
    print()

    if allowlist:
        for name in sorted(allowlist):
            print(f"  {BRIGHT_GREEN}{name}{RESET}")
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS DENYLIST{RESET}")
    print()

    if denylist:
        for name in sorted(denylist):
            print(f"  {BRIGHT_RED}{name}{RESET}")
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    return 0


def builtin_help():
    """Show help information."""
    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS COMMANDS{RESET}")
    print()

    entries = [
        ("cd <directory>", "Change directory"),
        ("cd -", "Return to previous directory"),
        ("pwd", "Print current directory"),
        ("export NAME=value", "Set environment variable"),
        ("unset NAME", "Remove environment variable"),
        ("env", "Show environment"),
        ("history", "Show command history"),
        ("redo", "Re-run the last command"),
        ("jobs", "Show jobs"),
        ("fg %1", "Bring job to foreground"),
        ("bg %1", "Continue job in background"),
        ("audit", "Show recent audit records"),
        ("audit 50", "Show last 50 audit records"),
        ("audit search ssh", "Search audit database"),
        ("audit clear", "Clear audit database"),
        ("audit risky", "Show commands with risk >= 40"),
        ("audit risky 70", "Show commands with risk >= 70"),
        ("audit-stats", "Show audit statistics"),
        ("risk <command>", "Score a command without executing it"),
        ("suspicious", "Show recent suspicious events"),
        ("suspicious high", "Filter by severity"),
        ("suspicious search foo", "Search suspicious events"),
        ("suspicious-stats", "Show suspicious event stats"),
        ("suspicious-clear", "Clear current session events"),
        ("suspicious-clear all", "Clear ALL suspicious events"),
        ("security", "Show current security policy"),
        ("security mode <name>", "Change mode (off/warn/confirm/block/allowlist/dry-run)"),
        ("security threshold 70", "Set risk threshold"),
        ("security save", "Save policy to disk"),
        ("security load", "Load policy from disk"),
        ("security reset", "Reset policy to defaults"),
        ("allow <command>", "Add command to allowlist"),
        ("deny <command>", "Add command to denylist"),
        ("allowlist", "Show allowlist and denylist"),
        ("help", "Show this help"),
        ("exit", "Exit Argus"),
    ]

    for name, description in entries:
        print(f"{BRIGHT_CYAN}{name}{RESET}  {description}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}OPERATORS{RESET}")
    print()

    operators = [
        "command1 | command2",
        "command < input.txt",
        "command > output.txt",
        "command >> output.txt",
        "command &",
    ]

    for operator in operators:
        print(f"{BRIGHT_BLACK}{operator}{RESET}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}READLINE SHORTCUTS{RESET}")
    print()
    print(f"{BRIGHT_BLACK}Ctrl+R    Reverse history search{RESET}")
    print(f"{BRIGHT_BLACK}Ctrl+S    Forward history search{RESET}")
    print(f"{BRIGHT_BLACK}Ctrl+L    Clear screen{RESET}")
    print(f"{BRIGHT_BLACK}Up/Down   Navigate history{RESET}")
    print(f"{BRIGHT_BLACK}Alt+.     Insert last argument of previous command{RESET}")
    print(f"{BRIGHT_BLACK}Ctrl+C    Interrupt foreground process{RESET}")
    print(f"{BRIGHT_BLACK}Ctrl+Z    Stop (suspend) foreground process{RESET}")
    print()

    from .config import RISK_LEVELS
    print(f"{BRIGHT_PURPLE}{BOLD}RISK LEVELS{RESET}")
    print()

    for threshold, name, _color in RISK_LEVELS:
        print(f"{_color}{threshold:>3}+{RESET} {name}")

    print()

    print(f"{BRIGHT_PURPLE}{BOLD}SUSPICIOUS SEVERITIES{RESET}")
    print()

    from .suspicious import severity_color as sus_severity_color
    for name in ("low", "medium", "high", "critical"):
        color = sus_severity_color(name)
        print(f"{color}{name}{RESET}")

    print()

    print(f"{BRIGHT_PURPLE}{BOLD}SECURITY MODES{RESET}")
    print()

    print("  off       - no enforcement (warnings still shown)")
    print("  warn      - default; warnings only, always runs")
    print("  confirm   - prompt [y/N] on high-risk / suspicious")
    print("  block     - refuse to run high-risk / suspicious")
    print("  allowlist - only allowlisted commands run")
    print("  dry-run   - classify but never execute")

    print()
