"""
Built-in shell commands for Argus.
"""

import copy
import json
import os
import re
import sqlite3
from contextlib import closing


from .colors import (
    BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_CYAN,
    BRIGHT_BLACK, BRIGHT_PURPLE, BRIGHT_WHITE, BOLD, RESET
)
from .config import DEFAULT_SECURITY_POLICY, RISK_MAX
from .database import get_database_connection
from .risk import risk_level_name, risk_color
from .suspicious import analyze_suspicious
from .security import (security_policy, save_policy_to_disk, load_policy_from_disk,
                       evaluate_security, analyze_command_risk, administrative_command,
                       validate_policy)
from . import operations
from .operations import builtin_vault, builtin_settings, builtin_redaction, builtin_security_actions
from .jobs import jobs, job_status_name, job_status_color, update_jobs
from .utils import get_current_directory, safe_text

_runtime = None
_session = None


def configure_runtime(runtime, session=None):
    global _runtime, _session
    _runtime, _session = runtime, session
    operations.configure_runtime(runtime, session)


def _usage(text):
    print(f"{BRIGHT_YELLOW}Argus: usage: {text}{RESET}")
    return 2


def _error(message):
    print(f"{BRIGHT_RED}Argus: {safe_text(message)}{RESET}")
    return 1


def _confirmed(prompt):
    try:
        return input(f"{BRIGHT_YELLOW}Argus: {prompt} [y/N] {RESET}").strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def builtin_cd(args):
    """Change directory without discarding a failed outcome."""
    if len(args) > 2:
        return _usage("cd [directory]")
    previous_directory = get_current_directory()
    environment = _runtime.state.variables if _runtime is not None else os.environ
    target_directory = (
        os.path.expanduser("~") if len(args) == 1 else
        environment.get("OLDPWD", previous_directory) if args[1] == "-" else
        os.path.expanduser(args[1])
    )
    try:
        os.chdir(target_directory)
        os.environ["OLDPWD"] = previous_directory
        os.environ["PWD"] = os.getcwd()
        if _runtime is not None:
            _runtime.state.variables.update(OLDPWD=previous_directory, PWD=os.getcwd())
            _runtime.state.exported.update({"OLDPWD", "PWD"})
    except (OSError, ValueError) as error:
        return _error(f"cd: {target_directory}: {error}")
    if len(args) == 2 and args[1] == "-":
        print(safe_text(target_directory))
    return 0


def builtin_pwd(args=None):
    """Print current directory."""
    if args is not None and len(args) != 1:
        return _usage("pwd")
    try:
        print(safe_text(os.getcwd()))
    except OSError as error:
        return _error(f"pwd: {error}")
    return 0


def builtin_env(args=None):
    """Show escaped environment metadata."""
    if args is not None and len(args) != 1:
        return _usage("env")
    environment = _runtime.state.environment() if _runtime is not None else os.environ
    for key, value in sorted(environment.items()):
        print(f"{safe_text(key)}={safe_text(value)}")
    return 0


def builtin_history(args=None):
    """Manage the active session's durable, privacy-aware history."""
    if _session is None:
        return _error("history requires an interactive session")
    return _session.history.command((args or ["history"])[1:])


def builtin_jobs(args=None):
    """Show active jobs."""
    if args is not None and len(args) != 1:
        return _usage("jobs")
    update_jobs()
    if not jobs:
        print(f"{BRIGHT_BLACK}No active jobs.{RESET}")
        return 0
    for job_id in sorted(jobs):
        job = jobs[job_id]
        status = job_status_name(job["status"])
        color = job_status_color(job["status"])
        print(
            f"{BRIGHT_CYAN}[{job_id}]{RESET} "
            f"{color}{safe_text(status):<8}{RESET} "
            f"{safe_text(job['command'])}"
        )
    return 0


def builtin_audit(args):
    """Show audit log."""
    if len(args) >= 2 and args[1] in {"verify", "archive"}:
        return operations.builtin_audit_integrity(args)
    if len(args) >= 2 and args[1].lower() == "risky":
        if len(args) > 3:
            return _usage("audit risky [threshold]")
        try:
            threshold = int(args[2]) if len(args) == 3 else 40
        except ValueError:
            return _usage("audit risky [integer threshold]")
        return audit_risky(max(0, min(threshold, RISK_MAX)))
    if len(args) >= 2 and args[1].lower() == "clear":
        if len(args) != 2:
            return _usage("audit clear")
        if not _confirmed("clear finalized command audit records (active commands are retained)?"):
            print(f"{BRIGHT_CYAN}Audit log was not cleared.{RESET}")
            return 1
        try:
            with closing(get_database_connection()) as connection:
                with connection:
                    connection.execute("DELETE FROM command_audit WHERE state NOT IN ('running', 'stopped')")
        except (sqlite3.Error, OSError) as error:
            return _error(f"could not clear audit log: {error}")
        print(f"{BRIGHT_GREEN}Argus: finalized audit records cleared; active commands retained.{RESET}")
        return 0

    return operations.builtin_query(_query_arguments(args), connect=get_database_connection)


def _query_arguments(args):
    """Accept convenient count/search/severity forms alongside composable flags."""
    result = list(args)
    if len(result) > 1 and result[1] == "search":
        return [result[0], "--search", " ".join(result[2:])]
    if len(result) > 1 and result[1].isdigit():
        result[1:2] = ["--limit", result[1]]
    if len(result) > 1 and result[0] == "suspicious" and result[1] in {"low", "medium", "high", "critical"}:
        result[1:2] = ["--severity", result[1]]
    if len(result) > 2 and result[1] == "detail":
        result[1:2] = ["--detail"]
    return result


def audit_risky(threshold):
    return operations.builtin_query(["audit", "--risk", str(threshold)],
                                    connect=get_database_connection)


def builtin_risk(args):
    """Analyze exactly one raw subject without executing or recording it."""
    if len(args) != 2:
        return _usage('risk "entire command subject" (exactly one quoted argument)')
    command_text = args[1]
    try:
        from .language import preview, command_text as canonical
        stages, uncertainties = preview(command_text, _runtime.state if _runtime else None)
    except (ValueError, SyntaxError) as error:
        return _error(f"risk: invalid subject: {error}")
    if not command_text.strip():
        return _usage('risk "nonempty command subject"')
    environment = _runtime.state.environment() if _runtime else None
    score, reasons = analyze_command_risk(command_text, stages, environment=environment)
    suspicious_hits = analyze_suspicious(canonical(stages))
    decision, reason = evaluate_security(
        command_text, score, suspicious_hits, stages=stages,
        administrative=administrative_command(stages), environment=environment)
    if uncertainties and decision == "allow":
        decision, reason = "unknown", "dynamic expansion requires runtime authorization"
    color = risk_color(score)
    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS RISK ANALYSIS{RESET}")
    print(f"{BRIGHT_CYAN}Command:{RESET} {safe_text(command_text)}")
    print(f"{BRIGHT_CYAN}Score:{RESET} {color}{BOLD}{score}{RESET} / {RISK_MAX}")
    print(f"{BRIGHT_CYAN}Level:{RESET} {color}{risk_level_name(score)}{RESET}")
    print(
        f"{BRIGHT_CYAN}Enforcement:{RESET} {BRIGHT_WHITE}{safe_text(decision)}{RESET}"
        f" ({safe_text(reason)})"
    )
    print("Preview only: subject is not executed or recorded; detector context is unchanged.")
    for uncertainty in uncertainties:
        print(f"Unknown dynamic expansion: {safe_text(uncertainty)}")
    print()
    print(f"{BRIGHT_PURPLE}{BOLD}MATCHED RISK RULES{RESET}")
    if reasons:
        for matched_reason in reasons:
            print(f"{BRIGHT_RED}  • {RESET}{safe_text(matched_reason)}")
    else:
        print(f"{BRIGHT_GREEN}No risk rules matched.{RESET}")
    print()
    print(f"{BRIGHT_PURPLE}{BOLD}SUSPICIOUS CHECKS (including current context){RESET}")
    if suspicious_hits:
        for rule, severity, matched_reason in suspicious_hits:
            print(f"  {safe_text(severity)}: {safe_text(rule)} — {safe_text(matched_reason)}")
    else:
        print(f"{BRIGHT_GREEN}No suspicious rules matched.{RESET}")
    print()
    return 0


def builtin_suspicious(args):
    """Query suspicious events with the shared composable filters."""
    return operations.builtin_query(_query_arguments(args), connect=get_database_connection)


def builtin_suspicious_stats(args=None):
    """Show suspicious event statistics."""
    if args is not None and len(args) != 1:
        return _usage("suspicious-stats")
    from .suspicious import suspicious_session_id, severity_color as sus_severity_color
    
    connection = None
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


    except (sqlite3.Error, OSError) as error:
        return _error(f"suspicious stats error: {error}")
    finally:
        if connection is not None:
            connection.close()

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS SUSPICIOUS STATISTICS{RESET}")
    print()
    print(f"{BRIGHT_CYAN}Total events:{RESET} {total}")
    print(f"{BRIGHT_CYAN}This session:{RESET} {session_total}")
    print(f"{BRIGHT_CYAN}Session ID:{RESET} {safe_text(suspicious_session_id)}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}BY SEVERITY{RESET}")
    print()

    if not by_severity:
        print(f"{BRIGHT_BLACK}No events recorded.{RESET}")
    else:
        for row in by_severity:
            color = sus_severity_color(row["severity"])
            print(
                f"{color}{safe_text(row['severity']):<10}{RESET}"
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
                f"{safe_text(row['rule_name']):<30}"
                f"{BRIGHT_WHITE}{row['total']}{RESET}"
            )

    print()

    return 0


def builtin_suspicious_clear(args):
    """Delete database rows only, leaving live detector memory unchanged."""
    if len(args) == 2 and args[1] in ("-h", "--help"):
        _usage("suspicious-clear [all]")
        print("Confirms deletion of stored events for this session (or all sessions).")
        print("Detector context and cooldowns are not reset.")
        return 0
    if len(args) > 2 or (len(args) == 2 and args[1].lower() != "all"):
        return _usage("suspicious-clear [all]")
    from .suspicious import suspicious_session_id
    all_sessions = len(args) == 2
    scope = "ALL sessions" if all_sessions else "this session"
    if not _confirmed(f"delete stored suspicious events for {scope}?"):
        print(f"{BRIGHT_CYAN}Not cleared.{RESET}")
        return 1
    try:
        with closing(get_database_connection()) as connection:
            with connection:
                if all_sessions:
                    cursor = connection.execute("DELETE FROM suspicious_events")
                else:
                    cursor = connection.execute(
                        "DELETE FROM suspicious_events WHERE session_id = ?",
                        (suspicious_session_id,),
                    )
                deleted = cursor.rowcount
    except (sqlite3.Error, OSError) as error:
        return _error(f"clear error: {error}")
    print(
        f"{BRIGHT_GREEN}Argus: deleted {deleted} stored events for {scope}; "
        f"detector context and cooldowns are unchanged.{RESET}"
    )
    return 0


def builtin_audit_stats(args=None):
    """Show audit statistics."""
    if args is not None and len(args) != 1:
        return _usage("audit-stats")
    connection = None
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


    except (sqlite3.Error, OSError) as error:
        return _error(f"statistics error: {error}")
    finally:
        if connection is not None:
            connection.close()

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
                f"{safe_text(row['command_name']):<20}"
                f"{BRIGHT_WHITE}{row['total']}{RESET}"
            )

    print()
    return 0


def _replace_policy(candidate):
    validated = validate_policy(candidate)
    security_policy.clear()
    security_policy.update(validated)


def _set_policy_field(field, value):
    candidate = copy.deepcopy(security_policy)
    path = field.split(".")
    if len(path) == 1 and path[0] in candidate:
        candidate[path[0]] = value
    elif len(path) == 2 and path[0] == "resource_limits" and path[1] in candidate[path[0]]:
        candidate[path[0]][path[1]] = value
    else:
        raise ValueError("unknown policy field")
    _replace_policy(candidate)


def builtin_security(args):
    """Validate the complete candidate before publishing any in-memory edit."""
    try:
        if len(args) == 1:
            print(json.dumps(security_policy, indent=2, ensure_ascii=True))
        elif args[1] == "set" and len(args) in {3, 4}:
            raw = args[3] if len(args) == 4 else input(args[2] + " (JSON): ")
            _set_policy_field(args[2], json.loads(raw))
        elif args[1] in {"mode", "threshold"} and len(args) == 3:
            _set_policy_field("mode" if args[1] == "mode" else "risk_threshold",
                              args[2] if args[1] == "mode" else int(args[2]))
        elif args[1] == "rule" and len(args) >= 3:
            action = args[2]
            if action == "list" and len(args) == 3:
                print(json.dumps(security_policy["command_rules"], indent=2, ensure_ascii=True))
                return 0
            if len(args) not in {4, 5} or action not in {"set", "edit", "remove"}:
                return _usage("security rule list|set EXEC JSON|edit EXEC|remove EXEC")
            candidate = copy.deepcopy(security_policy)
            name = args[3]
            if action == "remove" and len(args) == 4:
                if name not in candidate["command_rules"]:
                    raise ValueError("rule does not exist")
                del candidate["command_rules"][name]
            elif action == "set" and len(args) == 5:
                candidate["command_rules"][name] = json.loads(args[4])
            elif action == "edit" and len(args) == 4:
                print(json.dumps(candidate["command_rules"].get(name, {}), ensure_ascii=True))
                print("Rule fields: allowed_args, denied_args, input_roots, output_roots (JSON lists).")
                candidate["command_rules"][name] = json.loads(input("Replacement rule (JSON object): "))
            else:
                return _usage("security rule list|set EXEC JSON|edit EXEC|remove EXEC")
            _replace_policy(candidate)
        elif args[1:] == ["save"]:
            if not save_policy_to_disk():
                raise ValueError("policy was not saved")
        elif args[1:] == ["load"]:
            if not load_policy_from_disk():
                raise ValueError("no policy file found; active policy unchanged")
        elif args[1:] == ["reset"]:
            _replace_policy(DEFAULT_SECURITY_POLICY)
        else:
            return _usage("security [set FIELD [JSON]|mode NAME|threshold INTEGER|rule ...|save|load|reset]")
        return 0
    except (ValueError, OSError, EOFError) as error:
        return _error(error)


def _edit_list(args, field):
    removing = len(args) == 3 and args[1] in {"remove", "--remove"}
    if len(args) != (3 if removing else 2):
        return _usage(args[0] + " [remove] EXECUTABLE")
    name = args[-1]
    if not name or name.startswith("-") or "\x00" in name:
        return _usage(args[0] + " [remove] EXECUTABLE")
    candidate = copy.deepcopy(security_policy)
    if removing:
        if name not in candidate[field]:
            return _error("entry does not exist")
        candidate[field].remove(name)
    elif name not in candidate[field]:
        candidate[field].append(name)
    try:
        _replace_policy(candidate)
    except ValueError as error:
        return _error(error)
    return 0


def builtin_allow(args):
    return _edit_list(args, "allowlist")


def builtin_deny(args):
    return _edit_list(args, "denylist")


def builtin_allowlist(args=None):
    """Show allowlist and denylist."""
    if args is not None and len(args) != 1:
        return _usage("allowlist")
    allowlist = security_policy.get("allowlist", [])
    denylist = security_policy.get("denylist", [])

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS ALLOWLIST{RESET}")
    print()

    if allowlist:
        for name in sorted(allowlist):
            print(f"  {BRIGHT_GREEN}{safe_text(name)}{RESET}")
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    print(f"{BRIGHT_PURPLE}{BOLD}ARGUS DENYLIST{RESET}")
    print()

    if denylist:
        for name in sorted(denylist):
            print(f"  {BRIGHT_RED}{safe_text(name)}{RESET}")
    else:
        print(f"{BRIGHT_BLACK}  (empty){RESET}")

    print()
    return 0


def builtin_help(args=None):
    """Show help information."""
    if args is not None and len(args) != 1:
        return _usage("help")
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
        ("history [search TEXT|delete N|clear|private on/off|ignore ...|limit N]", "Manage durable private history"),
        ("redo", "Re-run the last command"),
        ("jobs", "Show jobs"),
        ("fg %1", "Bring job to foreground"),
        ("bg %1", "Continue job in background"),
        ("audit", "Show recent audit records"),
        ("audit 50", "Show last 50 audit records"),
        ("audit search ssh", "Search audit database"),
        ("audit clear", "Confirm deletion of stored command audit rows"),
        ("audit risky", "Show commands with risk >= 40"),
        ("audit risky 70", "Show commands with risk >= 70"),
        ("audit-stats", "Show audit statistics"),
        ('risk "entire command"', "Pure risk, suspicious and policy preview; exactly one subject"),
        ("suspicious", "Show recent suspicious events"),
        ("suspicious high", "Filter by severity"),
        ("suspicious search foo", "Search suspicious events"),
        ("suspicious-stats", "Show suspicious event stats"),
        ("suspicious-clear", "Confirm deletion of this session's stored events (memory unchanged)"),
        ("suspicious-clear all", "Confirm deletion of ALL stored events (memory unchanged)"),
        ("security", "Show current security policy"),
        ("security mode <name>", "Change mode (off/warn/confirm/block/allowlist/dry-run)"),
        ("security threshold 70", "Set risk threshold"),
        ("security save", "Save policy to disk"),
        ("security load", "Load policy from disk"),
        ("security reset", "Reset policy to defaults"),
        ("allow <command>", "Add command to allowlist"),
        ("deny <command>", "Add command to denylist"),
        ("allowlist", "Show allowlist and denylist"),
        ("allow remove <command> / deny remove <command>", "Remove one list entry"),
        ("security set FIELD [JSON]", "Set any validated field; dotted resource_limits fields"),
        ("security rule list|set EXEC JSON|edit EXEC|remove EXEC", "Author argument/redirection rules"),
        ("audit|suspicious|security-actions --session ID --cwd PATH --since ISO --until ISO", "Composable record filters"),
        ("audit|suspicious|security-actions --severity LEVEL --risk N --limit N --offset N", "Severity/risk/pagination"),
        ("audit|suspicious|security-actions --detail ID --format table|json|csv", "Full details/export"),
        ("audit verify PATH [--public-key FILE --anchor FILE]", "Verify signed chain and external trust anchor"),
        ("audit archive DEST [--encrypt --key-id NAME]", "Archive local audit records"),
        ("vault set|get|delete NAME; vault list; vault env NAME VARIABLE", "OS keyring secrets; hidden set prompt"),
        ("settings [list|get NAME|set NAME JSON]", "Validated persistent user settings"),
        ("redaction list|add REGEX|remove NUMBER|test", "Configure best-effort secret detection"),
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
    print(f"{BRIGHT_PURPLE}{BOLD}EDITOR SHORTCUTS{RESET}")
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
    print("  warn      - default; warnings only, lists/rules not enforced")
    print("  confirm   - prompt [y/N] on high-risk / suspicious")
    print("  block     - refuse to run high-risk / suspicious")
    print("  allowlist - require listed identities and pass risk/suspicious checks")
    print("  dry-run   - block execution/mutations; inspection, exit and explicit mode escape allowed")

    print()
    return 0
