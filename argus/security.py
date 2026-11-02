"""Validated user-assistance policy; this is not child-process confinement."""

import copy
import json
import os
import shutil
import sqlite3

from .config import ARGUS_POLICY_FILE, DEFAULT_SECURITY_POLICY, SECURITY_MODES, SEVERITY_RANK
from .database import get_database_connection, prune_records
from .risk import score_command
from .storage import atomic_write, private_directory, private_text, storage_warning
from .utils import (SESSION_ID, get_timestamp, get_current_username,
                    get_current_directory, redact_text, safe_text)


# Imported consumers retain this exact object for the lifetime of the session.
security_policy = copy.deepcopy(DEFAULT_SECURITY_POLICY)
_RULE_KEYS = {"allowed_args", "denied_args", "input_roots", "output_roots"}


def _strings(value, field, *, allow_empty=False):
    if not isinstance(value, list) or any(
        not isinstance(item, str) or "\x00" in item or (not item and not allow_empty)
        for item in value
    ):
        raise ValueError(field + " must be a list of valid strings")
    return list(value)


def validate_policy(data):
    """Build a complete independent policy, rejecting every invalid field."""
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    unknown = data.keys() - DEFAULT_SECURITY_POLICY.keys()
    if unknown:
        raise ValueError("unknown policy fields: " + ", ".join(sorted(unknown)))
    merged = copy.deepcopy(DEFAULT_SECURITY_POLICY)
    merged.update(copy.deepcopy(data))
    if type(merged["schema_version"]) is not int or merged["schema_version"] != 1:
        raise ValueError("unsupported policy schema_version")
    if not isinstance(merged["mode"], str) or merged["mode"] not in SECURITY_MODES:
        raise ValueError("unsupported policy mode")
    threshold = merged["risk_threshold"]
    if type(threshold) is not int or not 0 <= threshold <= 100:
        raise ValueError("risk_threshold must be an integer from 0 to 100")
    if type(merged["block_on_suspicious"]) is not bool:
        raise ValueError("block_on_suspicious must be boolean")
    severity = merged["suspicious_min_severity"]
    if not isinstance(severity, str) or severity not in SEVERITY_RANK:
        raise ValueError("invalid suspicious_min_severity")
    for key in ("allowlist", "denylist"):
        merged[key] = _strings(merged[key], key)
    supplied_limits = data.get("resource_limits", {})
    if not isinstance(supplied_limits, dict):
        raise ValueError("resource_limits must be an object")
    default_limits = DEFAULT_SECURITY_POLICY["resource_limits"]
    if supplied_limits.keys() - default_limits.keys():
        raise ValueError("unknown resource limit")
    limits = dict(default_limits)
    limits.update(supplied_limits)
    for key, value in limits.items():
        if key == "enabled":
            if type(value) is not bool:
                raise ValueError("resource_limits.enabled must be boolean")
        elif type(value) is not int or not 0 <= value <= 2**31 - 1:
            raise ValueError("resource_limits." + key + " must be a nonnegative bounded integer")
    merged["resource_limits"] = limits
    rules = merged["command_rules"]
    if not isinstance(rules, dict):
        raise ValueError("command_rules must be an object")
    for executable, rule in rules.items():
        if not isinstance(executable, str) or not executable or "\x00" in executable:
            raise ValueError("command_rules keys must name executables")
        if not isinstance(rule, dict) or rule.keys() - _RULE_KEYS:
            raise ValueError("invalid command_rules entry")
        for key, value in rule.items():
            _strings(value, "command_rules." + key, allow_empty=key.endswith("args"))
            if key.endswith("roots") and any(not os.path.isabs(root) for root in value):
                raise ValueError("redirection roots must be absolute paths")
    return merged


def load_policy_from_disk():
    """Missing policy uses defaults; unsafe/corrupt policy raises, never resets."""
    try:
        private_directory(os.path.dirname(os.path.abspath(ARGUS_POLICY_FILE)))
        with private_text(ARGUS_POLICY_FILE) as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return False
    validated = validate_policy(data)
    security_policy.clear()
    security_policy.update(validated)
    return True


def save_policy_to_disk():
    """Validate first and replace the private policy file atomically."""
    try:
        validated = validate_policy(security_policy)
        atomic_write(ARGUS_POLICY_FILE, json.dumps(validated, indent=2) + "\n")
    except (OSError, ValueError) as error:
        storage_warning("could not save policy", safe_text(error))
        return False
    return True


def log_security_action(mode, action, reason, command_line, risk_score=None,
                        suspicious_rules=None, session_id=None):
    """Persist a best-effort local action, visibly reporting failures."""
    connection = None
    try:
        connection = get_database_connection()
        connection.execute(
            """INSERT INTO security_actions
            (timestamp, username, cwd, session_id, mode, action, reason,
             command, risk_score, suspicious_rules) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (get_timestamp(), get_current_username(), get_current_directory(),
             session_id or SESSION_ID, mode, action, redact_text(reason),
             redact_text(command_line), risk_score,
             ",".join(hit[0] for hit in suspicious_rules) if suspicious_rules else None))
        prune_records(connection, "security_actions")
        connection.commit()
    except (sqlite3.Error, OSError) as error:
        storage_warning("could not persist security action", safe_text(error))
    finally:
        if connection is not None:
            connection.close()


def _identity(executable, assignments=None, environment=None):
    environment = dict(os.environ if environment is None else environment)
    environment.update(assignments or {})
    resolved = shutil.which(executable, path=environment.get("PATH", os.defpath))
    if resolved is None and (os.path.sep in executable or (os.altsep and os.altsep in executable)):
        resolved = executable
    return (executable, os.path.basename(executable),
            os.path.realpath(resolved) if resolved else None)


def _matches(entry, identity, *, assignments=None, environment=None):
    original, basename, resolved = identity
    if os.path.sep in entry or (os.altsep and os.altsep in entry):
        return resolved is not None and os.path.realpath(entry) == resolved
    if entry in (original, basename, os.path.basename(resolved) if resolved else None):
        return True
    effective = dict(os.environ if environment is None else environment)
    effective.update(assignments or {})
    entry_path = shutil.which(entry, path=effective.get("PATH", os.defpath))
    return bool(resolved and entry_path and os.path.realpath(entry_path) == resolved)


def _within(target, roots):
    canonical = os.path.realpath(target)
    for root in roots:
        try:
            if os.path.commonpath((canonical, os.path.realpath(root))) == os.path.realpath(root):
                return True
        except ValueError:
            continue
    return False


def command_text(stage):
    from .language import command_text as canonical
    return canonical(stage)


def analyze_command_risk(command_line, stages, *, environment=None):
    """Share effective expanded/resolved risk metadata with reports and audit."""
    subjects, canonical_subjects = [], []
    candidates = [command_line]
    for stage in stages:
        subject = command_text(stage)
        subjects.append(subject)
        if stage.argv:
            identity = _identity(stage.argv[0], stage.assignments, environment)
            canonical = " ".join(
                [os.path.basename(identity[2]) if identity[2] else stage.argv[0]]
                + stage.argv[1:])
            canonical += " " + " ".join(redir.operator + " " + redir.target
                                       for redir in stage.redirections)
            canonical_subjects.append(canonical)
            candidates.extend((subject, canonical))
    candidates.extend((" | ".join(subjects), " | ".join(canonical_subjects)))
    score, reasons = 0, []
    for candidate in candidates:
        value, matched = score_command(candidate)
        if value > score:
            score, reasons = value, list(matched)
        elif value == score:
            reasons.extend(reason for reason in matched if reason not in reasons)
    return score, reasons

def administrative_command(commands, background=False):
    """Identify explicit single-command controls, never raw source prefixes."""
    return (not background and len(commands) == 1 and bool(commands[0].argv)
            and not commands[0].redirections and not commands[0].assignments
            and commands[0].argv[0] in {
                "pwd", "env", "history", "jobs", "security", "allow", "deny",
                "allowlist", "audit", "audit-stats", "suspicious", "suspicious-stats",
                "suspicious-clear", "security-actions", "risk", "help", "exit",
                "settings", "redaction", "vault"})

def _preview_inspection(argv):
    name = argv[0]
    if name == "security":
        return len(argv) == 1 or (len(argv) == 3 and argv[1].lower() == "mode" and argv[2].lower() in SECURITY_MODES)
    if name == "audit":
        return len(argv) == 1 or argv[1].lower() not in {"clear", "archive"}
    if name == "history":
        return len(argv) == 1 or argv[1] in {"show", "search"}
    if name in {"settings", "redaction"}:
        return len(argv) == 1 or argv[1] in {"list", "get", "test"}
    if name == "vault":
        return len(argv) == 2 and argv[1] == "list"
    return name in {"pwd", "env", "jobs", "help", "exit", "risk",
                    "audit-stats", "suspicious", "suspicious-stats", "allowlist",
                    "security-actions"}


def evaluate_security(command_line, risk_score, suspicious_hits, *, stages=None,
                      administrative=False, environment=None):
    """Authorize all parsed stages before launch; no claims about child behavior.

    Off/warn preserve advisory semantics. Enforcing modes apply every matching
    command rule (exact argument membership and canonical redirection roots).
    Allowlist mode also checks risk and suspicious hits, with blocking semantics.
    """
    try:
        policy = validate_policy(security_policy)
        if stages is None:
            from .language import preview
            stages, uncertainties = preview(command_line)
            if uncertainties:
                return "deny", "dynamic command requires runtime authorization"
        for stage in stages:
            if (not isinstance(stage.argv, list)
                    or any(not isinstance(arg, str) or "\x00" in arg for arg in stage.argv)
                    or (stage.argv and not stage.argv[0])):
                raise ValueError("invalid executable arguments")
            if any(not isinstance(key, str) or not isinstance(value, str)
                   or "\x00" in key or "\x00" in value
                   for key, value in stage.assignments.items()):
                raise ValueError("invalid command assignments")
            for redirection in stage.redirections:
                if (type(redirection.fd) is not int or redirection.fd < 0
                        or redirection.operator not in {
                            "<", ">", ">>", "<>", ">|", "<&", ">&", "&>", "&>>",
                            "<<", "<<-", "<<<"}
                        or not isinstance(redirection.target, str)
                        or "\x00" in redirection.target):
                    raise ValueError("invalid redirection")
    except (ValueError, TypeError, AttributeError) as error:
        return "deny", "invalid command or policy: " + str(error)
    mode = policy["mode"]
    inspection = (administrative and administrative_command(stages)
                  and _preview_inspection(stages[0].argv))
    if mode == "dry-run" and not inspection:
        return "deny", "dry-run mode (not executed)"
    if mode in ("off", "warn"):
        return "allow", "mode=" + mode
    for stage in stages:
        if not stage.argv:
            continue
        identity = _identity(stage.argv[0], stage.assignments, environment)
        if any(_matches(entry, identity, assignments=stage.assignments, environment=environment)
               for entry in policy["denylist"]):
            return "deny", repr(stage.argv[0]) + " matches denylist executable identity"
        if mode == "allowlist" and not any(
                _matches(entry, identity, assignments=stage.assignments, environment=environment)
                for entry in policy["allowlist"]):
            return "deny", repr(stage.argv[0]) + " not in allowlist"
        for executable, rule in policy["command_rules"].items():
            if not _matches(executable, identity, assignments=stage.assignments, environment=environment):
                continue
            args = stage.argv[1:]
            if "allowed_args" in rule and any(arg not in rule["allowed_args"] for arg in args):
                return "deny", "argument not permitted for " + repr(stage.argv[0])
            if any(arg in rule.get("denied_args", ()) for arg in args):
                return "deny", "argument denied for " + repr(stage.argv[0])
            for redirection in stage.redirections:
                operator, target = redirection.operator, redirection.target
                if operator in {"<<", "<<-", "<<<"}:
                    continue
                if operator in {"<&", ">&"}:
                    if target == "-" or target.rstrip("-").isdigit():
                        continue
                    return "deny", "invalid descriptor duplication"
                roots = []
                if operator in {"<", "<>"}:
                    roots.append("input_roots")
                if operator in {">", ">>", ">|", "<>", "&>", "&>>"}:
                    roots.append("output_roots")
                for key in roots:
                    if key in rule and not _within(target, rule[key]):
                        return "deny", "redirection target outside configured " + key
    if inspection and mode == "dry-run":
        return "allow", "parsed inspection/control command"
    risk_score = max(risk_score, analyze_command_risk(
        command_line, stages, environment=environment)[0])
    threshold = policy["risk_threshold"]
    if risk_score >= threshold:
        return ("confirm" if mode == "confirm" else "deny",
                "risk %s >= threshold %s" % (risk_score, threshold))
    if policy["block_on_suspicious"]:
        minimum = SEVERITY_RANK[policy["suspicious_min_severity"]]
        for rule, severity, _reason in suspicious_hits:
            if SEVERITY_RANK.get(severity, 0) >= minimum:
                return ("confirm" if mode == "confirm" else "deny",
                        "suspicious rule %r (%s)" % (rule, severity))
    return "allow", "no policy violation"
