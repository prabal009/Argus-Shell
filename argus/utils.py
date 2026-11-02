"""Identity, timestamps, and safe presentation/persistence helpers."""

import os
import re
import uuid
from datetime import datetime

SESSION_ID = uuid.uuid4().hex
_SECRET_NAME = r'(?:[A-Za-z_][A-Za-z0-9_]*_)?(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)'
_ASSIGNMENT_SECRET = re.compile(r'(?i)(\b' + _SECRET_NAME + r'\s*=\s*)("[^"\n]*"|\'[^\'\n]*\'|[^\s]+)')
_OPTION_SECRET = re.compile(r'(?i)(--(?:password|passwd|token|secret|api-key|access-key)(?:=|\s+))("[^"\n]*"|\'[^\'\n]*\'|[^\s]+)')
_URL_SECRET = re.compile(r'(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)')
_registered_secrets = set()


def register_secret(value):
    """Keep retrieved vault values out of subsequent local presentation records."""
    if value:
        _registered_secrets.add(str(value))


def unregister_secret(value):
    _registered_secrets.discard(str(value))


def secret_values():
    """Private worker handoff; values must never be printed or logged."""
    return tuple(_registered_secrets)


def get_identity():
    if os.name == "nt":
        from .winsecurity import current_sid, current_username
        return {"uid": None, "euid": None, "username": current_username(), "sid": current_sid()}
    import pwd
    uid = os.getuid()
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = str(uid)
    return {"uid": uid, "euid": os.geteuid(), "username": username, "sid": None}


def get_current_username():
    return get_identity()['username']


def get_current_directory():
    try:
        return os.getcwd()
    except OSError:
        return 'unknown'


def get_timestamp():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def get_command_name(command):
    return command[0] if command else ''


def safe_text(value):
    """Escape terminal controls, including bidi/format characters, not executable data."""
    return ''.join(ch if ch.isprintable() else ch.encode('unicode_escape').decode('ascii') for ch in str(value))


def redact_text(value):
    """Best-effort common credential forms; arbitrary secrets cannot be recognized."""
    text = str(value)
    text = _ASSIGNMENT_SECRET.sub(lambda m: m[1] + '[REDACTED]', text)
    text = _OPTION_SECRET.sub(lambda m: m[1] + '[REDACTED]', text)
    text = _URL_SECRET.sub(lambda m: m[1] + '[REDACTED]' + m[2], text)
    for secret in sorted(_registered_secrets, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    from .config import get_settings
    for pattern in get_settings().get("redaction_patterns", []):
        text = re.sub(pattern, "[REDACTED]", text)
    return text
