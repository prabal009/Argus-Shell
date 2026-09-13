"""
Configuration constants and default settings for Argus.
"""

import os
import re

# ============================================================
# HISTORY CONFIGURATION
# ============================================================

HISTORY_FILE = os.path.expanduser("~/.argus_history")
HISTORY_LIMIT = 1000

# ============================================================
# ARGUS DATA DIRECTORY
# ============================================================

ARGUS_DATA_DIR = os.path.expanduser("~/.argus")
ARGUS_DATABASE = os.path.join(ARGUS_DATA_DIR, "argus.db")
ARGUS_POLICY_FILE = os.path.join(ARGUS_DATA_DIR, "policy.json")

# ============================================================
# RISK SCORING CONFIGURATION
# ============================================================

RISK_MAX = 100

RISK_LEVELS = [
    (0, "safe", "\033[92m"),
    (20, "low", "\033[96m"),
    (40, "medium", "\033[93m"),
    (70, "high", "\033[91m"),
    (90, "critical", "\033[95m"),
]

RISK_RULES = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*\s+)+/\s*$"),
     95, "recursive delete of root"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$"),
     95, "rm -rf /"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:"),
     100, "fork bomb"),
    (re.compile(r"\bmkfs(\.\w+)?\b"),
     90, "format filesystem"),
    (re.compile(r"\bdd\b.*\bof=/dev/[sh]d[a-z]"),
     90, "raw write to block device"),
    (re.compile(r">\s*/dev/[sh]d[a-z]"),
     90, "redirect to raw disk"),
    (re.compile(r"/dev/tcp/"),
     90, "bash reverse shell"),
    (re.compile(r"\bnc\b.*\s-e\s"),
     90, "netcat exec (reverse shell)"),
    (re.compile(r"\bbase64\s+(-d|--decode)\b.*\|\s*(ba)?sh\b"),
     90, "base64 decode piped to shell"),
    (re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh\b"),
     90, "download piped to shell"),
    (re.compile(r"\bchmod\s+777\s+/\s*$"),
     90, "chmod 777 on root"),
    (re.compile(r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*f"),
     75, "recursive force delete"),
    (re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]"),
     75, "recursive force delete"),
    (re.compile(r"\brm\s+-rf\b"),
     75, "rm -rf"),
    (re.compile(r"\bsudo\b"),
     40, "privilege escalation"),
    (re.compile(r"\bsu\b(\s|$)"),
     40, "switch user"),
    (re.compile(r"\b(shutdown|reboot|halt|poweroff)\b"),
     70, "system shutdown/reboot"),
    (re.compile(r"\bkill(all)?\s+-9\b"),
     70, "SIGKILL"),
    (re.compile(r"\b(pkill|killall)\b"),
     60, "bulk process kill"),
    (re.compile(r"\biptables\b"),
     75, "firewall modification"),
    (re.compile(r"\b(useradd|userdel|usermod|groupadd|groupdel)\b"),
     70, "user/group management"),
    (re.compile(r"\bpasswd\b"),
     60, "password change"),
    (re.compile(r"\bcrontab\b"),
     65, "scheduled task modification"),
    (re.compile(r"\bsystemctl\b.*\b(stop|disable|mask)\b"),
     65, "service shutdown"),
    (re.compile(r"\bchown\b.*-R\b"),
     70, "recursive ownership change"),
    (re.compile(r"\bchmod\b.*-R\b.*777"),
     80, "recursive world-writable"),
    (re.compile(r"/etc/(shadow|sudoers|passwd)\b"),
     75, "sensitive auth file access"),
    (re.compile(r"\bhistory\s+-c\b"),
     65, "history wipe"),
    (re.compile(r"\bunset\s+HISTFILE\b"),
     70, "disable history logging"),
    (re.compile(r"\bexport\s+HISTFILE=/dev/null\b"),
     70, "disable history logging"),
    (re.compile(r"\bchmod\s+777\b"),
     55, "world-writable permissions"),
    (re.compile(r"\bchmod\s+\+s\b"),
     60, "setuid/setgid bit"),
    (re.compile(r"\bmount\b"),
     50, "filesystem mount"),
    (re.compile(r"\bumount\b"),
     50, "filesystem unmount"),
    (re.compile(r"\b(curl|wget)\b"),
     45, "network download"),
    (re.compile(r"\bssh\b"),
     40, "remote shell"),
    (re.compile(r"\bscp\b"),
     40, "remote copy"),
    (re.compile(r"\bnc\b|\bnetcat\b"),
     50, "netcat usage"),
    (re.compile(r"\b(nmap|masscan)\b"),
     60, "network scanner"),
    (re.compile(r"\b(tcpdump|wireshark|tshark)\b"),
     55, "packet capture"),
    (re.compile(r"\b(find|locate)\b.*\s-perm\b"),
     45, "permission search"),
    (re.compile(r"\bfind\b.*-name\s+\.ssh"),
     60, "SSH key discovery"),
    (re.compile(r"\bgit\s+push\b.*--force"),
     55, "force push"),
    (re.compile(r"\bgit\s+reset\b.*--hard"),
     55, "hard reset"),
    (re.compile(r"\bdocker\s+(rm|rmi|system\s+prune)\b"),
     45, "docker cleanup"),
    (re.compile(r"\bkubectl\s+delete\b"),
     55, "kubernetes delete"),
    (re.compile(r"\baws\s+.*\b(delete|terminate|destroy)\b"),
     65, "AWS destructive action"),
    (re.compile(r"\bgcloud\s+.*\bdelete\b"),
     65, "GCP delete"),
    (re.compile(r"\baz\s+.*\bdelete\b"),
     65, "Azure delete"),
    (re.compile(r"\b(curl|wget)\b.*-o\s"),
     25, "download to file"),
    (re.compile(r"\bpip\s+install\b"),
     25, "package install"),
    (re.compile(r"\bnpm\s+install\b"),
     25, "package install"),
    (re.compile(r"\bapt(-get)?\s+install\b"),
     30, "package install"),
    (re.compile(r"\byum\s+install\b"),
     30, "package install"),
    (re.compile(r"\bbrew\s+install\b"),
     25, "package install"),
    (re.compile(r"\bcp\b.*\s-r\b|\bcp\b.*\s-R\b"),
     30, "recursive copy"),
    (re.compile(r"\bmv\b"),
     20, "move/rename"),
    (re.compile(r"\bkill\b"),
     35, "process kill"),
]

# ============================================================
# SUSPICIOUS DETECTION CONFIGURATION
# ============================================================

SUSPICIOUS_WINDOW_SIZE = 50
SUSPICIOUS_SEQUENCE_WINDOW_SECONDS = 60
SUSPICIOUS_COOLDOWN_SECONDS = 30
SUSPICIOUS_REPEAT_COUNT = 5
SUSPICIOUS_REPEAT_SECONDS = 20

_SUSPICIOUS_SEQUENCE_SPECS = [
    (
        "recon_then_destroy",
        "critical",
        [
            r"\b(whoami|id|uname)\b",
            r"\b(cat|less|head)\s+/etc/(passwd|shadow)\b",
            r"\b(rm\s+-rf|dd\b.*of=/dev/|mkfs)\b",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "reconnaissance followed by destructive command"
    ),
    (
        "priv_esc_then_persist",
        "critical",
        [
            r"\bsudo\b",
            r"\b(chmod\s+\+s|chmod\s+777\b)\b",
            r"\b(crontab|systemctl\s+enable|at\s+)\b",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "privilege escalation followed by persistence"
    ),
    (
        "download_then_exec",
        "high",
        [
            r"\b(curl|wget)\b",
            r"\bchmod\s+\+x\b",
            r"\./",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "downloaded file then made executable and run"
    ),
    (
        "reverse_shell_setup",
        "critical",
        [
            r"\b(nc|ncat|netcat)\b",
            r"(/dev/tcp/|\bnc\b.*\s-e\s)",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "reverse shell setup"
    ),
    (
        "credential_harvest",
        "high",
        [
            r"\b(find|locate)\b.*(\.ssh|id_rsa|\.pem)",
            r"\b(cat|scp|curl)\b",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "SSH key discovery followed by exfiltration"
    ),
    (
        "history_tamper",
        "high",
        [
            r"\b(history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=/dev/null)\b",
            r"\b(rm|shred|truncate)\b.*\.(bash_history|zsh_history|argus_history)",
        ],
        SUSPICIOUS_SEQUENCE_WINDOW_SECONDS,
        "history wipe followed by history file deletion"
    ),
]

SUSPICIOUS_SEQUENCE_RULES = [
    (
        name,
        severity,
        [re.compile(p) for p in patterns],
        window,
        reason
    )
    for (name, severity, patterns, window, reason) in _SUSPICIOUS_SEQUENCE_SPECS
]

SUSPICIOUS_PATTERNS = [
    (
        "obfuscated_shell",
        "critical",
        re.compile(
            r"\$IFS|\$\{IFS\}|"
            r"\bbase64\s+(-d|--decode)\b|"
            r"\bxxd\s+-r\b|"
            r"\beval\b.*\$\(|"
            r"\beval\b.*`|"
            r"\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}"
        ),
        "obfuscated shell command"
    ),
    (
        "encoded_pipe_to_shell",
        "critical",
        re.compile(
            r"\b(echo|printf)\b.*\|.*\b(base64|xxd|openssl)\b.*\|.*\b(sh|bash|zsh)\b"
        ),
        "encoded payload piped to shell"
    ),
    (
        "inline_shell_via_alt",
        "high",
        re.compile(
            r"\b(python|python3|perl|ruby|node)\b\s+-[ce]\b.*\b(exec|system|eval|os\.popen|subprocess)\b"
        ),
        "inline interpreter exec"
    ),
    (
        "hidden_command",
        "medium",
        re.compile(
            r"(^|\s)\./\.[A-Za-z0-9_]+|"
            r"\s/[A-Za-z0-9_/]*/\.[A-Za-z0-9_]+"
        ),
        "hidden executable invoked"
    ),
    (
        "unset_secure_path",
        "high",
        re.compile(
            r"\bunset\s+PATH\b|"
            r"\bexport\s+PATH\s*=\s*[\"']?\s*[\"']?$|"
            r"\bexport\s+PATH\s*=\s*\."
        ),
        "PATH manipulation"
    ),
    (
        "sudoers_modify",
        "critical",
        re.compile(
            r">>?\s*/etc/sudoers|"
            r"\bvisudo\b|"
            r"\btee\s+/etc/sudoers"
        ),
        "sudoers modification"
    ),
    (
        "cron_persistence",
        "high",
        re.compile(
            r"\bcrontab\s+-e\b|"
            r">>?\s*/etc/cron\.|"
            r">>?\s*/var/spool/cron/"
        ),
        "cron persistence"
    ),
    (
        "ssh_authorized_keys_write",
        "critical",
        re.compile(
            r">>?\s*.*\.ssh/authorized_keys|"
            r"\btee\b.*\.ssh/authorized_keys"
        ),
        "SSH key installation"
    ),
    (
        "reverse_shell_classic",
        "critical",
        re.compile(
            r"\bbash\s+-i\b.*>&\s*/dev/tcp/|"
            r"\bsh\s+-i\b.*>&\s*/dev/tcp/|"
            r"\bnc\b.*\s-e\s+/(bin/)?(ba)?sh"
        ),
        "classic reverse shell"
    ),
    (
        "log_deletion",
        "high",
        re.compile(
            r"\brm\b.*(/var/log/|\.log\b)|"
            r"\bshred\b.*(/var/log/|\.log\b)|"
            r">\s*/var/log/"
        ),
        "log deletion"
    ),
]

# ============================================================
# SECURITY / SANDBOX CONFIGURATION
# ============================================================

SECURITY_MODE_DEFAULT = "warn"

SECURITY_MODES = (
    "off",
    "warn",
    "confirm",
    "block",
    "allowlist",
    "dry-run",
)

DEFAULT_SECURITY_POLICY = {
    "mode": SECURITY_MODE_DEFAULT,
    "risk_threshold": 70,
    "block_on_suspicious": True,
    "suspicious_min_severity": "high",
    "allowlist": [
        "ls", "pwd", "cd", "cat", "echo", "head", "tail", "wc",
        "grep", "find", "sort", "uniq", "which", "whoami", "id",
        "date", "uname", "env", "printenv", "file", "stat",
        "history", "jobs", "audit", "audit-stats", "risk",
        "suspicious", "suspicious-stats", "suspicious-clear",
        "security", "allow", "deny", "allowlist", "redo",
        "help", "exit",
        "git", "python", "python3", "pip", "pip3",
        "node", "npm", "cargo", "rustc", "go",
    ],
    "denylist": [],
    "resource_limits": {
        "enabled": False,
        "cpu_seconds": 60,
        "memory_mb": 512,
        "max_processes": 0,
        "file_size_mb": 100,
        "open_files": 256,
    },
}

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
