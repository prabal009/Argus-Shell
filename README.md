# Argus

A security-focused Unix shell written in pure Python.

Zero dependencies. Every command is audited to SQLite, scored for risk, 
checked against suspicious patterns, and — if you enable it — blocked 
or confirmed before it runs. The codebase is organized into clean, 
modular components for maintainability and extensibility.

## Features

- **Full Unix shell** — pipes, input/output/append redirection, background jobs, `Ctrl+C`, `Ctrl+Z`, `fg`, `bg`
- **SQLite audit log** — every command persisted with timestamp, cwd, user, exit status, duration, and risk score
- **Risk scoring** — 60+ regex rules produce a 0–100 score with per-rule reasons
- **Suspicious detection** — single-command patterns (reverse shells, obfuscation, persistence) and cross-command sequences within a rolling 60-second window
- **Enforcement modes** — `warn`, `confirm`, `block`, `allowlist`, `dry-run`, `off`
- **Resource limits** — CPU, memory, file size, open files on child processes (Unix only)
- **Zero third-party dependencies** — pure Python stdlib

## Requirements

- Python 3.8+
- A Unix-like OS: Linux, macOS, WSL, or BSD
- Native Windows is not supported — Argus relies on `fork()`, process groups, and `tcsetpgrp()`, which do not exist on Windows.

**Note:** While the shell itself requires Unix, the Python package can be imported on Windows (with graceful degradation for Unix-only features like readline). This enables Windows users to analyze shell scripts or use Argus components in Windows-based Python tools.

## Quick Start

###  For End Users (Simplest)
```bash
pip install argus-shell
argus
```

###  For Developers (Development setup)
```bash
git clone <repo>
cd argus
pip install -e .
argus
```

###  For Testing (No installation)
```bash
cd argus
python3 argus_shell.py
```

## Install

### Option A — Install from the repository with pip (recommended for development)

    cd argus
    pip install .

This installs Argus as a Python package and adds the `argus` command to your PATH.

For development mode (editable install, changes reflected immediately):

    pip install -e .

### Option B — Install in a Virtual Environment (recommended for production)

    # Create virtual environment
    python3 -m venv argus_env
    
    # Activate it
    source argus_env/bin/activate      # Linux/macOS
    # or
    argus_env\Scripts\activate         # Windows
    
    # Install
    pip install .
    
    # Run
    argus

### Option C — Install from PyPI (when published to package registry)

    pip install argus-shell
    argus

### Option D — Run directly without installation

    cd argus
    python3 argus_shell.py

No `pip install`, no virtualenv, no build step. Just run directly.

For system-wide installation, see options 2 and 3 in the Running Argus section below.

## Running Argus

There are three ways to start the shell. All of them work from the repository directory.

### Option 1 — Run with Python directly (recommended)

    python3 argus_shell.py

This is the simplest and most portable method. It works on every supported platform.

If your system only has python (not python3):

    python argus_shell.py

Alternatively, run as a module:

    python3 -m argus.main

### Option 2 — Make it executable and run it as a script

    chmod +x argus_shell.py
    ./argus_shell.py

The chmod command only needs to be run once. After that, `./argus_shell.py` will start the shell.

### Option 3 — Put it on your PATH and run it from anywhere

    chmod +x argus_shell.py
    sudo mv argus_shell.py /usr/local/bin/argus

Then start it from any directory:

    argus

This is the closest thing to installing Argus system-wide without a package manager.

## Verify Installation

After installation, verify everything works:

    # Check if argus command is available
    which argus
    
    # Check package information
    pip show argus-shell
    
    # Test importing the module
    python3 -c "import argus; print('✓ Argus imported successfully')"
    
    # Start the shell
    argus
    
    # Inside the shell, test a basic command
    Argus [~] > pwd
    Argus [~] > ls
    Argus [~] > exit

## Architecture

Argus is organized into a modular Python package for better maintainability and extensibility:

- **`argus/`** — Main package containing all shell logic
  - **`main.py`** — Main shell loop and command execution engine
  - **`builtins.py`** — All built-in shell commands (cd, pwd, audit, risk, etc.)
  - **`execution.py`** — Command parsing, tokenization, and pipeline handling
  - **`jobs.py`** — Background/foreground job management
  - **`risk.py`** — Risk scoring based on command patterns
  - **`suspicious.py`** — Detection of suspicious activity
  - **`security.py`** — Security policy management and enforcement
  - **`audit.py`** — Command auditing and logging
  - Plus supporting modules for database, colors, config, and utilities

For detailed module documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Deployment & Packaging

Argus includes modern Python packaging files for easy distribution:

- **`setup.py`** — Traditional setuptools configuration
- **`pyproject.toml`** — Modern PEP 518 build configuration
- **`requirements.txt`** — Dependency documentation (empty for stdlib-only project)

The package is published as **`argus-shell`** on PyPI and can be installed with:

    pip install argus-shell

For details about packaging, building, and publishing, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Usage

Run any command you would run in a normal shell:

    Argus [~] > ls -la
    Argus [~] > cat file.txt | grep foo | wc -l
    Argus [~] > sleep 5 &
    Argus [~] > echo hello > /tmp/x

Every command is audited automatically. Inspect the log with:

    Argus [~] > audit              # last 20 commands
    Argus [~] > audit 50           # last 50
    Argus [~] > audit risky 70     # only risk >= 70
    Argus [~] > audit search ssh   # search command text, cwd, user
    Argus [~] > audit-stats        # aggregated totals

Score a command without running it:

    Argus [~] > risk rm -rf /

Look at suspicious activity:

    Argus [~] > suspicious
    Argus [~] > suspicious critical
    Argus [~] > suspicious search base64
    Argus [~] > suspicious-stats

Manage enforcement:

    Argus [~] > security
    Argus [~] > security mode confirm
    Argus [~] > security mode block
    Argus [~] > security mode allowlist
    Argus [~] > security threshold 50
    Argus [~] > security save
    Argus [~] > security load
    Argus [~] > security reset

Manage the allowlist and denylist:

    Argus [~] > allow curl
    Argus [~] > deny nc
    Argus [~] > allowlist

Re-run the last command:

    Argus [~] > redo

See `help` inside the shell for the full command list.

## Command reference

| Command | Description |
|---|---|
| `cd <dir>` | Change directory |
| `cd -` | Return to previous directory |
| `pwd` | Print working directory |
| `export NAME=value` | Set environment variable |
| `unset NAME` | Remove environment variable |
| `env` | Show environment |
| `history` | Show command history |
| `redo` | Re-run the last command |
| `jobs` | List jobs |
| `fg %N` | Bring job N to foreground |
| `bg %N` | Continue job N in background |
| `audit [N]` | Show last N audit records |
| `audit search <term>` | Search audit records |
| `audit risky [score]` | Show commands with risk >= score |
| `audit clear` | Delete all audit records |
| `audit-stats` | Show aggregate statistics |
| `risk <command>` | Score a command without running it |
| `suspicious [N]` | Show recent suspicious events |
| `suspicious <severity>` | Filter by low/medium/high/critical |
| `suspicious search <term>` | Search suspicious events |
| `suspicious-stats` | Show suspicious event stats |
| `suspicious-clear` | Clear current session events |
| `suspicious-clear all` | Clear all suspicious events |
| `security` | Show current security policy |
| `security mode <name>` | Change mode |
| `security threshold <n>` | Set risk threshold |
| `security save` | Save policy to disk |
| `security load` | Load policy from disk |
| `security reset` | Reset to defaults |
| `allow <command>` | Add to allowlist |
| `deny <command>` | Add to denylist |
| `allowlist` | Show allowlist and denylist |
| `help` | Show help |
| `exit` | Exit Argus |

## Operators

| Operator | Meaning |
|---|---|
| `cmd1 \| cmd2` | Pipe stdout of cmd1 to stdin of cmd2 |
| `cmd < file` | Redirect stdin from file |
| `cmd > file` | Redirect stdout to file (truncate) |
| `cmd >> file` | Redirect stdout to file (append) |
| `cmd &` | Run cmd in background |

Not supported yet: `&&`, `||`, `2>`, `2>>`, `&>`, process substitution.

## Keyboard shortcuts

Inside Argus (readline bindings):

| Key | Action |
|---|---|
| `Ctrl+R` | Reverse history search |
| `Ctrl+S` | Forward history search |
| `Ctrl+L` | Clear screen |
| `Up` / `Down` | Navigate history |
| `Alt+.` | Insert last argument of previous command |
| `Ctrl+C` | Interrupt foreground process |
| `Ctrl+Z` | Suspend foreground process (resume with `fg`) |

### Clipboard shortcuts

Argus does not implement Ctrl+Shift+C or Ctrl+Shift+V itself. Those are handled by your terminal emulator, not by the shell running inside it.

On most terminals these already work:

| Terminal | Copy | Paste |
|---|---|---|
| GNOME Terminal | `Ctrl+Shift+C` | `Ctrl+Shift+V` |
| Konsole | `Ctrl+Shift+C` | `Ctrl+Shift+V` |
| Windows Terminal | `Ctrl+Shift+C` | `Ctrl+Shift+V` |
| Kitty | `Ctrl+Shift+C` | `Ctrl+Shift+V` |
| iTerm2 (macOS) | `Cmd+C` | `Cmd+V` |
| Terminal.app (macOS) | `Cmd+C` | `Cmd+V` |

If copy and paste does not work in your terminal, configure it there. It cannot be set from inside Argus.

## Enforcement modes

| Mode | Behavior |
|---|---|
| `off` | No enforcement. Warnings only. |
| `warn` | Default. Print warnings, always run. |
| `confirm` | Prompt `[y/N]` for high-risk or suspicious commands. |
| `block` | Refuse to run high-risk or suspicious commands. |
| `allowlist` | Only commands in the allowlist may run. |
| `dry-run` | Classify commands but never execute them. |

A command is high-risk when its risk score is at or above the configured `risk_threshold` (default `70`). A command is suspicious when it matches a detection rule at or above `suspicious_min_severity` (default `high`).

## How risk scoring works

Every command line is matched against a set of regex rules. Each match adds points and a human-readable reason. The total is clamped to 100.

Representative rules:

| Pattern | Score | Reason |
|---|---|---|
| `rm -rf /` | 95 | recursive delete of root |
| `curl ... \| sh` | 90 | download piped to shell |
| `chmod 777 /` | 90 | chmod 777 on root |
| `sudo` | 40 | privilege escalation |
| `chmod 777` | 55 | world-writable permissions |

The full list lives in `RISK_RULES` inside `argus.py`.

## How suspicious detection works

Three engines run on every command line:

1. Single-command patterns — regexes for obfuscation (`$IFS`, `base64 -d | sh`), reverse shells (`bash -i >& /dev/tcp/...`), persistence writes (`>> /etc/sudoers`, `crontab -e`), log deletion (`rm /var/log/*`), PATH manipulation, etc.
2. Sequence detection — ordered patterns across the last 50 commands within 60 seconds. For example: `whoami` then `cat /etc/passwd` then `rm -rf`.
3. Repetition detection — the same command 5 or more times in 20 seconds.

Hits are written to the `suspicious_events` table and can trigger enforcement in `confirm` and `block` modes.

## Files created

Argus stores its data under `~/.argus/`:

    ~/.argus/argus.db         # SQLite: command_audit, suspicious_events, security_actions
    ~/.argus/policy.json      # optional; written by "security save"
    ~/.argus_history          # readline command history

The data directory is created with mode `0700`.

You can query the database directly:

    sqlite3 ~/.argus/argus.db "SELECT timestamp, command, risk_score FROM command_audit ORDER BY id DESC LIMIT 10;"

## Policy file

`security save` writes a JSON file to `~/.argus/policy.json`. Sample:

    {
      "mode": "warn",
      "risk_threshold": 70,
      "block_on_suspicious": true,
      "suspicious_min_severity": "high",
      "allowlist": ["ls", "pwd", "cd", "cat", "echo", "grep", "git"],
      "denylist": [],
      "resource_limits": {
        "enabled": false,
        "cpu_seconds": 60,
        "memory_mb": 512,
        "max_processes": 0,
        "file_size_mb": 100,
        "open_files": 256
      }
    }

`max_processes: 0` means no process-count limit. Setting it to a positive number uses `RLIMIT_NPROC`, which on Linux is per-user and can lock out your whole session. Use with care.

A sample is included in `examples/policy.json`.

## Limitations

- Heuristic, not magic. Regex rules catch common patterns, not novel attacks. Argus is a visibility and guardrail tool, not a sandbox against a determined adversary who already has shell access to your account.
- Unix only. No Windows support.
- Enforcement runs on the raw command line before variable expansion. `echo $EVIL` where `$EVIL="rm -rf /"` will not be blocked by the `rm -rf` rule.
- Allowlist mode matches only the first token. `git` allowed means all `git` subcommands are allowed.
- Resource limits depend on `resource.setrlimit`. On macOS some limits behave differently from Linux. Test on your target OS.
- Redirection inside pipelines is not supported. `cmd > file | cmd2` is rejected with a clear error.
- Builtins cannot run inside pipelines or in the background. `echo hi | cd` and `cd &` are rejected with clear errors.

## Security notes

Argus is a shell. It executes whatever you type. It is not a hardened sandbox — it is a shell with observability and policy layers on top. If you are worried about a specific attacker with local access, this is the wrong tool. If you want to see, score, and gate the commands you run, this is the right tool.

## Contributing

Issues and pull requests are welcome. If you add a risk rule, suspicious pattern, or enforcement feature, include:

- A one-line reason string
- A test case (a command that should and should not match)
- A short explanation of why it matters

## Documentation

Detailed documentation is available in:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Complete guide to the modular codebase structure, module dependencies, and development workflow
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — Deployment checklist, installation methods, and platform compatibility notes

## Why Argus Is More Secure Than a Standard Shell

A traditional shell (bash, zsh, fish) is designed purely for convenience — it runs whatever you type, whenever you type it, with zero awareness of whether that command is dangerous. Argus wraps a POSIX-style shell with a layered security pipeline that inspects, scores, correlates, and optionally blocks every command before it executes. This provides concrete mechanisms that make it harder to accidentally (or maliciously) damage a system.
