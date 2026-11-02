# Argus Shell

A programmable Python shell with a Bash-grammar parser, native POSIX/Windows process backends, policy analysis, local audit tools, and optional independently administered protected execution.

Requires **Python 3.11+** and the dependencies declared in `pyproject.toml`: tree-sitter/Bash grammar, prompt-toolkit, cryptography, keyring, psutil, and platformdirs. This is no longer a standard-library-only application.

[![PyPI](https://img.shields.io/pypi/v/argus-shell)](https://pypi.org/project/argus-shell/)
[![CI](https://github.com/prabal009/Argus-Shell/actions/workflows/ci.yml/badge.svg)](https://github.com/prabal009/Argus-Shell/actions)

## Install and run

### From PyPI (recommended)

Argus Shell is published on PyPI as [`argus-shell`](https://pypi.org/project/argus-shell/):

```bash
python -m pip install argus-shell
argus
```

### From source

Linux/macOS:

```bash
git clone https://github.com/prabal009/Argus-Shell.git
cd Argus-Shell
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
argus
```

Native Windows PowerShell:

```powershell
git clone https://github.com/prabal009/Argus-Shell.git
cd Argus-Shell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\argus.exe
```

Activation is optional: invoke the venv launcher directly. WSL remains an alternative Windows route using the Linux instructions. Running source now also needs dependencies: install the checkout first, then use `.venv/bin/python argus_shell.py` or `.venv\Scripts\python.exe argus_shell.py`. Do not move the thin launcher without its package.

## Scripts and commands

```bash
argus --help
argus --version
argus -c 'for x in one two; do echo "$x"; done'
argus script.argus argument1 argument2
python -m argus --norc --no-color -c 'echo "$0:$1"' example value
```

Supported language includes lists and `&&`/`||`, loops, functions, `if`/`case`, shell-local/exported variables, prefix assignments, positional/special parameters, field splitting/globbing, braces/tilde/arithmetic/command substitution, source, aliases, directory stack, pipelines/background jobs, and ordered descriptor redirection/heredocs/here-strings. Argus interprets the parsed syntax itself; scripts are not silently forwarded to Bash. It is not a claim of complete Bash compatibility: arrays, process substitution, and other unimplemented grammar forms must fail explicitly.

Examples inside Argus:

```text
name=world
echo "hello $name"
f() { echo "argument: $1"; }
f example
printf '%s\n' one two | read first
read greeting <<< hello
echo "$greeting" > message.txt
sleep 2 &
jobs
wait
risk 'echo "$(some-command)"'
```

The `risk` subject is parsed without executing substitutions; uncertain dynamic execution is reported, not guessed as safe. Every actual simple command still crosses the policy/audit callback. Builtins/functions in a pipeline or background job run in isolated worker state.

## Interactive controls

Prompt-toolkit provides command/path/function/alias completion, Bash syntax highlighting, history suggestions, multiline continuation, and native console input. `--accessible` selects plain input; `--no-color` and `NO_COLOR` disable styling. `--locale en` and `--locale es` select available core UI catalogs. The prompt is configurable through `settings` or `ARGUS_PROMPT` using `{cwd}`, `{status}`, `{jobs}`, `{user}`, and `{host}`.

```text
history search build
history private on
history private off
history delete 3
history clear
alias ll='ls -la'
pushd /tmp
popd
dirs
```

Inspect `history --help` for supported privacy/merge controls. History has durable cross-session merging; deletion/private mode must not be confused with audit deletion. Startup scripts are configured with `startup_files` or `--rcfile`; `--norc` disables them.

## Policy and records

```text
security
security mode block
allow python3
allow remove python3
deny unwanted-command
deny remove unwanted-command
security set risk_threshold 70
security save
security load
settings
settings set retention_records 10000
settings set retention_days 30
audit --risk 40 --limit 50 --format json
suspicious --severity high --format csv
security-actions --limit 20
audit --detail 12
audit archive /private/archive.json --encrypt
audit verify
```

Read `help` and command usage errors for exact supported forms. Modes remain advisory `off`/`warn`, prompting `confirm`, blocking `block`/`allowlist`, and preview `dry-run`. Administrative controls are user-owned and are not a hostile-account restriction.

Settings and policy use XDG/platformdirs locations; explicit `ARGUS_CONFIG_HOME`, `ARGUS_STATE_HOME`, and `ARGUS_DATA_HOME` override them. Legacy `~/.argus` data is imported non-destructively into the new locations. Inspect `settings` for concrete paths/settings. New records include authenticated OS identity/session IDs and lifecycle metadata. Count/age retention is configurable; unfinished command starts are protected from pruning.

## Secrets and integrity

```text
vault set service-token
vault list
vault env service-token SERVICE_TOKEN
vault delete service-token
redaction add 'custom-sensitive-pattern'
settings set audit_sign true
audit verify
```

Vault values use a secure OS keyring; unavailable keyrings fail rather than fall back to plaintext. Common credential forms, configured patterns, and registered vault values are redacted from new local records. **No program can reliably identify every arbitrary secret.** Legacy/free-form secrets can remain; avoid embedding secrets in command arguments.

Signed logs use Ed25519 hash chains; encrypted archives use AES-256-GCM with keyring-backed keys. A signing key controlled by the log owner is not independent trust. Detecting replacement/truncation requires a separately pinned public key and retained external anchor. The collector uses authenticated TLS and signed receipts.

## Optional protected execution

Normal Argus is not a sandbox and local logging is visible best-effort. An optional Linux administrator-owned broker adds an actual external boundary: peer-UID authentication, immutable administrator policy, bubblewrap namespaces/mount/network restrictions, cgroup-v2 aggregate CPU/memory/PID limits, wall deadlines, and independently owned signed audit.

```bash
argus --strict -c 'echo isolated'
```

Strict mode fails closed when the service, pinned key, bubblewrap, delegated cgroups, or authorization is unavailable. It does not silently run normally. The service is administrator-installed explicitly; Argus never invokes sudo to install it. Protected requests are script jobs, not a persistent interactive parent-state session. Native Windows normal execution has a backend; protected Windows AppContainer/service provisioning remains a separate prerequisite and must not be represented as Linux-equivalent isolation.

See [DEPLOYMENT.md](DEPLOYMENT.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [understand.md](understand.md) for deployment, command details, verification evidence, and remaining boundaries.

## Verification and releases

```bash
python -m unittest discover -s tests
python packaging/verify_runtime.py
python packaging/build_standalone.py --help
```

CI/release configuration and standalone build scripts describe runnable checks/artifacts, not proof that all operating systems have passed or that a package has been published. Exact exercised results belong in `understand.md`. The package is published on PyPI as `argus-shell`; later releases are uploaded manually or via the gated release workflow.

## Changelog: 2.0

Added the programmable grammar/evaluator, portable worker/pipeline backend, richer job and shell-state controls, prompt-toolkit UI, XDG settings, operations/query/export/vault controls, cryptographic audit/archive/collector components, optional protected broker, and release automation. The earlier B01–B29 repairs remain regression requirements; broader features do not waive authorization, lifecycle correctness, or explicit trust boundaries.
