# Understanding Argus Shell 2.0

This guide describes the expanded implementation, its commands and installation, how execution/security work, and what still requires deployment or platform validation. The original B01–B29 register described defects in the earlier limited command runner. Version 2.0 changes the language, dependency, UI, process, and deployment architecture; the old standard-library-only and Unix-only descriptions no longer apply.

## 1. Installation

Python **3.11+** is required. Runtime dependencies are declared once in `pyproject.toml`: tree-sitter with the Bash grammar, prompt-toolkit, cryptography, keyring, psutil, and platformdirs.

### Linux / macOS

From Bash/Zsh or the normal OS terminal:

```bash
cd /path/to/Argus-Shell
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
argus
```

On Debian/Ubuntu/Kali, install missing prerequisites with `sudo apt install python3 python3-venv`. Do not launch normal Argus with sudo. Activation is optional: `/path/to/Argus-Shell/.venv/bin/argus` works from another directory.

### Native Windows

From PowerShell with Python installed:

```powershell
cd C:\path\to\Argus-Shell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\argus.exe
```

The normal backend uses Windows subprocesses, console APIs and Job Objects rather than pretending Windows has `fork()`. Native Windows execution code and CI are not the same thing as locally verified Windows behavior. The independently protected Linux broker is not available as a Windows AppContainer service; strict requests on Windows fail closed.

### WSL alternative

In administrator PowerShell:

```powershell
wsl --install -d Ubuntu
```

Restart if requested, finish Ubuntu user setup, then use the Linux instructions inside Ubuntu. A checkout at `C:\Users\Alice\Downloads\Argus-Shell` is usually `/mnt/c/Users/Alice/Downloads/Argus-Shell`. Do not share a venv between Windows and WSL. See [Microsoft's WSL guide](https://learn.microsoft.com/en-us/windows/wsl/install).

### Source, scripts, and standalone applications

After installing dependencies, source launches work with `python argus_shell.py` or `python -m argus`. The thin launcher is not a self-contained application: do not move it without the package.

```bash
argus --help
argus --version
argus --norc -c 'echo hello'
argus script.argus first second
argus -c 'echo "$0:$1:$#"' example value
```

`-` as a script filename reads standard input. `--norc` disables startup scripts; `--rcfile FILE` adds one. PyInstaller standalone builds and platform CI/release workflows live under `packaging/` and `.github/workflows/`; publishing requires the appropriate credentials/permissions and actual target runners. Matching public PyPI publication is not assumed.

## 2. Shell language and use cases

Argus parses Bash grammar with tree-sitter and evaluates supported constructs itself. It does not forward the entire script to Bash. Actual simple commands—including those inside functions, substitutions, and conditions—cross the Argus execution/policy callback.

| Feature | Example / purpose |
| --- | --- |
| Command lists | `echo one; echo two` runs sequentially. |
| Conditional lists | `true && echo yes`; `false \|\| echo recovered` short-circuit. |
| If/elif/else | `if true; then echo yes; else echo no; fi`. |
| For/while/until | `for x in one two; do echo "$x"; done`; condition loops and break/continue are supported. |
| Functions | `greet() { echo "hello $1"; }; greet world`; local function variables and positional frames. |
| Case | `case "$x" in one) echo matched;; *) echo other;; esac`. |
| Local/exported variables | `x=local`; `export y=child`; `unset x`. Only exported values enter child environments. |
| Prefix assignments | `MODE=test python script.py` changes the command environment without leaking the temporary assignment to the parent. |
| Parameters | `$0`, `$1`, `$#`, `$?`, `$$`, `$!`, quoted `$@`/`$*`, defaults/alternates/length/pattern removal. |
| Expansions | Tilde, brace, quote-aware field splitting/globbing, arithmetic `$((...))`, command `$(...)` and backticks. |
| Group/subshell | `{ echo grouped; }`; `(cd /tmp; echo isolated)` uses isolated worker state. |
| Pipes/background | `echo hello \| read value`; `some-command &`; built-in/function child-state changes do not mutate the parent. |
| Redirection | Ordered `<`, `>`, `>>`, `<>`, `>\|`, descriptor duplication/move/close, combined stdout/stderr, heredocs and here-strings. |

Quoted operator text remains data. POSIX unquoted splitting/globbing is now intentional functionality; this differs from the older limited parser, which kept every expansion as one word. Expanded text is not reparsed as new shell operator syntax. Dynamic substitutions execute through the same policy seam rather than an unexamined underlying shell.

Examples:

```text
name=world
printf 'hello %s\n' "$name"
read greeting <<< hello
echo "$greeting"
echo "$(echo nested)"
for n in {1..3}; do echo "$n"; done
source ./settings.argus
```

Unsupported grammar forms must produce contextual errors, not guessed execution. Arrays/subscripts, process substitution, ANSI-C/translated strings, `select`, and extended glob syntax are not claimed as complete Bash compatibility.

## 3. Commands and use cases

Commands below are built-ins or shell forms; installed external programs remain OS-dependent. Linux `ls`, `grep`, `cat`, and `sleep` are not automatically installed native Windows tools. Native Windows users can invoke installed executables with their native arguments; use Python-based scripts for portable examples.

### Navigation, state, and scripts

| Command | Use case / behavior |
| --- | --- |
| `cd [DIR]`, `cd -` | Change directory/home/previous directory; update PWD/OLDPWD and return real errors. |
| `pwd` | Current directory; usable in parent or redirected/pipeline child contexts. |
| `env` | Show exported environment with safe terminal rendering. |
| `export [NAME[=VALUE] ...]` | Mark/set exported variables; flags and validation are handled by the language runtime. |
| `unset [-v\|-f] NAME ...`, `unsetenv NAME ...` | Remove variables or functions. Readonly variables cannot be silently changed. |
| `local`, `declare`, `typeset`, `readonly` | Function-local declarations, declaration/export/readonly state. Unsupported options fail. |
| `set`, `set -- ARG ...`, `shift [N]` | Inspect/set options and positional arguments. Options include errexit, nounset, xtrace, noexec, noglob, noclobber, allexport, pipefail. |
| `source FILE [ARG ...]`, `. FILE [ARG ...]` | Evaluate a file in current shell state; source-local positional arguments are restored afterward. |
| `read [OPTIONS] NAME ...` | Read into shell variables, including redirected/heredoc input. |
| `umask [MASK]` | Inspect/change creation mask; OS semantics apply. |
| `exec [COMMAND ARG ...]` | Replace the shell with an authorized executable. With no command, apply supplied redirections persistently. Audit records replacement rather than inventing a later exit result. |
| `type NAME ...`, `command [-v\|-V] NAME ...` | Classify names or invoke while bypassing function lookup. |
| `alias [NAME=SOURCE ...]`, `unalias NAME ...` | Define/list/remove syntax aliases; alias expansion is bounded against recursion. |
| `pushd [DIR]`, `popd`, `dirs` | Manage the directory stack. |
| `eval ARG ...` | Evaluate shell source through the same interpreter/policy path. |
| `return [N]`, `break [N]`, `continue [N]` | Function/source return and loop control; invalid contexts fail. |
| `trap ACTION SIGNAL ...`, `trap -p`, `trap -l` | Queued signal traps and EXIT/ERR/DEBUG/RETURN handling at safe points. OS signal availability differs. |
| `true`, `false`, `:` | Status-producing primitives. |
| `echo [-n] ARG ...`, `printf FORMAT ARG ...` | Portable built-in output; use quoting to preserve arguments. |
| `redo` | Replay the previous saved command through parsing/policy. Recursive replay is rejected. |
| `help` | Supported command/operator overview. |
| `exit [INTEGER]` | Exit with actual status, run EXIT trap, clean up owned jobs and terminal state. |

### Jobs and asynchronous use

| Command | Use case / behavior |
| --- | --- |
| `jobs` | Show tracked job states. |
| `fg [SELECTOR]`, `bg [SELECTOR]` | Foreground/resume a job. |
| `wait [SELECTOR ...]`, `wait -n` | Wait for selected/all jobs or the next available completion. |
| `disown [SELECTOR]` | Detach an owned job from shell shutdown management. |

Selectors include current `%+`/`%%`, previous `%-`, numeric `%N`, prefix `%name`, and substring `%?text`. Ambiguous selectors fail. Completed results are retained within a bounded history so notification does not immediately make `wait` impossible. `$!` exposes the last background PID.

POSIX uses process groups and terminal ownership; Windows uses native process groups, Job Objects and psutil tree operations. Exact terminal stop/resume keys differ by OS. Ctrl+C at the prompt cancels input; Ctrl+C/Ctrl+Z with a foreground POSIX job interrupt/suspend it. Disown intentionally changes cleanup ownership; it is not confinement.

### Policy, risk, and custom rules

| Command | Use case / behavior |
| --- | --- |
| `security` | Display authoritative live policy. |
| `security mode MODE`, `security threshold N` | Change mode/threshold. |
| `security set FIELD [JSON]` | Change any validated policy field; omitted JSON prompts interactively. Resource-limit fields support dotted names. |
| `security rule list` | Show per-executable rules. |
| `security rule set EXEC JSON`, `security rule edit EXEC`, `security rule remove EXEC` | Author/edit/remove argument and canonical redirection-root rules. |
| `security save`, `security load`, `security reset` | Private validated atomic persistence and in-memory reset. Invalid startup policy fails closed. |
| `allow EXEC`, `allow remove EXEC` | Add/remove allowlist entries. |
| `deny EXEC`, `deny remove EXEC` | Add/remove denylist entries. |
| `allowlist` | Show both lists. |
| `risk 'COMPLETE SUBJECT'` | Pure all-branch preview, risk/suspicious analysis, and explicit uncertainty without executing substitutions or altering detector context. |

Modes: `off`/`warn` are advisory; `confirm` prompts for high-risk matches but noninteractive input is not silently consumed as approval; `block`/`allowlist` enforce every actual command. Dry-run denies state-changing execution while allowing explicit inspection/control escape. User-owned controls are not administrator authority.

Rules support exact allowed/denied arguments and canonical input/output roots. They cannot understand every application's internal file/network/plugin behavior. Permitting an interpreter or package manager permits substantial user-level capability; use the separate protected service for OS confinement.

### Query, export, archive, and integrity

| Command | Use case |
| --- | --- |
| `audit [N]`, `audit search TEXT`, `audit risky [N]` | Legacy convenient views of retained records. |
| `audit-stats` | Retained command/outcome/risk/duration statistics. |
| `suspicious [N\|SEVERITY]`, `suspicious search TEXT`, `suspicious-stats` | Stored detector events and summaries. |
| `security-actions` | Unified policy-action viewer. |
| `audit clear` | Confirm deletion of finalized command rows, retaining unfinished starts. |
| `suspicious-clear [all]` | Confirm current-session/all event deletion; database deletion does not reset live detector context. |
| `audit verify [PATH] [--public-key FILE --anchor FILE]` | Verify signed-chain integrity with explicit trust inputs. |
| `audit archive DEST [--encrypt --key-id NAME --since ISO --until ISO]` | Consistent local snapshot, optionally AES-GCM encrypted with secure keyring-backed key. |

`audit`, `suspicious`, and `security-actions` accept composable `--session ID`, `--cwd PATH`, `--since ISO`, `--until ISO`, `--severity LEVEL`, `--risk N`, `--limit N`, `--offset N`, `--search TEXT`, `--detail ID`, and `--format table|json|csv`. Filters bind SQL values rather than interpolating syntax. Detail views include lifecycle events. New shared searches are literal text rather than caller-controlled SQL LIKE wildcards.

```text
audit --risk 40 --limit 50 --format json
suspicious --severity high --since 2026-11-01T00:00:00Z --format csv
security-actions --session SESSION_ID --detail 1
```

### Settings, privacy, and secrets

| Command | Use case |
| --- | --- |
| `settings [list]`, `settings get NAME`, `settings set NAME JSON` | Validated persistent user settings. |
| `history` and history controls | Search/list/delete/clear/private/merge through the active history manager; inspect command help for exact options. |
| `vault set NAME`, `vault get NAME`, `vault delete NAME`, `vault list` | Secure OS keyring values and metadata; set uses hidden input. Get intentionally reveals the value to the terminal. |
| `vault env NAME VARIABLE` | Load/register a secret into an exported shell variable without putting its value in command text. |
| `redaction list`, `redaction add REGEX`, `redaction remove N`, `redaction test` | Configure/test additional credential detection and record redaction. |

Settings include prompt/startup_files, no_color/accessibility/locale, history_private/history_limit/history_ignore, redaction_patterns, retention_records/retention_days, archive_dir/archive_encrypted, audit_sign/audit_chain, and protected broker settings. A zero retention count/age disables that bound; history_limit must remain positive and private mode disables history recording.

Vault/key encryption operations fail if no secure OS keyring is available; they do not silently store plaintext alternatives. Arbitrary credential detection is impossible to guarantee. Default patterns, user patterns and registered secret values reduce leakage, but raw program output and legacy/free-form secrets can still expose data.

## 4. Interactive experience and configuration

Prompt-toolkit supplies native command/path/function/alias completion, syntax highlighting, history suggestions, multiline continuation and keyboard editing. Enter accepts complete input or continues incomplete grammar; Alt+Enter inserts a newline. Prompt templates support `{cwd}`, `{status}`, `{jobs}`, `{user}`, `{host}`; `ARGUS_PROMPT` overrides the template. `--accessible`, `--no-color`, `NO_COLOR`, terminal capability checks, and `--locale en|es` control presentation. Catalog support is core UI localization, not a claim that every OS/application diagnostic is translated.

Interactive startup displays a responsive cyan-to-violet ARGUS wordmark, version, localized subtitle, and a brief decorative light sweep (about 0.2 seconds). Narrow terminals use a compact wordmark; legacy output encodings use ASCII. Color depth follows advertised truecolor, 256-color, or basic ANSI support. No startup banner is added to scripts, `-c`, or piped input.

To keep the styling but skip the motion, launch with `ARGUS_NO_ANIMATION=1 argus` (Linux/macOS/WSL), or set `$env:ARGUS_NO_ANIMATION='1'` before `argus` in PowerShell. `argus --no-color`, `argus --accessible`, `NO_COLOR`, and `TERM=dumb` use a plain one-line welcome instead. Ctrl+C during the sweep skips the effect; it does not consume typed input or clear the screen.

XDG/platformdirs separate configuration, state and data. Explicit `ARGUS_CONFIG_HOME`, `ARGUS_STATE_HOME`, `ARGUS_DATA_HOME` are useful for tests/deployment. The settings file is configuration `settings.json`; policy is configuration `policy.json`; SQLite/history/signing state live under the state directory; archives default under data. `settings` prints effective paths/settings.

A one-time locked migration imports legacy `~/.argus/argus.db`, `~/.argus/policy.json` and `~/.argus_history` without deleting the old files or overwriting new state. Existing unsafe ownership/symlinks fail rather than being blindly followed. POSIX files are private; native Windows storage uses current-user/SYSTEM/Administrators protected ACLs.

History supports multiline records, atomic durable merging, private/ignore controls, cross-session deletion reconciliation and configurable bounds. Its privacy controls are distinct from audit retention. Do not promise that clearing history deletes already archived or remotely collected records.

## 5. Internals and trust profiles

- `language.py` / `expansion.py`: grammar, evaluator, state, quoted expansion and pure preview. State-changing grammar operations use explicit authorization callbacks, not hidden direct execution.
- `main.py`: CLI, startup, callbacks, unified builtin/function dispatch, user controls, strict client routing, trap/exit lifecycle.
- `processes.py` / `worker.py` / `jobs.py`: ordered descriptor operations, gated JSON workers, portable process/job control, per-stage outcomes, wait/disown and bounded status retention.
- `interactive.py` / `terminal.py` / `history.py` / `i18n.py`: editor, capabilities, idle notifications, durable privacy-aware history and catalogs.
- `security.py` / `risk.py` / `suspicious.py`: stable validated policy, resolved identities/environment, scores, current hits and rolling context.
- `operations.py` / `builtins.py`: policy CRUD, filters/export, vault/settings/history/report controls.
- `database.py` / `audit.py` / `storage.py` / `winsecurity.py` / `utils.py`: schema migration, lifecycle records, identity, private storage, retention, snapshots, rendering/redaction.
- `integrity.py` / `collector.py` / `broker.py`, plus `service/`: signatures, encrypted archives, independently administered collection and protected execution.

Every actual simple command is authorized before dispatch/redirection. Pipeline workers isolate child state; normal foreground builtins modify parent state with exception-safe descriptor restoration. Startup is gated until workers initialize; failed launches kill/reap children and close descriptors. Pipeline redirection initialization can create/truncate already-authorized output files before a later setup failure: filesystem rollback is **not atomic**, and must not be claimed. Denied pipelines still perform no redirection effects.

Audit records start before execution, append lifecycle transitions, preserve launch cwd/background identity and monotonic duration, and use OS identity plus UUID sessions. A true `exec` records replacement, not a fabricated future completion. Count/age retention never deletes running/stopped starts; local write errors are visible best-effort failures.

### Normal profile

Normal Argus runs as the user. Policy/state/logs can be changed by that user and same-UID programs. It is useful for accidental-risk guidance and personal accountability, not a hostile-account security boundary. Powerful applications can act beyond source-text regex checks. A score of zero is not safety proof.

### Signed local records and independent collection

Ed25519 hash chains detect altered records. A log owner's signing key is not independent trust: external pinned public keys and retained anchors are needed to detect replacement/truncation. AES-256-GCM archives authenticate ciphertext with keys stored in secure keyring backends. TLS collection authenticates configured client certificates and verifies pinned stream/collector signatures; signed checkpoints make acknowledgement progress explicit. Lost acknowledgements/checkpoint divergence require reconciliation rather than silently skipping records.

### Optional protected Linux service

The administrator installs a separate root-owned runtime/configuration, Unix socket and signing material. Peer credentials authenticate UID; unprivileged requests cannot edit its policy. Scripts execute after UID/GID/group drop with bubblewrap namespaces, approved read-only/writable mounts, network policy, cgroup-v2 aggregate CPU/memory/PID budgets and wall/output limits. Failure to obtain any required control fails closed, without normal/root fallback. Root-owned accepted-script/start/completion records are independent of the requesting user; they are not a complete kernel syscall trace.

`argus --strict -c 'SCRIPT'` or strict script-file mode requests this boundary. Service jobs are isolated script requests, not persistent interactive parent-state sessions. Native Windows normal execution is implemented, but a Windows administrator-service/AppContainer strict counterpart is still an external backend/provisioning gap and is not falsely reported as Linux parity. See `DEPLOYMENT.md` and `service/` before any explicit administrator installation; normal Argus never runs sudo for you.

## 6. Original repairs and expanded acceptance

The original B01–B29 remain invariants: parsed every-stage authorization, authoritative policy, explicit current suspicious hits, no expansion-to-operator reparsing, complete report imports, truthful save/load, atomic validation, preserved quote identity, contextual malformed-input failures, deliberate I/O semantics, guarded replay, meaningful statuses, last-stage/pipefail outcomes, correctly timed sequences, accurate stop/resume/audit lifecycles, visible persistence errors, authenticated identity, validated clear operations, idle reaping, bounded completion retention, launch unwind, terminal restoration, cancellation, concurrent history, pure preview, monotonic durations, and truthful packaging/docs.

New language support replaces old tests that merely expected features to be unsupported; it does not waive consumer-visible security/lifecycle regressions. New tests cover grammar families, scope/expansion, real CLI/process workers, policy/report/vault operations, settings/migration, history/editor, signature/collector/protocol and protected-control validation.

Cross-platform CI exposed additional portability defects. Windows private directories, files, worker payloads, and atomic replacements now receive the current user's SID owner and protected ACL at creation, rather than depending on an elevated token's default owner. Existing foreign-owned paths, reparse points and hardlinks remain rejected; descriptor checks validate the opened object before truncation. Native Windows regressions check these boundaries.

The interactive package smoke continues servicing PTY output and cursor reports during shutdown, including while terminal restoration drains pending output. It checks successful and nonzero interactive exit statuses and reports terminal diagnostics on failure; it does not skip the macOS PTY test or relax its deadline.

## 7. Verification and still-left work

The results below were exercised on Linux. An implementation or workflow existing in the repository is not a claim of successful execution on every target.

Recorded Linux verification for this implementation:

- The final integrated local run executed **234 tests: 225 passed, 9 platform-specific cases skipped**, with resource warnings treated as errors. Native Windows/macOS results must be checked on their actual CI runners.
- The installed application's eight runtime scenarios passed, including actual PTY input with exit statuses 0 and 7, workers, pipelines, scripts/source, exported-variable boundaries and exit status.
- Fresh virtual environments independently installed the wheel and source distribution; each passed the same eight runtime scenarios from outside the checkout.
- Both PyInstaller **onefile** and **onedir** Linux builds completed, and each executable passed all eight runtime scenarios, including its internal frozen-worker path.
- A direct application smoke exercised functions/local scope, brace expansion, loops, here-strings, command substitution, pipelines, subshell `exec` isolation and EXIT traps.
- The banner update was exercised in real PTYs with gradient, compact, motion-disabled, no-color, accessible, dumb-terminal, `NO_COLOR`, ASCII-encoding and interrupted-animation modes. A command typed during the sweep was preserved and executed; `-c` and piped input stayed banner-free. A regression checks line-width bounds across seven terminal widths.
- The unprivileged bubblewrap namespace prerequisite executed successfully on this host. The administrator-owned broker/systemd/delegated-cgroup deployment was **not** installed or exercised; its protected guarantees remain subject to explicit target-host provisioning and validation.

The built Linux artifacts are retained under `dist/standalone/`; wheel/source packages are under `dist/`. These are local build results, not a claim of signed publication, manylinux portability, Windows/macOS execution, or a deployed privileged service.

```bash
python -m unittest discover -s tests
python packaging/verify_runtime.py
python packaging/build_standalone.py --help
```

Still requires real external prerequisites or further compatibility work:

1. Windows/macOS runner results, their actual console/job behavior, signed standalone releases, and publication credentials must be established by the configured target CI/release process. Linux-only evidence cannot substitute for them.
2. Privileged broker integration requires an explicitly authorized administrator install, working bubblewrap/user namespaces and delegated cgroup-v2 controllers. Unit/protocol tests are not proof of an exercised host confinement boundary.
3. Windows protected service/AppContainer provisioning and persistent strict interactive state are not implemented as normal-mode fallbacks. Strict requests fail rather than silently weakening isolation.
4. Secure keyring, independent collector TLS certificates/allowlists, external public-key/anchor retention and deployment recovery need real operator provisioning. No plaintext vault fallback or invented credential/certificate is supplied.
5. Full Bash compatibility beyond the requested families remains outside the implemented grammar subset: arrays, process substitution, ANSI-C/translated strings, select and extended globs need separate implementation/testing.
6. Credential detection can never guarantee recognition of all secrets. Redaction is best-effort, past records may contain plaintext, and arbitrary child output is not automatically secret-safe.
7. Core English/Spanish UI catalogs do not translate every external program or platform error. Additional languages, accessibility audits and terminal backends need target-user validation.

These are explicit remaining limitations, not claimed repair successes. Keep independent backups and your ordinary OS shell for recovery. Never run the normal shell as root merely to bypass configuration or keyring errors.
