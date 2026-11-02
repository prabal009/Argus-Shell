# Argus architecture

## Execution modes and trust boundaries

Argus is a Python 3.11+ programmable shell with a tree-sitter Bash syntax frontend, its own evaluator, cross-platform process backends, user policy assistance, and local observability. It does not hand entire programs to Bash or PowerShell. Native external tools still have their normal platform-specific syntax and availability.

There are two distinct execution boundaries:

1. **Ordinary mode:** programs execute with the user's normal account permissions. Per-command analysis and policy are shell mediation, not kernel confinement. A launched interpreter/editor/build tool can perform actions invisible to command-text inspection. The same user can modify their configuration, database, history, and local signing key.
2. **Optional Linux strict mode:** the client submits source to an independently installed root-owned broker. Unix socket peer credentials authenticate the client; bubblewrap namespaces/mounts and delegated cgroup v2 enforce the administrator's execution envelope. The broker drops identity before user code and returns an authenticated signed completion receipt. Unavailable controls fail closed. Native Windows strict mode has no installed equivalent and is explicitly rejected; it never falls back to ordinary execution.

The optional independent mTLS collector provides a further retention boundary. Its signing identity, client certificate authorization, storage, and retained anchors must be outside the originating user's control. It does not make local advisory policy immutable, inspect every syscall, or protect against compromise of the collector administrator.

## Module map

| Module/resource | Responsibility |
|---|---|
| `main.py` | CLI/startup, unified authorization and builtin dispatch, normal/strict selection, interactive lifecycle and audit integration |
| `language.py` | Bash tree-sitter AST evaluation, `Command`/`Redirection` data, shell state, control flow/functions, stateful language builtins, pure preview |
| `expansion.py` | Quote-sensitive shell expansion and substitution handling |
| `execution.py` | Compatibility-free structured execution helpers consumed by remaining runtime/security callers |
| `processes.py` | Portable pipeline launch and ordered descriptor redirection, isolated builtin workers, platform resource hooks |
| `worker.py` | Private serialized shell-state worker, ordinary and frozen worker entry |
| `jobs.py` | Child tracking, status and audit lifecycle, POSIX process groups/terminal control, native Windows job management |
| `interactive.py`, `terminal.py`, `history.py` | Prompt-toolkit editor/completion/highlighting, capabilities/accessibility, deferred child notifications and durable locked history |
| `builtins.py`, `operations.py` | Shell-facing policy/settings/history/jobs, filtered audit/event queries and exports, vault/redaction/integrity operations |
| `security.py`, `risk.py`, `suspicious.py` | Validated stable live policy, executable/argument/redirection authorization, heuristic scoring and stateful detection |
| `resource.py` | Ordinary-mode per-process limits and Windows Job Object support; not equivalent to the protected Linux broker |
| `config.py`, `storage.py`, `winsecurity.py` | Platform paths, validated settings, migration, safe owned-file operations, platform locking and Windows security helpers |
| `database.py`, `audit.py` | SQLite schemas/migration/retention, command and lifecycle persistence, signed audit integration and archive operations |
| `integrity.py` | Canonical Ed25519 envelopes and hash chains, pinned-key/anchor verification, secure-keyring-backed AES-GCM archives |
| `broker.py` | Root policy/path validation, framed authenticated Unix protocol, bubblewrap/cgroup execution and signed result verification |
| `collector.py` | Mutual TLS client/server, per-stream certificate authorization, contiguous signature/chain validation, durable collector receipts |
| `utils.py`, `colors.py`, `locales/` | Identity/session/redaction/display primitives and localization resources |
| `service/` | Inert systemd units, explicit administrator installer, protected one-shot forwarder/timer |
| `packaging/`, `.github/workflows/` | Native frozen builds, artifact/install verification, cross-platform CI and gated tagged publication |

`argus_shell.py`, `python -m argus`, and the installed `argus` script enter the same application. `pyproject.toml` declares runtime dependencies and derives its version from `argus.__version__`. Python distributions install broker/collector entry points but do not activate services. Source/frozen resources are inert until an administrator explicitly installs and enables them.

## Language and dispatch contracts

`ShellState` owns variables, export membership, positional parameters, last status/background identity, aliases, function source, options, traps, and directory stack. `environment(assignments)` constructs the exported environment plus command-local overlay; local unexported variables do not leak into external processes. `snapshot()` and `from_snapshot()` define the portable worker boundary.

`Command` carries `argv`, assignments, ordered redirections, and source. `Redirection` carries descriptor, operator, target/body, and heredoc expansion semantics. Grammar comes from tree-sitter Bash; execution comes from Argus. Lists, conditionals, loops, functions, substitutions, and heredocs are evaluated without silently forwarding the program to another shell. Unsupported syntax fails visibly rather than being partially executed under an unrelated interpreter.

Every actual simple command or pipeline reaches the executor callback **before** dispatch, including functions and assignments. Expansion output is argument data unless the language explicitly requests evaluation (for example `eval`); it is not an implicit opportunity to inject another pipeline. Runtime evaluation must authorize dynamically reached commands, not just the first parsed executable.

The executor separates analysis, authorization, auditing, and launch. Policy consumes all structured commands, executable identities and redirection targets, not raw text prefixes. Administrative read-only exemptions must be structural and must not allow a redirected/pipelined command to bypass policy. Preview/risk inspection is side-effect-free: it reports unknown/dynamic behavior rather than running substitutions, consuming detector cooldowns, or changing shell state.

Foreground singleton stateful builtins run in the parent so changes persist. Pipeline/background builtins and functions run in isolated workers using private state payloads; they cannot mutate the parent state. Ordered redirection applies to builtins and external programs, including descriptor duplication, heredoc/here-string input and restoration after errors. The same main dispatch interface is used inside workers, including frozen `--internal-worker` launches.

## Platform processes and interactive lifecycle

POSIX execution uses process groups and foreground terminal ownership; the shell returns terminal ownership on completion, stop, or launch failure. Job state reflects all pipeline children. Windows execution uses native subprocesses and Job Objects; Unix stop/resume semantics are not fabricated on platforms without them. Ordinary resource limits remain platform-dependent and distinct from broker aggregate enforcement.

Prompt-toolkit supplies multiline editing, completion, syntax presentation, suggestions and native console handling. Child notifications are scheduled into normal editor/event-loop context; signal handlers wake/queue rather than reap or print during signal execution. History updates are merged under a platform file lock, not blindly overwritten by a second session. Private/ignore/redaction settings govern persisted interactive history. Plain/accessibility/no-color modes avoid relying on ANSI color alone.

PTY regressions cover only the POSIX terminal model. Native Windows portable CLI tests do not establish ConPTY, Ctrl+C/Ctrl+Break, stop/resume equivalence, or manual console rendering quality.

## Policy, settings, queries, and local storage

The security policy dictionary retains stable identity. Load/set operations validate candidate types and bounds before replacing live values. Invalid existing policy does not silently become permissive defaults. Settings (prompt/startup/history/retention/locale and similar preferences) are separate from enforcement policy.

`platformdirs` selects configuration/data/state locations, with explicit `ARGUS_CONFIG_HOME`, `ARGUS_DATA_HOME`, and `ARGUS_STATE_HOME` overrides. Migration imports legacy state non-destructively. Tests must isolate these locations, not merely assume a changed `HOME` overrides all platform paths. Private storage rejects unsafe links/file types and uses actual platform locks; Windows ACL treatment does not imply a protected execution service exists.

Command attempts and lifecycle events distinguish running, stopped, completed and blocked states; no final exit code is not success. Audit, suspicious-event and security-action queries compose filters and table/JSON/CSV rendering. Parameter values are bound to SQL, not interpolated as syntax. Redaction occurs on persistence/export boundaries but cannot detect every arbitrary secret. A secure keyring vault does not rewrite historical exposures, prevent child processes from reading explicitly supplied secrets, or guarantee detection of new secret formats.

SQLite and history are local user-owned persistence, with visible failures and bounded configured retention. Signing a user-owned log adds consistency evidence, not an administrator boundary. Archive encryption uses maintained cryptographic primitives and refuses an unavailable secure keyring rather than storing plaintext key material as a fallback.

## Protected broker mechanics

The root broker validates policy and protected paths, including ownership/non-writable ancestry, runtime contents, interpreter, non-setuid bubblewrap, approved mount roots, log/key directories and resource bounds. It authenticates `SO_PEERCRED` and rejects root or unlisted request UIDs. The client independently checks the server is root, pins the administrator's public key, and verifies request identity/hash, caller identity, exit status and output hashes against the signed receipt.

The systemd socket unit creates the root-owned group-reachable endpoint and removes it on stop; the service consumes that activated descriptor. A dedicated service cgroup delegates CPU/memory/pids controllers. The manager moves into its own subgroup so per-job subgroups can enforce aggregate limits. Jobs join their cgroup **before** dropped-identity exec, clear supplementary groups, set GID/UID, and execute bubblewrap with no retained capabilities. Namespace/mount setup clears the environment and exposes only configured roots and private temporary/kernel views. Cgroup kill terminates descendants on completion/timeout and cleanup.

The broker records accepted script/start/completion, not a full audit of everything a nested interpreter does. Source/output can contain secrets. Bounded captured output is not an interactive PTY. Writable workspace contents and explicitly allowed network access remain intentionally accessible to the user's confined programs. Isolation prerequisites and exact limits must be exercised on the deployment kernel; missing controls do not grant ordinary execution.

## Integrity, collection, and forwarding

A signed envelope contains version, monotonic sequence, previous hash, public key, event, Ed25519 signature, and envelope hash over canonical JSON. Local append operations lock the log, verify the prior chain, append, flush and fsync. A pinned public key detects replacement by another signing identity. An independently retained `{seq, hash}` anchor detects loss/replacement of an anchored suffix; a key alone cannot detect deletion of a valid suffix. The embedded public key without an external pin is merely self-identification.

The collector requires TLS 1.2+ mutual authentication, checks the client certificate's SHA-256 DER fingerprint against a configured stream, verifies every source envelope contiguously against that stream's pinned key, and fsyncs a signed collection record containing the received records and source head. Its log is the recovery state: restart rebuilds stream heads and replay identities from verified persisted events rather than trusting a separate rewritable counter file.

The Linux forwarding service verifies the source against its pinned key and prior signed collector anchor, snapshots a bounded batch under the source lock, submits via mTLS, and atomically persists the authenticated receipt under its own checkpoint lock. It advances no cursor on authentication/network failure. One bounded batch per timer pass limits service work and framed message size. Remote acceptance and local checkpoint persistence are not a distributed transaction: lost responses/checkpoints cause visible sequence divergence and require administrator reconciliation using the independently verified collector envelope. The system does not silently reset counters, discard events, or claim exactly-once recovery.

Source snapshot locking opens the writer's existing lock read-only with `O_NOFOLLOW` and takes `LOCK_SH`. This works under the forwarding unit's read-only broker mount without granting log-directory writes. Framed JSON parsing converts excessive nesting into a protocol rejection shared by broker and collector, rather than leaking a recursion exception into their serving loops.

Collector/forwarder service credentials and paths are root-owned; the collector should be independently administered. Native Windows supports the mTLS client API, not installation of these Linux systemd services or an invented equivalent protected Windows server.

## Delivery and verification boundaries

Native build tooling collects dynamically loaded grammar extensions/keyring backends and builds both PyInstaller layouts. Artifact verification installs wheel and sdist into independent temporary environments outside the source checkout. Tag/version checks read static metadata rather than importing application startup code. Source distributions carry service/packaging resources; frozen bundles retain inert catalogs.

CI declares native Linux/macOS/Windows jobs; tagged release jobs gate publication on distribution and frozen runtime checks. Protected GitHub environments and trusted-publisher configuration are external administrative prerequisites. A workflow file, package classifier, or generated checksum is not evidence that a remote job ran, a binary is signed/notarized, or a package was published. See [DEPLOYMENT.md](DEPLOYMENT.md) for exact installation and recovery procedures.
