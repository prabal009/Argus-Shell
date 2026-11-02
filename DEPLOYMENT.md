# Installation, packaging, and protected deployment

## Ordinary cross-platform installation

Argus 2 requires Python **3.11 or later**. Install into a virtual environment using the maintained dependencies declared in `pyproject.toml`:

```sh
python -m venv .venv
# Linux/macOS:
.venv/bin/python -m pip install .
.venv/bin/argus --norc -c 'printf "hello\n"'
```

On native Windows use `.venv\Scripts\python.exe -m pip install .` and `.venv\Scripts\argus.exe`; activate the environment if shorter commands are preferred. Prompt-toolkit supplies the native editor. Native subprocesses and a Windows Job Object backend replace Unix-only process assumptions. Windows does not gain POSIX terminal stop/resume signals; a ConPTY/manual console exercise is distinct from portable CLI testing. macOS uses the POSIX backend. These are implemented target paths, not claims that this checkout was exercised on every operating system.

Run `python argus_shell.py` from a source checkout only after installing dependencies. The launcher needs the adjacent package; copying it or a virtualenv console script alone is not a standalone distribution. Recreate virtual environments rather than moving them between hosts. Normal Argus must run as the interactive user, **not root**.

`platformdirs` selects platform-standard configuration, state, and data directories. `ARGUS_CONFIG_HOME`, `ARGUS_STATE_HOME`, and `ARGUS_DATA_HOME` explicitly override them. Configuration contains `policy.json` and `settings.json`; state contains `argus.db` and `history.json`. Legacy state migration is non-destructive. Startup files execute shell code: use `--norc` for automation and isolated verification. `--private` controls interactive history, not independent broker collection or all audit logging.

## Packaging and release resources

`pyproject.toml` owns dependencies, entry points, and Python/platform declarations. Version comes from the literal `argus.__version__` assignment. The Python wheel is platform-neutral; native runtime dependencies publish their own platform wheels. This does **not** imply that protected execution is portable.

```sh
python -m pip install --constraint packaging/constraints.txt . build twine packaging
python packaging/run_regressions.py --legacy
python -m build --outdir dist/packages
python -m twine check --strict dist/packages/*
python packaging/verify_distributions.py --dist dist/packages
```

The distribution verifier checks metadata, runtime modules, safe source members, and service resources, then installs the wheel and source distribution separately into temporary environments and exercises each outside the checkout. `constraints.txt` is a reviewed top-level constraint set, **not a complete transitive dependency lock**. Installation/builds can download dependencies. Supply an approved package index or prebuilt dependency wheelhouse for offline deployments.

```sh
python packaging/build_standalone.py --install --mode both
```

PyInstaller builds onefile and onedir variants on the **native host**, collecting Bash grammar binaries, cryptography, prompt-toolkit, keyring backends, metadata, locale resources, and inert service resources. Archives, per-platform JSON manifests, and SHA-256 lists go to `dist/standalone`. A frozen normal shell is not a suitable administrator broker runtime: protected services require a separately installed, non-editable virtualenv and `python -I -m` workers.

`.github/workflows/ci.yml` defines Linux/macOS/Windows Python 3.11/3.13 package-and-runtime jobs. Native Windows runs portable language/backend and integrity/protocol regressions; POSIX-only legacy PTY/process fixtures are explicitly skipped. `.github/workflows/release.yml` checks that the tag exactly equals `v<argus.__version__>`, verifies Python distributions, builds and exercises both frozen modes on each native runner, and publishes assets through the protected `github-release` environment. A rerun replaces same-named assets on the existing release. PyPI upload additionally requires a manual tag-ref dispatch with `publish_pypi`, repository variable `ARGUS_ENABLE_PYPI=true`, a configured trusted publisher, and the protected `pypi` environment. Configure required reviewers for both environments. Workflow definitions are not evidence of completed remote runs or publication. No Windows/macOS signing or notarization identity is included; checksums do not replace publisher authentication.

## Optional Linux protected broker

Normal shell policy and local logs remain same-user assistance, **not confinement**. `--strict` instead submits the entire source to an independently installed root broker. Missing service, invalid receipt, unsupported platform, missing cgroup controller, or failed namespace setup must fail closed; there is no automatic ordinary-execution fallback. Native Windows strict mode is deliberately unavailable: there is no installed authenticated named-pipe/admin-ACL/AppContainer execution service. WSL strict mode is a Linux deployment requiring the same Linux prerequisites.

### Host prerequisites

An administrator must separately provision:

- Linux with systemd and unified cgroup v2, delegated `cpu`, `memory`, and `pids` controllers, and kernel support for `cgroup.kill`.
- Non-setuid `/usr/bin/bwrap` supporting `--disable-userns`, and permission for the non-root client UID to create the required user/mount/PID/network namespaces. Distribution restrictions can make this unavailable; do not weaken isolation silently.
- A **root-owned, non-user-writable, non-editable** Argus installation at `/opt/argus/venv`, including every directory, package, interpreter target, and ancestor. Install dependencies from an administrator-approved source. Do not install an editable checkout into this environment.
- An existing client-owned working directory such as `/srv/argus-work`, whose parent is root-owned and not group/world-writable. Only explicitly approved mounts are exposed. Do not use an entire home directory or a user-replaceable mountpoint.

After reviewing the source distribution, explicitly invoke the installer as administrator (replace the UID and directory with the intended client):

```sh
/opt/argus/venv/bin/python service/install.py broker --uid 1000 --workdir /srv/argus-work
```

`--runtime /absolute/venv` is a global installer option placed **before** the component name. The installer never invokes `sudo`, changes system packages, reloads systemd, enables services, or starts processes on behalf of a client. It creates root-owned configuration/key/state directories and inert units, validates the protected runtime and policy, and prints activation commands. It refuses existing policies, keys exported as public files, helpers, or units instead of overwriting them. A validation failure can leave newly created inert files; inspect and repair those explicitly before retrying. Existing shared configuration/runtime directories must meet the documented ownership and permissions; unsafe paths are not automatically chmodded or adopted.

Review `/etc/argus/broker.json`, then explicitly run:

```sh
systemctl daemon-reload
systemctl enable --now argus-broker.socket
```

The socket unit owns cleanup and recreation of `/run/argus/broker.sock` across restarts. Socket group permission only controls reachability; `SO_PEERCRED` authenticates the actual UID, and the root policy's `allowed_uids` is authoritative. Pin `/etc/argus/broker.pub` from the administrator, not from a user-provided log. That public file is readable through the root-owned 0755 `/etc/argus` directory; private policies remain 0600.

As the allowed **non-root** user, from the approved working directory:

```sh
argus --strict --norc -c 'printf "isolated\n"'
```

The service drops supplementary groups/GID/UID before executing bubblewrap. It exposes approved system/runtime mounts read-only, the configured workspace read-write, and private temporary/proc/device views; clears the inherited environment; and disables network by default. Per-request cgroups enforce aggregate memory, pids, CPU rate, total CPU consumption, and wall timeout, including descendants. The broker records accepted source, start, and completion and signs status/output hashes. It is not a syscall trace, semantic authorization of all nested programs, or a full interactive remote PTY. Output is captured and bounded. Do not assume that enabling network also supplies DNS configuration or additional mounts.

Inspect `systemctl status argus-broker.socket argus-broker.service` and `journalctl -u argus-broker.service` on the target. Validate resource exhaustion, denied UID, daemon restarts, and namespace failure there before production use. No privileged host service was activated merely by providing these repository resources.

## Independent mTLS collector and forwarding

For stronger retention, deploy the collector on a separately administered host, not merely another file writable by the originating user. Provision a TLS server certificate with the correct DNS SAN, a client CA, and per-source client certificates/private keys. Do not use self-issued ad-hoc signing formats: TLS uses OpenSSL and audit envelopes use Ed25519. Keep TLS private keys and all policy ancestors root-owned and non-writable; TLS keys must be private. Obtain certificate fingerprints from DER certificate bytes, not the textual PEM file.

Create a reviewed collector policy with these exact fields (the symbolic values below describe administrator-supplied material, not usable sample credentials):

| Field | Required value |
|---|---|
| `version` | `1` |
| `host`, `port` | Listen address and TCP port, e.g. `0.0.0.0`, `9443` |
| `certificate`, `tls_key`, `client_ca` | Absolute administrator-owned PEM paths |
| `key` | `/var/lib/argus-collector/signing.key` |
| `log` | `/var/lib/argus-collector/audit.jsonl` |
| `streams` | Object mapping a stable stream name to `public_key` (source Ed25519 base64 public text) and `certificate_sha256` (list of authorized lowercase 64-hex DER client certificate digests) |

```sh
/opt/argus/venv/bin/python service/install.py collector --policy /root/reviewed-collector.json
systemctl daemon-reload
systemctl enable --now argus-collector.service
```

The installer creates the independent signing key and `/etc/argus/collector.pub`. Transfer its public value to the source through a trusted administrative channel. Retain old stream public keys in the collector configuration while historical log entries use them. Restrict firewall access to intended source hosts and establish backups/retention for the independent log; the service does not invent a certificate authority or firewall rule.

On the broker host, prepare a forwarding policy with exact fields:

| Field | Required value |
|---|---|
| `version` | `1` |
| `host`, `port` | Collector DNS name matching its certificate SAN, and port |
| `ca_file`, `certificate`, `private_key` | Absolute protected collector-CA and source client certificate/key paths |
| `collector_key` | Independently pinned collector Ed25519 base64 public text |
| `stream` | Collector-configured stable stream name |
| `source` | `/var/lib/argus-broker/audit.jsonl` |
| `source_key` | Independently pinned broker Ed25519 base64 public text |
| `checkpoint` | `/var/lib/argus-forward/broker.receipt.json` |

```sh
/opt/argus/venv/bin/python service/install.py forward --policy /root/reviewed-forward.json
systemctl daemon-reload
systemctl enable --now argus-forward.timer
```

Each timer activation verifies the local chain and last signed collector receipt, submits one bounded contiguous batch using mutual TLS, and atomically/fsynchronously persists the authenticated receipt. Backlogs drain over successive activations. A source record larger than the framed protocol budget is rejected visibly rather than dropped. Do not truncate/rotate the source chain behind the forwarder's checkpoint.

The forwarder opens the broker's existing lock file read-only and takes a shared POSIX lock while snapshotting; it needs no write access to the broker log directory. A source with no records yet is an empty pass. A missing lock beside an existing log is an error, not permission to create a new lock outside the forwarder's writable state.

**Recovery boundary:** the remote append and local receipt replacement are not a distributed transaction. If the collector commits but its response/local checkpoint is lost, the next submission is rejected as a sequence mismatch, not treated as success. Stop the timer, independently verify the collector's persisted signed `collection` envelope for that stream/request and source head, restore that exact envelope as the private local checkpoint, then restart. Never reset counters or delete the collector log to suppress divergence. Preserve the latest receipt anchor in independent storage as part of recovery procedures. Root/host compromise and removal of every external anchor remain outside the guarantee.

Native Windows can use `argus.collector.submit` with administrator-protected client credentials, but this repository installs Linux systemd collector/forwarder services only. It does not claim to install equivalent protected Windows services.

## Data and operational limits

Local SQLite/history contain sensitive data even with configurable redaction. Arbitrary-secret detection cannot be guaranteed. A signed user-owned log detects corruption but cannot establish trust against its owner replacing both log and key. A pinned key without an externally retained head cannot detect deletion of a valid suffix. Keyring-backed encrypted archives use AES-256-GCM and fail if the secure keyring is unavailable; no plaintext key fallback is created. Preserve archive keys and independent anchors separately, and verify backups before deleting originals.

Keep an ordinary system shell and administrative recovery access available. Test the actual target's terminal, Job Object/process groups, keyring, namespace restrictions, cgroup limits, certificates, service ownership, and backup recovery. Repository scripts and workflow declarations are deployment mechanisms, not claims of production hardening or exercised remote platforms.
