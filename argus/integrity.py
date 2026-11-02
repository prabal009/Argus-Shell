"""Signed, append-only audit records and keyring-backed encrypted archives.

A key next to a user-owned log detects accidents, not a malicious log owner.
Only an independently pinned public key AND retained head anchor establish external
trust and detect replacement/truncation. No keyring failure has a file fallback.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ZERO_HASH = "0" * 64
MAX_RECORD = 4 * 1024 * 1024


class IntegrityError(ValueError):
    """Untrusted, malformed, or inaccessible integrity material."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def public_text(key: Ed25519PublicKey) -> str:
    return base64.b64encode(key.public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)).decode("ascii")


def load_public_key(value: str | bytes | Path | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, Path):
        value = value.read_bytes()
    if isinstance(value, str):
        value = value.encode("ascii")
    try:
        if value.startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(value)
            if not isinstance(key, Ed25519PublicKey):
                raise IntegrityError("Expected Ed25519 public key")
            return key
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(value.strip(), validate=True))
    except (ValueError, TypeError) as exc:
        raise IntegrityError("Invalid Ed25519 public key") from exc


def _open(path: Path, flags: int, mode: int = 0o600):
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), mode)


@contextmanager
def locked(path: str | Path):
    """Serialize a log and key operation; Windows byte locks use a private file."""
    path = Path(str(path) + ".lock")
    fd = _open(path, os.O_RDWR | os.O_CREAT)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def signing_key(path: str | Path, *, create: bool = False) -> Ed25519PrivateKey:
    path = Path(path)
    if create:
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        try:
            fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    try:
        fd = _open(path, os.O_RDONLY)
        with os.fdopen(fd, "rb") as stream:
            stat = os.fstat(stream.fileno())
            if os.name != "nt" and (stat.st_mode & 0o077 or stat.st_uid != os.geteuid()):
                raise IntegrityError("Signing key must be private and owned by its reader")
            key = serialization.load_pem_private_key(stream.read(65536), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise IntegrityError("Expected Ed25519 private key")
        return key
    except (OSError, ValueError) as exc:
        raise IntegrityError(f"Cannot load signing key: {exc}") from exc


def sign_record(record: dict, key: Ed25519PrivateKey, *, seq: int, previous: str) -> dict:
    body = {"version": 1, "seq": seq, "previous": previous,
            "public_key": public_text(key.public_key()), "record": record}
    body["signature"] = base64.b64encode(key.sign(canonical(body))).decode("ascii")
    body["hash"] = hashlib.sha256(canonical(body)).hexdigest()
    return body


def verify_record(envelope: dict, public_key=None, *, seq=None, previous=None) -> str:
    try:
        if set(envelope) != {"version", "seq", "previous", "public_key", "record", "signature", "hash"}:
            raise IntegrityError("Unexpected signed record fields")
        if envelope["version"] != 1 or type(envelope["seq"]) is not int or envelope["seq"] < 1:
            raise IntegrityError("Invalid record version/sequence")
        if not isinstance(envelope["record"], dict):
            raise IntegrityError("Record must be an object")
        if seq is not None and envelope["seq"] != seq:
            raise IntegrityError("Non-monotonic record sequence")
        if previous is not None and envelope["previous"] != previous:
            raise IntegrityError("Broken hash chain")
        key = load_public_key(public_key if public_key is not None else envelope["public_key"])
        if public_text(key) != envelope["public_key"]:
            raise IntegrityError("Signing key does not match trusted key")
        hashed = dict(envelope)
        digest = hashed.pop("hash")
        if hashlib.sha256(canonical(hashed)).hexdigest() != digest:
            raise IntegrityError("Record hash mismatch")
        signature = base64.b64decode(hashed.pop("signature"), validate=True)
        key.verify(signature, canonical(hashed))
        return digest
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        if isinstance(exc, IntegrityError):
            raise
        raise IntegrityError("Invalid signed record") from exc


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    count: int
    head: str
    public_key: str | None
    trust: str
    error: str | None = None

    @property
    def anchor(self):
        return {"seq": self.count, "hash": self.head}


def _records(path):
    try:
        fd = _open(Path(path), os.O_RDONLY)
    except FileNotFoundError:
        return
    with os.fdopen(fd, "rb") as stream:
        while True:
            line = stream.readline(MAX_RECORD + 1)
            if not line:
                return
            if len(line) > MAX_RECORD or not line.endswith(b"\n"):
                raise IntegrityError("Oversized or incomplete audit record")
            try:
                value = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                raise IntegrityError("Invalid audit JSON") from exc
            yield value


def verify(path, *, public_key=None, anchor=None) -> VerificationResult:
    """Verify full chain, optionally require a previously retained {seq,hash} anchor.

    An anchor may describe any record in this chain, not just its current tail.
    A pinned key without an anchor cannot detect deletion of a valid suffix.
    """
    count, head, pinned = 0, ZERO_HASH, public_key
    trust = "external-key-and-anchor" if public_key is not None and anchor else (
        "external-key-unanchored" if public_key is not None else "user-owned-local-key")
    found_anchor = anchor is None or anchor == {"seq": 0, "hash": ZERO_HASH}
    key_text = public_text(load_public_key(public_key)) if public_key is not None else None
    try:
        for envelope in _records(path):
            if pinned is None:
                pinned = envelope["public_key"]
                key_text = pinned
            head = verify_record(envelope, pinned, seq=count + 1, previous=head)
            count += 1
            if anchor is not None and count == anchor.get("seq"):
                if head != anchor.get("hash"):
                    raise IntegrityError("Retained anchor mismatch")
                found_anchor = True
        if not found_anchor:
            raise IntegrityError("Retained anchor missing: log truncated or replaced")
        return VerificationResult(True, count, head, key_text, trust)
    except (OSError, IntegrityError, KeyError, TypeError) as exc:
        return VerificationResult(False, count, head, key_text, trust, str(exc))


def append_record(path, record: dict, *, key_path=None, private_key=None) -> dict:
    """Append and fsync one signed event. Caller must create the private parent dir."""
    path = Path(path)
    with locked(path):
        key = private_key or signing_key(key_path or Path(str(path) + ".key"), create=True)
        state = verify(path, public_key=key.public_key())
        if not state.valid:
            raise IntegrityError(state.error)
        envelope = sign_record(record, key, seq=state.count + 1, previous=state.head)
        data = canonical(envelope) + b"\n"
        if len(data) > MAX_RECORD:
            raise IntegrityError("Audit record too large")
        fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        with os.fdopen(fd, "ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return envelope


def _archive_key(key_id: str, *, create: bool) -> bytes:
    from .operations import _keyring
    try:
        # Archive keys require the same OS credential-store boundary as vault
        # secrets, including reads: an insecure backend must not receive a key.
        keyring = _keyring()
        value = keyring.get_password("argus.audit.archive", key_id)
        if value is None:
            if not create:
                raise IntegrityError("Archive encryption key not found in keyring")
            value = base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")
            keyring.set_password("argus.audit.archive", key_id, value)
            if keyring.get_password("argus.audit.archive", key_id) != value:
                raise IntegrityError("Keyring did not persist archive key")
        key = base64.b64decode(value, validate=True)
        if len(key) != 32:
            raise IntegrityError("Invalid archive key length")
        return key
    except Exception as exc:
        if isinstance(exc, IntegrityError):
            raise
        raise IntegrityError(f"Secure keyring unavailable: {exc}") from exc


def encrypt_archive(source, destination, *, key_id="default") -> dict:
    """Encrypt an archive using AES-256-GCM; never delete the source implicitly."""
    key = _archive_key(key_id, create=True)
    header = {"version": 1, "algorithm": "AES-256-GCM", "key_id": key_id}
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, Path(source).read_bytes(), canonical(header))
    envelope = {**header, "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii")}
    fd = _open(Path(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(envelope))
        stream.flush()
        os.fsync(stream.fileno())
    return header


def decrypt_archive(source, destination, *, key_id=None):
    try:
        envelope = json.loads(Path(source).read_bytes())
        header = {key: envelope[key] for key in ("version", "algorithm", "key_id")}
        if header["version"] != 1 or header["algorithm"] != "AES-256-GCM":
            raise IntegrityError("Unsupported encrypted archive")
        if key_id is not None and key_id != header["key_id"]:
            raise IntegrityError("Archive key identity mismatch")
        key = _archive_key(header["key_id"], create=False)
        plaintext = AESGCM(key).decrypt(base64.b64decode(envelope["nonce"], validate=True),
                                       base64.b64decode(envelope["ciphertext"], validate=True),
                                       canonical(header))
    except (KeyError, ValueError, InvalidTag) as exc:
        raise IntegrityError("Archive authentication failed") from exc
    fd = _open(Path(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    with os.fdopen(fd, "wb") as stream:
        stream.write(plaintext)
        stream.flush()
        os.fsync(stream.fileno())
