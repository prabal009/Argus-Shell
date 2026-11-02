"""Consumer-visible integrity guarantees, including the limits of local trust."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import keyring
from keyring.backend import KeyringBackend

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from argus import integrity


class SecureTestKeyring(KeyringBackend):
    """In-memory credential boundary; cryptographic operations remain real."""
    __module__ = "keyring.backends.SecretService"
    priority = 1

    def __init__(self):
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, password):
        self.values[service, username] = password


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "audit.jsonl"
        self.key = Ed25519PrivateKey.generate()

    def secure_keyring(self):
        previous = keyring.get_keyring()
        backend = SecureTestKeyring()
        keyring.set_keyring(backend)
        self.addCleanup(keyring.set_keyring, previous)
        return backend

    def append(self, value):
        return integrity.append_record(self.log, {"command": value}, private_key=self.key)

    def test_pinned_chain_and_retained_anchor_survive_append(self):
        first = self.append("first")
        self.append("second")
        result = integrity.verify(self.log, public_key=self.key.public_key(),
                                  anchor={"seq": 1, "hash": first["hash"]})
        self.assertTrue(result.valid, result.error)
        self.assertEqual(result.count, 2)
        self.assertEqual(result.trust, "external-key-and-anchor")

    def test_valid_suffix_deletion_requires_an_external_anchor_to_detect(self):
        first = self.append("first")
        second = self.append("second")
        self.log.write_bytes(integrity.canonical(first) + b"\n")
        self.assertTrue(integrity.verify(self.log, public_key=self.key.public_key()).valid)
        anchored = integrity.verify(self.log, public_key=self.key.public_key(),
                                    anchor={"seq": 2, "hash": second["hash"]})
        self.assertFalse(anchored.valid)
        self.assertIn("truncated", anchored.error)

    def test_record_tamper_and_attacker_resigning_fail_pinned_verification(self):
        original = self.append("original")
        changed = copy.deepcopy(original)
        changed["record"]["command"] = "altered"
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_record(changed, self.key.public_key())
        forged = integrity.sign_record({"command": "forged"}, Ed25519PrivateKey.generate(),
                                       seq=1, previous=integrity.ZERO_HASH)
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_record(forged, self.key.public_key())

    def test_append_refuses_corrupt_or_incomplete_existing_log(self):
        self.append("one")
        with self.log.open("ab") as stream:
            stream.write(b'{"incomplete":')
        before = self.log.read_bytes()
        with self.assertRaises(integrity.IntegrityError):
            self.append("must not append")
        self.assertEqual(self.log.read_bytes(), before)

    def test_encrypted_archive_authentication_and_non_overwrite(self):
        source = self.root / "source"
        encrypted = self.root / "encrypted"
        restored = self.root / "restored"
        source.write_bytes(b"sensitive\x00archive")
        self.secure_keyring()
        integrity.encrypt_archive(source, encrypted, key_id="test")
        self.assertNotIn(source.read_bytes(), encrypted.read_bytes())
        integrity.decrypt_archive(encrypted, restored, key_id="test")
        self.assertEqual(source.read_bytes(), restored.read_bytes())
        with self.assertRaises(FileExistsError):
            integrity.decrypt_archive(encrypted, restored)
        envelope = json.loads(encrypted.read_bytes())
        envelope["key_id"] = "tampered"
        encrypted.write_bytes(integrity.canonical(envelope))
        destination = self.root / "unauthenticated"
        with self.assertRaises(integrity.IntegrityError):
            integrity.decrypt_archive(encrypted, destination)
        self.assertFalse(destination.exists())

    def test_unavailable_secure_keyring_never_falls_back_to_file(self):
        backend = self.secure_keyring()
        with patch.object(backend, "get_password", side_effect=RuntimeError("locked")):
            with self.assertRaisesRegex(integrity.IntegrityError, "Secure keyring unavailable"):
                integrity.encrypt_archive(self.root / "absent", self.root / "out")
        self.assertFalse((self.root / "out").exists())


if __name__ == "__main__":
    unittest.main()
