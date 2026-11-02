"""Native owner/DACL regressions; run on normal and elevated Windows accounts."""

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import tempfile
import unittest

from argus.storage import (atomic_write, locked_file, open_private, private_directory,
                           private_temporary_directory)
from argus.winsecurity import current_sid, secure_path


@unittest.skipUnless(os.name == 'nt', 'requires native Windows security APIs')
class WindowsStorageTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory(prefix='argus-windows-storage-')
        self.addCleanup(self.home.cleanup)
        self.root = Path(self.home.name)
        self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]

    def sid_text(self, sid):
        text = wintypes.LPWSTR()
        if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            self.kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def security(self, path):
        owner, dacl, descriptor = (ctypes.c_void_p() for _ in range(3))
        self.advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int,
            wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p)]
        self.advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
        result = self.advapi.GetNamedSecurityInfoW(str(path), 1, 5,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if result:
            raise ctypes.WinError(result)
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            self.advapi.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
                ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
            if not self.advapi.GetSecurityDescriptorControl(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise ctypes.WinError(ctypes.get_last_error())
            self.assertTrue(dacl.value, 'private storage must not have a NULL DACL')
            # ACL header: revision, reserved byte, size WORD, ACE count WORD.
            count = ctypes.c_ushort.from_address(dacl.value + 4).value
            self.advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p)]
            entries = []
            for index in range(count):
                ace = ctypes.c_void_p()
                if not self.advapi.GetAce(dacl, index, ctypes.byref(ace)):
                    raise ctypes.WinError(ctypes.get_last_error())
                kind = ctypes.c_ubyte.from_address(ace.value).value
                flags = ctypes.c_ubyte.from_address(ace.value + 1).value
                mask = wintypes.DWORD.from_address(ace.value + 4).value
                entries.append((kind, flags, mask, self.sid_text(ace.value + 8)))
            return self.sid_text(owner), control.value, entries
        finally:
            self.kernel.LocalFree(descriptor)

    def assert_private(self, path):
        owner, control, entries = self.security(path)
        self.assertEqual(owner, current_sid(), str(path))
        self.assertTrue(control & 0x1000, 'DACL inheritance must be protected')
        self.assertEqual(len(entries), 3)
        self.assertEqual({entry[3] for entry in entries},
                         {current_sid(), 'S-1-5-18', 'S-1-5-32-544'})
        for kind, flags, mask, _ in entries:
            self.assertEqual(kind, 0, 'only allow ACEs are expected')
            self.assertFalse(flags & 0x10, 'inherited ACEs must not grant access')
            self.assertEqual(mask, 0x001F01FF, 'each trusted SID needs full file access')

    def test_new_platform_roots_records_and_atomic_replacements_are_private(self):
        for name in ('config', 'state', 'data'):
            directory = self.root / name / 'nested'
            private_directory(directory)
            self.assert_private(directory.parent)
            self.assert_private(directory)
            path = directory / 'record'
            fd = open_private(path)
            try:
                self.assertFalse(os.get_inheritable(fd))
                os.write(fd, b'first')
                secure_path(path, fd=fd)
            finally:
                os.close(fd)
            self.assert_private(path)
            atomic_write(path, 'replacement')
            self.assert_private(path)
            fd = open_private(path, os.O_RDONLY)
            try:
                self.assertEqual(os.read(fd, 100), b'replacement')
            finally:
                os.close(fd)
            with self.assertRaises(FileExistsError):
                open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            fd = open_private(path, os.O_WRONLY | os.O_TRUNC)
            os.close(fd)
            self.assertEqual(path.read_bytes(), b'')
            self.assert_private(path)
            with locked_file(directory / 'record.lock'):
                self.assert_private(directory / 'record.lock')
            self.assertEqual(list(directory.glob('.argus-*')), [])

    def test_fd_security_uses_opened_object_after_path_is_replaced(self):
        directory = self.root / 'state'
        private_directory(directory)
        record = directory / 'record'
        renamed = directory / 'renamed'
        fd = open_private(record)
        try:
            os.write(fd, b'original')
            os.replace(record, renamed)
            replacement = directory / 'replacement'
            atomic_write(replacement, 'other')
            os.link(replacement, record)
            # The old pathname is now unsafe, but the open original is not.
            secure_path(record, fd=fd)
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(fd, 100), b'original')
            self.assert_private(renamed)
            with self.assertRaises(PermissionError):
                open_private(record)
        finally:
            os.close(fd)

    def test_worker_directory_and_payload_start_private(self):
        with private_temporary_directory(prefix='argus-worker-regression-') as directory:
            self.assert_private(directory)
            payload = Path(directory) / 'payload.json'
            atomic_write(payload, '{}')
            self.assert_private(payload)
        self.assertFalse(Path(directory).exists())

    def test_hardlinked_existing_records_are_rejected_without_truncation(self):
        directory = self.root / 'state'
        private_directory(directory)
        record = directory / 'record'
        atomic_write(record, 'preserve')
        alias = directory / 'alias'
        os.link(record, alias)
        for path in (record, alias):
            with self.assertRaises(PermissionError):
                open_private(path, os.O_WRONLY | os.O_TRUNC)
        self.assertEqual(record.read_text(), 'preserve')

    def test_reparse_points_are_rejected_without_changing_targets(self):
        directory = self.root / 'state'
        private_directory(directory)
        record = directory / 'record'
        atomic_write(record, 'preserve')
        link = directory / 'link'
        directory_link = self.root / 'directory-link'
        try:
            link.symlink_to(record)
            directory_link.symlink_to(directory, target_is_directory=True)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows symlink creation requires privilege or Developer Mode')
            raise
        with self.assertRaises(PermissionError):
            open_private(link, os.O_WRONLY | os.O_TRUNC)
        with self.assertRaises(PermissionError):
            secure_path(link)
        with self.assertRaises(PermissionError):
            private_directory(directory_link)
        self.assertEqual(record.read_text(), 'preserve')
        self.assert_private(record)

    def test_existing_administrators_owned_state_is_not_adopted(self):
        # Elevated tokens can assign Administrators as owner; a normal token
        # cannot, so only this foreign-owner fixture needs an elevated account.
        directory = self.root / 'foreign'
        private_directory(directory)
        record = directory / 'record'
        atomic_write(record, 'preserve')
        self.advapi.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        self.advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int,
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p]
        self.advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
        administrators = ctypes.c_void_p()
        if not self.advapi.ConvertStringSidToSidW('S-1-5-32-544', ctypes.byref(administrators)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            for path in (record, directory):
                result = self.advapi.SetNamedSecurityInfoW(
                    str(path), 1, 1, administrators, None, None, None)
                if result in (5, 1307, 1314):
                    self.skipTest('assigning a foreign owner requires an elevated token')
                if result:
                    raise ctypes.WinError(result)
            for flags in (os.O_RDONLY, os.O_WRONLY | os.O_TRUNC,
                          os.O_RDWR | os.O_CREAT):
                with self.assertRaisesRegex(PermissionError, 'current Windows SID'):
                    open_private(record, flags)
            with self.assertRaisesRegex(PermissionError, 'current Windows SID'):
                private_directory(directory)
            with self.assertRaisesRegex(PermissionError, 'current Windows SID'):
                atomic_write(record, 'must not replace', private_parent=False)
            self.assertEqual(record.read_text(), 'preserve')
            for path in (record, directory):
                self.assertEqual(self.security(path)[0], 'S-1-5-32-544')
        finally:
            self.kernel.LocalFree(administrators)


if __name__ == '__main__':
    unittest.main()
