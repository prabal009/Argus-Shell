"""Windows token identity and protected owner/SYSTEM/Administrators file ACLs."""

import ctypes
from ctypes import wintypes
import os
from contextlib import contextmanager


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [('nLength', wintypes.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p),
                ('bInheritHandle', wintypes.BOOL)]


class _FileInformation(ctypes.Structure):
    _fields_ = [('attributes', wintypes.DWORD), ('creation', wintypes.FILETIME),
                ('access', wintypes.FILETIME), ('write', wintypes.FILETIME),
                ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]


def _libraries():
    if os.name != 'nt':
        raise OSError('Windows security APIs require Windows')
    return ctypes.WinDLL('advapi32', use_last_error=True), ctypes.WinDLL('kernel32', use_last_error=True)


def current_username():
    """Return the Windows token account name, never environment-provided identity."""
    advapi, _ = _libraries()
    advapi.GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetUserNameW.restype = wintypes.BOOL
    # UNLEN is 256; the size includes the terminating NUL.
    size = wintypes.DWORD(257)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not advapi.GetUserNameW(buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        if error != 122:  # ERROR_INSUFFICIENT_BUFFER
            raise ctypes.WinError(error)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not advapi.GetUserNameW(buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def current_sid():
    advapi, kernel = _libraries()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token, size = wintypes.HANDLE(), wintypes.DWORD()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        value = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


@contextmanager
def _private_security():
    """Specify TokenUser as owner, even when TokenOwner is Administrators."""
    advapi, kernel = _libraries()
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    descriptor = ctypes.c_void_p()
    sid = current_sid()
    # Inherit the private ACL onto files made by native libraries (e.g. SQLite).
    sddl = f'O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    finally:
        kernel.LocalFree(descriptor)


def _open_handle(path, access, disposition, attributes=None):
    _, kernel = _libraries()
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    # OPEN_REPARSE_POINT prevents following a final symlink/junction; the handle
    # is checked before permissions are changed or file content is accessed.
    handle = kernel.CreateFileW(os.fsdecode(path), access, 0x7,
        ctypes.byref(attributes) if attributes is not None else None,
        disposition, 0x00200000 | 0x02000000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _close_handle(handle):
    _, kernel = _libraries()
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle(handle)


def _check_handle(handle, path, *, directory):
    _, kernel = _libraries()
    kernel.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
    info = _FileInformation()
    if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if (info.attributes & 0x400 or bool(info.attributes & 0x10) != directory
            or (not directory and info.links != 1)):
        raise PermissionError(f'unsafe storage {"directory" if directory else "file"}: {path}')


def _secure_handle(handle, path):
    """Never adopt a foreign existing object; update only this opened object."""
    advapi, kernel = _libraries()
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    advapi.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)]
    advapi.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    result = advapi.GetSecurityInfo(handle, 1, 1, ctypes.byref(owner), None, None, None,
                                   ctypes.byref(descriptor))
    if result:
        raise ctypes.WinError(result)
    owner_text = wintypes.LPWSTR()
    try:
        if not advapi.ConvertSidToStringSidW(owner, ctypes.byref(owner_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        if owner_text.value != current_sid():
            raise PermissionError(f'private storage must be owned by current Windows SID: {path}')
    finally:
        if owner_text:
            kernel.LocalFree(ctypes.cast(owner_text, ctypes.c_void_p))
        kernel.LocalFree(descriptor)
    with _private_security() as attributes:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not advapi.GetSecurityDescriptorDacl(attributes.lpSecurityDescriptor,
                ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        result = advapi.SetSecurityInfo(handle, 1, 0x80000004, None, None, dacl, None)
        if result:
            raise ctypes.WinError(result)


def secure_path(path, *, fd=None):
    """Reject foreign ownership and reparse points, then protect the object's ACL."""
    if fd is not None:
        import msvcrt
        handle = msvcrt.get_osfhandle(fd)
        _check_handle(handle, path, directory=False)
        _secure_handle(handle, path)
        return
    handle = _open_handle(path, 0x00020000 | 0x00040000, 3)
    try:
        # secure_path also supports directories; native handle attributes are
        # authoritative, not a second path lookup that could follow a link.
        _, kernel = _libraries()
        kernel.GetFileInformationByHandle.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
        info = _FileInformation()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        _check_handle(handle, path, directory=bool(info.attributes & 0x10))
        _secure_handle(handle, path)
    finally:
        _close_handle(handle)


def create_directory(path):
    """Create one private directory with the user owner and DACL atomically."""
    _, kernel = _libraries()
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    with _private_security() as attributes:
        if not kernel.CreateDirectoryW(os.fsdecode(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())


def open_private_file(path, flags):
    """Create privately or validate an existing nofollow handle before truncation."""
    import msvcrt
    access = 0x00020000 | 0x00040000  # READ_CONTROL | WRITE_DAC
    access |= 0x80000000 if not flags & os.O_WRONLY else 0
    if flags & (os.O_WRONLY | os.O_RDWR):
        access |= 0x40000000
    if flags & os.O_CREAT:
        with _private_security() as attributes:
            try:
                handle = _open_handle(path, access, 1, attributes)  # CREATE_NEW
            except FileExistsError:
                if flags & os.O_EXCL:
                    raise
                handle = _open_handle(path, access, 3)  # OPEN_EXISTING
    else:
        handle = _open_handle(path, access, 3)
    try:
        _check_handle(handle, path, directory=False)
        _secure_handle(handle, path)
        crt_flags = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_APPEND)
        fd = msvcrt.open_osfhandle(handle, crt_flags | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        _close_handle(handle)
        raise
    try:
        if flags & os.O_TRUNC:
            os.ftruncate(fd, 0)
        return fd
    except BaseException:
        os.close(fd)
        raise
