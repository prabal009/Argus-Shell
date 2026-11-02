"""Owned private local storage and cross-platform locks; not an owner trust boundary."""

import os
import stat
import sys
import tempfile
import secrets
import shutil
from contextlib import contextmanager


def _windows_private(path, *, fd=None):
    from .winsecurity import secure_path
    secure_path(path, fd=fd)


def _windows_makedirs(path):
    from .winsecurity import create_directory
    try:
        create_directory(path)
    except FileNotFoundError:
        parent = os.path.dirname(os.path.abspath(path))
        if parent == os.path.abspath(path):
            raise
        _windows_makedirs(parent)
        try:
            create_directory(path)
        except FileExistsError:
            pass
    except FileExistsError:
        pass


def _safe(value):
    return ''.join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in str(value))


def storage_warning(operation, error):
    print(f'Argus: {_safe(operation)}: {_safe(error)}; local persistence is best-effort', file=sys.stderr)


def private_directory(path):
    if os.name == 'nt':
        _windows_makedirs(path)
    else:
        os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PermissionError(f'unsafe storage directory: {path}')
    if getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermissionError(f'unsafe storage directory: {path}')
    if os.name == 'nt':
        _windows_private(path)
    elif info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(f'storage directory must be owned and private (chmod 700): {path}')


def open_private(path, flags=os.O_RDWR | os.O_CREAT):
    """Open an owned regular single-link file, rejecting links/FIFOs before use."""
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
        raise PermissionError(f'unsafe storage file: {path}')
    if os.name == 'nt':
        from .winsecurity import open_private_file
        return open_private_file(path, flags)
    extra = getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags | extra | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError(f'unsafe storage file: {path}')
        if info.st_uid != os.getuid():
            raise PermissionError(f'foreign-owned storage file: {path}')
        os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_temporary_file(directory):
    if os.name != 'nt':
        return tempfile.mkstemp(prefix='.argus-', dir=directory)
    for _ in range(100):
        path = os.path.join(directory, '.argus-' + secrets.token_hex(16))
        try:
            return open_private(path, os.O_RDWR | os.O_CREAT | os.O_EXCL), path
        except FileExistsError:
            continue
    raise FileExistsError('could not allocate a unique private temporary file')


@contextmanager
def private_temporary_directory(*, prefix='argus-'):
    """Create private worker storage without relying on the token default owner."""
    if os.name != 'nt':
        with tempfile.TemporaryDirectory(prefix=prefix) as directory:
            yield directory
        return
    from .winsecurity import create_directory
    for _ in range(100):
        directory = os.path.join(tempfile.gettempdir(), prefix + secrets.token_hex(16))
        try:
            create_directory(directory)
            break
        except FileExistsError:
            continue
    else:
        raise FileExistsError('could not allocate a unique private temporary directory')
    try:
        private_directory(directory)
        yield directory
    finally:
        shutil.rmtree(directory)


def atomic_write(path, text, *, private_parent=True):
    directory = os.path.dirname(os.path.abspath(path))
    if private_parent:
        private_directory(directory)
    else:
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise PermissionError(f'unsafe parent directory: {directory}')
        if getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError(f'unsafe parent directory: {directory}')
        if os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise PermissionError(f'unsafe parent directory: {directory}')
    if os.path.lexists(path):
        fd = open_private(path, os.O_RDONLY)
        os.close(fd)
    fd, temporary = _private_temporary_file(directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            if os.name == 'nt':
                _windows_private(temporary, fd=handle.fileno())
            else:
                os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == 'posix':
            dirfd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def private_text(path, mode='r'):
    flags = os.O_RDONLY if mode == 'r' else os.O_RDWR | os.O_CREAT
    fd = open_private(path, flags)
    with os.fdopen(fd, mode, encoding='utf-8') as handle:
        yield handle


@contextmanager
def locked_file(path):
    """Exclusive local-process lock with an actual Windows byte-range lock."""
    fd = open_private(path)
    acquired = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'\0')
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        acquired = True
        yield fd
    finally:
        try:
            if os.name == 'nt' and acquired:
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)
