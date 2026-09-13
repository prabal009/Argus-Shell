"""
Resource limit management for child processes.
"""

try:
    import resource
    HAVE_RESOURCE = True
except ImportError:
    HAVE_RESOURCE = False


def apply_resource_limits(security_policy):
    """
    Apply resource limits to the current process.
    
    Note: RLIMIT_NPROC is per-user on Linux, not per-process.
    Setting it can lock out the whole user session. It is only
    applied when max_processes > 0 explicitly.
    """
    if not HAVE_RESOURCE:
        return

    limits = security_policy.get("resource_limits", {})

    if not limits.get("enabled", False):
        return

    try:
        cpu_seconds = int(limits.get("cpu_seconds", 60))
        if cpu_seconds > 0:
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (cpu_seconds, cpu_seconds)
            )
    except (ValueError, OSError):
        pass

    try:
        memory_mb = int(limits.get("memory_mb", 512))
        if memory_mb > 0:
            memory_bytes = memory_mb * 1024 * 1024
            resource.setrlimit(
                resource.RLIMIT_AS,
                (memory_bytes, memory_bytes)
            )
    except (ValueError, OSError):
        pass

    # RLIMIT_NPROC only if explicitly > 0.
    try:
        max_processes = int(limits.get("max_processes", 0))
        if max_processes > 0:
            resource.setrlimit(
                resource.RLIMIT_NPROC,
                (max_processes, max_processes)
            )
    except (ValueError, OSError, AttributeError):
        pass

    try:
        file_size_mb = int(limits.get("file_size_mb", 100))
        if file_size_mb > 0:
            file_size_bytes = file_size_mb * 1024 * 1024
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (file_size_bytes, file_size_bytes)
            )
    except (ValueError, OSError):
        pass

    try:
        open_files = int(limits.get("open_files", 256))
        if open_files > 0:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (open_files, open_files)
            )
    except (ValueError, OSError):
        pass
