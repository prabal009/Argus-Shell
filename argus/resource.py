"""Per-child resource limits; these do not provide aggregate job isolation."""

import sys

from .utils import safe_text

try:
    import resource
    HAVE_RESOURCE = True
except ImportError:
    HAVE_RESOURCE = False


class ResourceLimitError(RuntimeError):
    """A requested resource limit could not be installed; do not exec the child."""


def apply_resource_limits(security_policy):
    """Apply enabled positive limits or raise visibly before child execution.

    Zero disables an individual limit. RLIMIT_NPROC is per real UID on Linux,
    not per Argus job, and is applied only when explicitly positive.
    """
    try:
        limits = security_policy.get("resource_limits", {})
        if not isinstance(limits, dict) or type(limits.get("enabled", False)) is not bool:
            raise ResourceLimitError("resource_limits.enabled must be boolean")
        if not limits.get("enabled", False):
            return
        if not HAVE_RESOURCE:
            raise ResourceLimitError("resource limits are unavailable on this platform")
        settings = (("cpu_seconds", "RLIMIT_CPU", 1, 60),
                    ("memory_mb", "RLIMIT_AS", 1024 * 1024, 512),
                    ("max_processes", "RLIMIT_NPROC", 1, 0),
                    ("file_size_mb", "RLIMIT_FSIZE", 1024 * 1024, 100),
                    ("open_files", "RLIMIT_NOFILE", 1, 256))
        # Validate and discover support before changing any irreversible hard limit.
        for key, constant, multiplier, default in settings:
            value = limits.get(key, default)
            if type(value) is not int or not 0 <= value <= 2**31 - 1:
                raise ResourceLimitError(key + " must be a bounded nonnegative integer")
            if value and not hasattr(resource, constant):
                raise ResourceLimitError(key + " is unavailable on this platform")
        for key, constant, multiplier, default in settings:
            value = limits.get(key, default)
            if not value:
                continue
            limit = value * multiplier
            try:
                resource.setrlimit(getattr(resource, constant), (limit, limit))
            except (AttributeError, ValueError, OSError, OverflowError) as error:
                raise ResourceLimitError(key + ": " + str(error)) from error
    except ResourceLimitError as error:
        print("Argus: child resource setup failed: " + safe_text(error), file=sys.stderr, flush=True)
        raise
