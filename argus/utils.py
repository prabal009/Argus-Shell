"""
Utility functions for common operations.
"""

import os
from datetime import datetime


def get_current_username():
    """Get the current username."""
    return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def get_current_directory():
    """Get the current working directory."""
    try:
        return os.getcwd()
    except OSError:
        return "unknown"


def get_timestamp():
    """Get the current timestamp in ISO format."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_command_name(command):
    """Extract the command name from a command list."""
    if not command:
        return ""
    return command[0]
