"""
Command parsing, tokenization, and execution logic.
"""

import os
import re
import shlex
import sys
import time
from .colors import BRIGHT_RED, BRIGHT_YELLOW, BRIGHT_CYAN, BRIGHT_BLACK, RESET, BOLD
from .audit import audit_command
from .jobs import create_job, give_terminal_to, give_terminal_to_shell, wait_for_job, jobs
from .resource import apply_resource_limits
from .utils import get_current_directory


# Operator tokens
OPERATORS = ("|", "<", ">>", ">", "&", "&&", "||")


def tokenize_operators(command):
    """Tokenize a command string, preserving operators."""
    tokens = []
    buffer = []
    i = 0
    length = len(command)

    in_single_quote = False
    in_double_quote = False
    escape_next = False

    def flush():
        if buffer:
            tokens.append("".join(buffer))
            buffer.clear()

    while i < length:
        character = command[i]

        if escape_next:
            buffer.append(character)
            escape_next = False
            i += 1
            continue

        if character == "\\" and not in_single_quote:
            escape_next = True
            buffer.append(character)
            i += 1
            continue

        if character == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            buffer.append(character)
            i += 1
            continue

        if character == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            buffer.append(character)
            i += 1
            continue

        if in_single_quote or in_double_quote:
            buffer.append(character)
            i += 1
            continue

        if command.startswith(">>", i):
            flush()
            tokens.append(">>")
            i += 2
            continue

        if command.startswith("&&", i):
            flush()
            tokens.append("&&")
            i += 2
            continue

        if command.startswith("||", i):
            flush()
            tokens.append("||")
            i += 2
            continue

        if character in ("|", "<", ">", "&"):
            flush()
            tokens.append(character)
            i += 1
            continue

        buffer.append(character)
        i += 1

    flush()
    return tokens


def expand_variables(command):
    """Expand environment variables in a command string."""
    result = []
    i = 0
    length = len(command)

    in_single_quote = False
    in_double_quote = False
    escape_next = False

    while i < length:
        character = command[i]

        if escape_next:
            result.append(character)
            escape_next = False
            i += 1
            continue

        if character == "\\" and not in_single_quote:
            escape_next = True
            result.append(character)
            i += 1
            continue

        if character == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            result.append(character)
            i += 1
            continue

        if character == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            result.append(character)
            i += 1
            continue

        if character == "$" and not in_single_quote:
            if i + 1 < length and command[i + 1] == "{":
                end = command.find("}", i + 2)
                if end != -1:
                    name = command[i + 2:end]
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                        result.append(os.environ.get(name, ""))
                        i = end + 1
                        continue

            match = re.match(
                r"\$([A-Za-z_][A-Za-z0-9_]*)",
                command[i:]
            )
            if match:
                name = match.group(1)
                result.append(os.environ.get(name, ""))
                i += len(match.group(0))
                continue

        result.append(character)
        i += 1

    return "".join(result)


def parse_pipeline(args):
    """Parse command arguments into a pipeline of commands."""
    commands = []
    current_command = []

    for argument in args:
        if argument == "|":
            if current_command:
                commands.append(current_command)
                current_command = []
        else:
            current_command.append(argument)

    if current_command:
        commands.append(current_command)

    return commands


def parse_redirection(args):
    """Parse input/output redirection from command arguments."""
    cleaned_args = []
    input_file = None
    output_file = None
    append_output = False

    index = 0

    while index < len(args):
        current = args[index]

        if current == "<":
            if index + 1 >= len(args):
                print(f"{BRIGHT_RED}Argus: missing input file{RESET}")
                return None
            input_file = args[index + 1]
            index += 2
            continue

        if current == ">":
            if index + 1 >= len(args):
                print(f"{BRIGHT_RED}Argus: missing output file{RESET}")
                return None
            output_file = args[index + 1]
            append_output = False
            index += 2
            continue

        if current == ">>":
            if index + 1 >= len(args):
                print(f"{BRIGHT_RED}Argus: missing output file{RESET}")
                return None
            output_file = args[index + 1]
            append_output = True
            index += 2
            continue

        cleaned_args.append(current)
        index += 1

    return (cleaned_args, input_file, output_file, append_output)


def apply_redirection(input_file, output_file, append_output):
    """Apply input/output redirection in a child process."""
    if input_file:
        try:
            fd = os.open(input_file, os.O_RDONLY)
            os.dup2(fd, sys.stdin.fileno())
            os.close(fd)
        except OSError as error:
            print(f"{BRIGHT_RED}Argus: {error}{RESET}")
            os._exit(1)

    if output_file:
        try:
            if append_output:
                fd = os.open(
                    output_file,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                    0o644
                )
            else:
                fd = os.open(
                    output_file,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o644
                )

            os.dup2(fd, sys.stdout.fileno())
            os.close(fd)

        except OSError as error:
            print(f"{BRIGHT_RED}Argus: {error}{RESET}")
            os._exit(1)


def setup_child_signals():
    """Set up signal handlers for child processes."""
    import signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTSTP, signal.SIG_DFL)
    signal.signal(signal.SIGQUIT, signal.SIG_DFL)
    signal.signal(signal.SIGTTIN, signal.SIG_DFL)
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)


def strip_quotes_from_token(token):
    """Strip quotes from a single token."""
    try:
        split = shlex.split(token)
    except ValueError:
        return [token]

    if len(split) == 0:
        return [""]

    if len(split) == 1:
        return [split[0]]

    return split
