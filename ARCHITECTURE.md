# Argus Shell - Refactored Architecture

## Overview

The monolithic `argus.py` file has been refactored into a well-organized, modular Python package structure. This provides better maintainability, testability, and separation of concerns.

## Directory Structure

```
argus/
├── __init__.py              # Package initialization
├── main.py                  # Main shell loop and command execution engine
├── colors.py                # ANSI color code definitions
├── config.py                # Configuration constants and default settings
├── database.py              # Database initialization and connection management
├── risk.py                  # Risk scoring and analysis functions
├── suspicious.py            # Suspicious activity detection logic
├── security.py              # Security policy management and enforcement
├── audit.py                 # Command audit logging and display
├── jobs.py                  # Background/foreground job management
├── execution.py             # Command parsing, tokenization, and execution utilities
├── builtins.py              # Built-in shell command implementations
├── utils.py                 # Utility functions (timestamps, paths, etc.)
└── resource.py              # Resource limit management

argus_shell.py              # Entry point script (executable)
```

## Module Descriptions

### Core Modules

- **main.py** - Contains the main REPL loop, command execution engine, and shell initialization. This is the heart of the application.

- **execution.py** - Handles all command parsing, tokenization, variable expansion, redirection parsing, and pipeline construction.

- **jobs.py** - Manages foreground and background job execution, process groups, terminal control, and job status tracking.

### Feature Modules

- **risk.py** - Implements risk scoring based on configurable patterns. Assigns risk levels to commands based on detected dangerous operations.

- **suspicious.py** - Detects suspicious activity patterns (obfuscated code, sequences of dangerous commands, rapid repetition).

- **security.py** - Implements the security policy system: mode selection, enforcement logic, policy persistence, and action logging.

- **audit.py** - Logs all executed commands to the SQLite database with risk scores, outcomes, and display utilities.

### Support Modules

- **config.py** - All configuration constants: risk rules, suspicious patterns, security modes, default policies, database paths, etc.

- **colors.py** - ANSI color code definitions for consistent terminal output styling.

- **database.py** - Database initialization, connection pooling, and schema management.

- **utils.py** - Common utility functions (get username, current directory, timestamps, etc.).

- **resource.py** - Resource limit management for child processes (CPU, memory, file size, etc.).

- **builtins.py** - All built-in shell commands (cd, pwd, audit, risk, suspicious, security, etc.).

## Key Improvements

1. **Separation of Concerns** - Each module has a single, well-defined responsibility.

2. **Reusability** - Modules can be imported and used independently in other projects.

3. **Testability** - Individual modules are easier to unit test in isolation.

4. **Maintainability** - Changes to one feature don't ripple through the entire codebase.

5. **Readability** - Each file is significantly smaller and easier to understand.

6. **Extensibility** - New features can be added with minimal impact on existing code.

## Running Argus

### From the new modular structure:

```bash
python3 argus_shell.py
```

Or if you want to run it as a module:

```bash
python3 -m argus.main
```

## Dependencies

The refactored code maintains the same external dependencies as the original:
- Standard library only (os, sys, sqlite3, readline, signal, re, time, json, shlex, etc.)
- No external packages required

## Migration Notes

If you have any custom modifications to the original `argus.py`, you'll need to:

1. Identify which module(s) contain the code you want to modify
2. Make your changes in those modules
3. Test to ensure everything works correctly

## Future Improvements

The modular structure makes it easier to add:
- Unit tests for individual modules
- Plugin system for custom audit backends
- Configuration file support beyond just the security policy
- Custom risk rule definitions
- Custom suspicious pattern definitions
- Extended command completion

## Development Workflow

When developing new features:

1. **New command?** Add it to `builtins.py`
2. **New security feature?** Extend `security.py`
3. **New detection pattern?** Update `config.py` and possibly `suspicious.py`
4. **New risk rule?** Update `config.py` and `risk.py`
5. **Database changes?** Update `database.py`

## Module Imports

All internal imports use relative imports (e.g., `from .colors import ...`) to maintain package cohesion and allow the package to be moved or embedded without breaking imports.
