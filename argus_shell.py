#!/usr/bin/env python3
"""
Argus Shell - Security-aware command shell with audit logging.

Entry point for the Argus shell application.
"""

import sys
from argus.main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    except Exception as e:
        print(f"Argus: fatal error: {e}", file=sys.stderr)
        sys.exit(1)
