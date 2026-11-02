#!/usr/bin/env python3
"""Reject releases whose Git tag is not the project's exact declared version."""
import os
import sys
from project_metadata import project_metadata

project = project_metadata()
tag = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("GITHUB_REF_NAME", "")
expected = f"v{project['version']}"
if tag != expected:
    raise SystemExit(f"Release tag must be {expected!r}, got {tag!r}")
print(f"Release tag matches argus.__version__: {tag}")
