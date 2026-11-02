#!/usr/bin/env python3
"""Validate wheel/sdist metadata and test each independently installed artifact."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from project_metadata import project_metadata
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    project = project_metadata()
    wheels = sorted(args.dist.glob("*.whl"))
    sources = sorted(args.dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        parser.error("expected exactly one wheel and one source tarball; use a fresh dist directory")
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise SystemExit("wheel must contain exactly one METADATA")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata["Version"] != project["version"]:
            raise SystemExit("wheel version differs from pyproject.toml")
        from packaging.specifiers import SpecifierSet
        from packaging.requirements import Requirement
        python_range = SpecifierSet(metadata["Requires-Python"] or "")
        if "3.10" in python_range or "3.11" not in python_range:
            raise SystemExit("wheel must require Python >=3.11")
        requirements = {str(Requirement(value)) for value in metadata.get_all("Requires-Dist", [])
                        if not Requirement(value).marker or "extra" not in str(Requirement(value).marker)}
        expected = {str(Requirement(value)) for value in project["dependencies"]}
        if requirements != expected:
            raise SystemExit(f"wheel runtime requirements mismatch: {requirements ^ expected}")
        if "argus/main.py" not in names or "argus/language.py" not in names or "argus/worker.py" not in names:
            raise SystemExit("wheel is missing runtime/interpreter/worker modules")
        wheel_metadata = archive.read(metadata_names[0].replace("METADATA", "WHEEL")).decode()
        if "Tag: py3-none-any" not in wheel_metadata:
            raise SystemExit("Argus's platform-neutral Python wheel should use py3-none-any; native dependencies carry their own tags")
    with tarfile.open(sources[0], "r:gz") as archive:
        names = archive.getnames()
        roots = {Path(name).parts[0] for name in names}
        if len(roots) != 1:
            raise SystemExit("source distribution must have a single root")
        root = next(iter(roots))
        for required in ("pyproject.toml", "argus_shell.py", "argus/main.py", "argus/language.py",
                         "packaging/build_standalone.py", "packaging/project_metadata.py",
                         "packaging/argus.spec", "packaging/constraints.txt",
                         "service/install.py", "service/forward.py",
                         "service/argus-broker.service", "service/argus-broker.socket",
                         "service/argus-collector.service", "service/argus-forward.service",
                         "service/argus-forward.timer", "tests/test_terminal_integration.py"):
            if f"{root}/{required}" not in names:
                raise SystemExit(f"source distribution is missing {required}")
        for member in archive.getmembers():
            if Path(member.name).is_absolute() or ".." in Path(member.name).parts or member.issym() or member.islnk():
                raise SystemExit(f"unsafe source archive member: {member.name}")
    for artifact in (wheels[0], sources[0]):
        with tempfile.TemporaryDirectory(prefix="argus-artifact-") as temporary:
            directory = Path(temporary)
            environment = directory / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run([str(python), "-m", "pip", "install", "--constraint",
                            str(ROOT / "packaging" / "constraints.txt"), str(artifact.resolve())],
                           cwd=directory, check=True)
            # Running from a temporary cwd proves this is not a source-tree import.
            subprocess.run([str(python), str(ROOT / "packaging" / "verify_runtime.py")],
                           cwd=directory, check=True)
            print(f"Verified installed artifact: {artifact.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
