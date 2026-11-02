#!/usr/bin/env python3
"""Build native PyInstaller bundles and release archives; never cross-compile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
from project_metadata import project_metadata
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CONSTRAINTS = ROOT / "packaging" / "constraints.txt"


def run(*args: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("onefile", "onedir", "both"), default="both")
    parser.add_argument("--install", action="store_true", help="Install project/build dependencies using reviewed constraints into this Python environment")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "standalone")
    args = parser.parse_args()
    project = project_metadata()
    if args.install:
        # pip resolves the project's actual dependencies, not a second hand-written
        # runtime requirements list; incompatible constraints fail visibly.
        run(sys.executable, "-m", "pip", "install", "--constraint", str(CONSTRAINTS), str(ROOT), "pyinstaller", "packaging")
    from packaging.requirements import Requirement
    from importlib.metadata import version
    for raw in project["dependencies"]:
        requirement = Requirement(raw)
        if requirement.marker is None or requirement.marker.evaluate():
            installed = version(requirement.name)
            if installed not in requirement.specifier:
                raise SystemExit(f"{requirement.name} {installed} does not satisfy {raw}; use --install")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    target = f"{platform.system().lower()}-{platform.machine().lower()}"
    modes = ("onefile", "onedir") if args.mode == "both" else (args.mode,)
    records = []
    for mode in modes:
        output = args.output / mode
        work = ROOT / "build" / f"pyinstaller-{mode}"
        env = dict(os.environ, ARGUS_BUNDLE_MODE=mode)
        run(sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
            "--distpath", str(output), "--workpath", str(work),
            str(ROOT / "packaging" / "argus.spec"), env=env)
        executable = output / ("argus.exe" if os.name == "nt" else "argus")
        if mode == "onedir":
            executable = output / "argus" / executable.name
        if not executable.is_file():
            raise SystemExit(f"PyInstaller did not produce expected executable: {executable}")
        basename = f"argus-{project['version']}-{target}-{mode}"
        archive = args.output / (basename + (".zip" if os.name == "nt" else ".tar.gz"))
        source = executable.parent if mode == "onedir" else executable
        if os.name == "nt":
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
                paths = sorted(source.rglob("*")) if source.is_dir() else [source]
                for path in paths:
                    if path.is_file():
                        relative = path.relative_to(source.parent)
                        stream.write(path, arcname=str(Path(basename) / relative))
        else:
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(source, arcname=f"{basename}/{source.name}")
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        records.append({"file": archive.name, "sha256": digest, "mode": mode,
                        "executable": str(executable), "platform": target,
                        "python": platform.python_version(), "version": project["version"]})
        print(f"Built {archive}")
    manifest = args.output / f"manifest-{target}.json"
    manifest.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (args.output / f"SHA256SUMS-{target}.txt").write_text(
        "".join(f"{record['sha256']}  {record['file']}\n" for record in records), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
