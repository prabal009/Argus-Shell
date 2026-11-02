# Build via packaging/build_standalone.py; PyInstaller specs execute as Python.
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata

root = Path(SPECPATH).parent
mode = os.environ.get("ARGUS_BUNDLE_MODE", "onedir")
if mode not in {"onefile", "onedir"}:
    raise ValueError("ARGUS_BUNDLE_MODE must be onefile or onedir")

datas = [(str(root / "License.txt"), ".")]
binaries = []
hiddenimports = ["argus.worker"]
# Bash's grammar is a native extension loaded dynamically. Keyring discovers
# backends through entry points. Collect their data/binaries as well as imports.
for package in ("argus", "tree_sitter", "tree_sitter_bash", "prompt_toolkit",
                "cryptography", "keyring", "psutil", "platformdirs"):
    package_data, package_binaries, package_imports = collect_all(package)
    datas += package_data
    binaries += package_binaries
    hiddenimports += package_imports
for distribution in ("argus-shell", "tree-sitter", "tree-sitter-bash", "keyring"):
    datas += copy_metadata(distribution, recursive=True)
# Preserve administrator-installable service/config catalogs in the bundle;
# they are inert resources, never installed or elevated by the executable.
if (root / "service").is_dir():
    datas.append((str(root / "service"), "service"))
if (root / "argus" / "locales").is_dir():
    datas.append((str(root / "argus" / "locales"), "argus/locales"))

a = Analysis([str(root / "argus_shell.py")], pathex=[str(root)],
             binaries=binaries, datas=datas, hiddenimports=hiddenimports,
             hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[],
             noarchive=False)
pyz = PYZ(a.pure)
if mode == "onefile":
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="argus",
              debug=False, bootloader_ignore_signals=False, strip=False,
              upx=False, console=True)
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="argus",
              debug=False, bootloader_ignore_signals=False, strip=False,
              upx=False, console=True)
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="argus")
