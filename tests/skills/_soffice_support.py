"""Shared helpers for the LibreOffice wrapper tests.

The wrapper and recalc.py are loaded from SOFFICE_GUARD_TREE when it is set
(scripts/check_soffice_guard_mutations.py points it at a copy holding a
mutated guard) and from this checkout otherwise.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pwd

REPO = Path(__file__).resolve().parents[2]
WRAPPER_REL = Path("skills/productivity/powerpoint/scripts/office/soffice.py")
RECALC_REL = Path("optional-skills/finance/excel-author/scripts/recalc.py")
GUARD_TREE = Path(os.environ.get("SOFFICE_GUARD_TREE") or REPO)
WRAPPER_PATH = GUARD_TREE / WRAPPER_REL
RECALC_PATH = GUARD_TREE / RECALC_REL

_loaded = 0


def load_module(path: Path):
    global _loaded
    _loaded += 1
    spec = importlib.util.spec_from_file_location(f"_soffice_under_test_{_loaded}", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_wrapper():
    return load_module(WRAPPER_PATH)


def libreoffice_available() -> bool:
    return load_wrapper()._find_soffice() is not None


def isolate_home(monkeypatch, tmp_path: Path) -> Path:
    """Point HOME at a fresh directory and clear the XDG overrides."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    return home


def private_root(home: Path) -> Path:
    return home / ".cache" / "hermes" / "lo-profiles"


def profile_dirs(root: Path) -> list[Path]:
    return sorted(root.glob("lo_profile_*")) if root.is_dir() else []


_XLSX_PARTS = {
    "[Content_Types].xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    ),
    "_rels/.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    ),
    "xl/workbook.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    ),
    "xl/_rels/workbook.xml.rels": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    ),
    # A2 holds a formula with no cached value -- what openpyxl writes.
    "xl/worksheets/sheet1.xml": (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
        '<row r="1"><c r="A1"><v>2</v></c></row>'
        '<row r="2"><c r="A2"><f>A1*21</f></c></row>'
        "</sheetData></worksheet>"
    ),
}


def write_formula_xlsx(path: Path) -> Path:
    """An .xlsx whose A2 is =A1*21 with no computed value, built with the stdlib."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in _XLSX_PARTS.items():
            archive.writestr(name, body)
    return path


def cached_value(path: Path, cell: str) -> str | None:
    with zipfile.ZipFile(path) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
    match = re.search(rf'<c r="{cell}"[^>]*>(.*?)</c>', sheet, re.S)
    if not match:
        return None
    value = re.search(r"<v>(.*?)</v>", match.group(1), re.S)
    return value.group(1) if value else None


# ---- running as other users -------------------------------------------------


def can_switch_users() -> bool:
    if not hasattr(os, "geteuid"):
        return False
    if os.geteuid() == 0:
        return True
    if shutil.which("sudo") is None:
        return False
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    return probe.returncode == 0


def other_users(count: int) -> list[pwd.struct_passwd]:
    """Unprivileged accounts to run as: the CI job's users first, then system ones."""
    import pwd

    names = ["hermes-lo-a", "hermes-lo-b", "nobody", "daemon"]
    found = []
    for name in names:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        if entry.pw_uid not in (0, os.geteuid()) and entry.pw_uid not in {u.pw_uid for u in found}:
            found.append(entry)
    return found[:count]


def as_root(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
    return subprocess.run(prefix + argv, check=True, **kwargs)


def run_as(user: pwd.struct_passwd, argv: list[str], env: dict[str, str], **kwargs):
    """Run *argv* as *user* with exactly *env* (no inherited variables).

    The working directory defaults to "/": the caller's (a checkout under a
    0750 home, say) may be unreadable to *user*, and soffice cds back to it.
    """
    kwargs.setdefault("cwd", "/")
    assignments = [f"{key}={value}" for key, value in env.items()]
    if os.geteuid() == 0:
        command = ["setpriv", f"--reuid={user.pw_uid}", f"--regid={user.pw_gid}", "--clear-groups", "env", "-i", *assignments, *argv]
    else:
        command = ["sudo", "-n", "-u", user.pw_name, "env", "-i", *assignments, *argv]
    return subprocess.run(command, **kwargs)


def popen_as(user: pwd.struct_passwd, argv: list[str], env: dict[str, str], **kwargs):
    kwargs.setdefault("cwd", "/")
    assignments = [f"{key}={value}" for key, value in env.items()]
    if os.geteuid() == 0:
        command = ["setpriv", f"--reuid={user.pw_uid}", f"--regid={user.pw_gid}", "--clear-groups", "env", "-i", *assignments, *argv]
    else:
        command = ["sudo", "-n", "-u", user.pw_name, "env", "-i", *assignments, *argv]
    return subprocess.Popen(command, **kwargs)


def system_python() -> str:
    """A Python interpreter other users can execute (a venv under /root may not be)."""
    for candidate in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if os.access(candidate, os.X_OK):
            return candidate
    return sys.executable
