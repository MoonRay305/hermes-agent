"""Every LibreOffice launch in the repository goes through the one wrapper.

Scans every file git knows about (tracked plus untracked-but-not-ignored) for
a LibreOffice executable used as a command:

* Python: a string literal whose command word is a LibreOffice executable
  (``["soffice", ...]``, ``shutil.which("libreoffice")``, ``"timeout 9 soffice
  --headless"``), or any use of the wrapper's private ``_find_soffice``.
* Everything else (Markdown, shell, YAML, Dockerfiles, ...): an executable in
  command position -- start of a line or code span, or after ``&&``, ``|``,
  ``;``, ``$(``, ``sudo``, ``timeout N`` and the like.

Mentions that are not launches ("LibreOffice", ``libreoffice-calc``,
``scripts/office/soffice.py``) do not match.
"""

import ast
import os
import re
import subprocess
from pathlib import Path

import pytest

from tests.skills._soffice_support import GUARD_TREE, REPO, WRAPPER_REL

LAUNCHERS = (
    "soffice",
    "libreoffice",
    "lowriter",
    "localc",
    "lodraw",
    "loimpress",
    "lomath",
    "lobase",
    "simpress",
    "swriter",
    "scalc",
    "sdraw",
    "oosplash",
    "unoconv",
    "unoconvert",
    "unoserver",
)

# Files allowed to name a launcher in command position, and why. Keep short.
ALLOWED = {
    WRAPPER_REL.as_posix(): "the wrapper: the one sanctioned launch site",
    "tests/skills/test_libreoffice_launch_policy.py": "the scanner's own patterns and positive controls",
    "tests/skills/_soffice_support.py": "asks the wrapper whether LibreOffice is installed, so real tests can skip",
    "tests/skills/test_soffice_wrapper.py": "stand-in soffice executables that record argv; nothing real is launched",
    "tests/skills/test_soffice_wrapper_libreoffice.py": "matches the wrapper's own binary to hook the launch it makes",
    "tests/skills/test_excel_author_skill.py": "a stand-in soffice that logs the wrapper's profile, then hands over",
}

_NAME = "|".join(LAUNCHERS)
_COMMAND = (
    # optional directory: /usr/bin/, "C:\Program Files\LibreOffice\program\", ...
    r"""(?:"[^"\n]*[/\\]|'[^'\n]*[/\\]|\S*[/\\])?"""
    rf"(?P<name>{_NAME})(?:\.bin|\.exe|\.com)?"
    r"""(?=$|[\s"'`;&|)])"""
)
# Wrappers that still leave the next word in command position.
_PRECOMMAND = (
    r"(?:(?:(?:sudo|nice|ionice|stdbuf|xargs|env)(?:\s+-[A-Za-z-]+(?:[= ][^\s-]\S*)?)*"
    r"|exec|nohup|command|time|timeout(?:\s+-\S+)*\s+\S+|[A-Za-z_][A-Za-z0-9_]*=\S*)\s+)*"
)
_STARTS = (
    r"(?:^|&&|\|\||[;|(`]|\$\(|^\s*(?:-\s+)?(?:run|command|cmd|entrypoint|script)\s*:"
    r"|^\s*RUN\b|^\s*[$>]\s|\bthen\b|\bdo\b|\belse\b)"
)
COMMAND_POSITION = re.compile(rf"(?:{_STARTS})\s*[\"']?\s*{_PRECOMMAND}{_COMMAND}", re.MULTILINE)
PRIVATE_LOOKUP = "_find_soffice"
_QUICK = re.compile(rf"(?<![\w.-])(?:{_NAME})(?![\w-])|{PRIVATE_LOOKUP}")


def _string_hits(value: str) -> bool:
    return bool(COMMAND_POSITION.search(value))


def _docstring_nodes(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                found.add(id(body[0].value))
    return found


def python_violations(source: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return text_violations(source)
    docstrings = _docstring_nodes(tree)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            if _string_hits(node.value):
                hits.append((node.lineno, node.value))
        elif isinstance(node, ast.Name) and node.id == PRIVATE_LOOKUP:
            hits.append((node.lineno, node.id))
        elif isinstance(node, ast.Attribute) and node.attr == PRIVATE_LOOKUP:
            hits.append((node.lineno, node.attr))
        elif isinstance(node, ast.ImportFrom) and any(a.name == PRIVATE_LOOKUP for a in node.names):
            hits.append((node.lineno, PRIVATE_LOOKUP))
    return hits


def text_violations(source: str) -> list[tuple[int, str]]:
    hits = []
    for lineno, line in enumerate(source.splitlines(), 1):
        if COMMAND_POSITION.search(line) or PRIVATE_LOOKUP in line:
            hits.append((lineno, line.strip()))
    return hits


def violations(relpath: str, source: str) -> list[tuple[int, str]]:
    if relpath.endswith(".py"):
        return python_violations(source)
    return text_violations(source)


def candidate_files(root: Path) -> list[str]:
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8", "surrogateescape")
        return sorted({name for name in listed.split("\0") if name})
    except (OSError, subprocess.CalledProcessError):
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__"}
        found = []
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in skip]
            found += [Path(base, f).relative_to(root).as_posix() for f in files]
        return sorted(found)


def scan(root: Path) -> dict[str, list[tuple[int, str]]]:
    report = {}
    for relpath in candidate_files(root):
        path = root / relpath
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        source = data.decode("utf-8", "replace")
        if not _QUICK.search(source):
            continue
        found = violations(relpath, source)
        if found:
            report[relpath] = found
    return report


def test_no_libreoffice_launch_outside_the_wrapper():
    report = scan(GUARD_TREE)
    offending = {path: hits for path, hits in report.items() if path not in ALLOWED}

    assert not offending, "LibreOffice launched outside the wrapper -- route it through run_soffice():\n" + "\n".join(
        f"  {path}:{lineno}: {text[:120]}" for path, hits in offending.items() for lineno, text in hits
    )


@pytest.mark.skipif(GUARD_TREE != REPO, reason="allowlist is checked against the full checkout")
def test_every_allowlist_entry_is_still_needed():
    report = scan(REPO)

    stale = [path for path in ALLOWED if path not in report]
    assert not stale, f"allowlist entries that no longer name a launcher (remove them): {stale}"


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        ("a.py", 'subprocess.run(["soffice", "--headless", doc])\n'),
        ("a.py", 'subprocess.run(["libreoffice", "--calc"])\n'),
        ("a.py", 'lo = shutil.which("libreoffice")\n'),
        ("a.py", 'for cmd in ("libreoffice", "soffice"):\n    pass\n'),
        ("a.py", 'os.system("timeout 30 soffice --headless --convert-to pdf x.docx")\n'),
        ("a.py", 'subprocess.run("cd out && lowriter --convert-to pdf x.docx", shell=True)\n'),
        ("a.py", 'subprocess.run(["/usr/lib/libreoffice/program/soffice.bin", "-env:X=1"])\n'),
        ("a.py", 'subprocess.run(["unoconv", "-f", "pdf", doc])\n'),
        ("a.py", "binary = wrapper._find_soffice()\n"),
        ("a.py", "from office.soffice import _find_soffice\n"),
        ("SKILL.md", "```bash\nlibreoffice --headless --calc --convert-to xlsx m.xlsx\n```\n"),
        ("SKILL.md", "For visual QA, use `soffice` + `pdftoppm`.\n"),
        ("SKILL.md", "Run `localc --headless` first.\n"),
        ("SKILL.md", "$ simpress --headless --convert-to pdf deck.pptx\n"),
        ("run.sh", "sudo -u app soffice --headless --convert-to pdf \"$f\"\n"),
        ("run.sh", "if true; then lodraw --headless x.odg; fi\n"),
        ("run.sh", "out=$(soffice --version)\n"),
        ("ci.yml", "      - run: soffice --headless --convert-to pdf a.docx\n"),
        ("Dockerfile", "RUN libreoffice --headless --version\n"),
        ("tool.ts", "spawn('soffice', ['--headless'])\n"),
        ("run.bat", '"C:\\Program Files\\LibreOffice\\program\\soffice.exe" --headless\n'),
    ],
)
def test_scanner_flags_direct_launches(relpath, source):
    assert violations(relpath, source)


@pytest.mark.parametrize(
    ("relpath", "source"),
    [
        ("a.md", "LibreOffice - PDF conversion; start it through `scripts/office/soffice.py`.\n"),
        ("a.md", "python scripts/office/soffice.py --headless --convert-to pdf output.pptx\n"),
        ("a.md", "I set up my agent with nextcloud and libreoffice so I can edit docs.\n"),
        ("ci.yml", "      - run: sudo apt-get install -y libreoffice-calc\n"),
        ("a.py", "from office.soffice import run_soffice\n"),
        ("a.py", 'result = run_soffice(["--headless", "--convert-to", "pdf", doc])\n'),
        ("a.py", '"""Recalculate formulas using LibreOffice headless; libreoffice is launched via the wrapper."""\n'),
        ("a.py", 'error = "LibreOffice did not produce output file"\n'),
        ("a.py", 'spec = importlib.util.spec_from_file_location("hermes_office_soffice", path)\n'),
        ("a.py", 'WRAPPER = Path("productivity", "powerpoint", "scripts", "office", "soffice.py")\n'),
    ],
)
def test_scanner_ignores_mentions_that_are_not_launches(relpath, source):
    assert violations(relpath, source) == []
