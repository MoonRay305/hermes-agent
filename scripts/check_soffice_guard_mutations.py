#!/usr/bin/env python3
"""Mutation check for the LibreOffice guard: weaken each guard, expect red tests.

For every mutation below, the wrapper and excel-author's recalc.py are copied
into a scratch tree at their repository paths, the mutation is applied to the
copy, and the listed tests run against that tree (SOFFICE_GUARD_TREE). A
mutation is "killed" when the tests fail; it "survives" when they pass, which
means that guard is untested. The unmutated copy must pass first.

HOME and TMPDIR point into the scratch tree for every run, so a mutant that
starts LibreOffice with its default profile cannot touch the real home.

Usage:
    python scripts/check_soffice_guard_mutations.py              # every mutation
    python scripts/check_soffice_guard_mutations.py -k shim      # ids containing "shim"
    python scripts/check_soffice_guard_mutations.py --strict     # CI: nothing may go unexercised

Tests that need LibreOffice or a second user skip when those are missing; a
mutation that only such tests catch is then "not exercised" (an error only
with --strict). The "LibreOffice guard" CI job has both and runs --strict.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WRAPPER = Path("skills/productivity/powerpoint/scripts/office/soffice.py")
RECALC = Path("optional-skills/finance/excel-author/scripts/recalc.py")

UNIT = "tests/skills/test_soffice_wrapper.py"
REAL = "tests/skills/test_soffice_wrapper_libreoffice.py"
RECALC_TESTS = "tests/skills/test_excel_author_skill.py"
POLICY = "tests/skills/test_libreoffice_launch_policy.py"


@dataclass(frozen=True)
class Mutation:
    id: str
    guard: str
    target: Path
    edits: tuple[tuple[str, str], ...]
    tests: tuple[str, ...]


MUTATIONS = (
    Mutation(
        "accept-caller-profile",
        "caller -env: and /env: overrides are refused",
        WRAPPER,
        (("        if _BOOTSTRAP_OVERRIDE.match(arg):", "        if False:"),),
        (UNIT,),
    ),
    Mutation(
        "narrow-override-pattern",
        "every spelling of a bootstrap override is refused",
        WRAPPER,
        ((r'_BOOTSTRAP_OVERRIDE = re.compile(r"\s*[-/]+env:", re.IGNORECASE)',
          r'_BOOTSTRAP_OVERRIDE = re.compile(r"-env:UserInstallation=")'),),
        (UNIT,),
    ),
    Mutation(
        "keep-env-profile-variable",
        "UserInstallation is dropped from the child environment",
        WRAPPER,
        (('if k.lower() != "userinstallation"', "if True"),),
        (UNIT,),
    ),
    Mutation(
        "allow-any-subprocess-option",
        "env=/executable=/shell= cannot be passed through",
        WRAPPER,
        (("unexpected = sorted(set(kwargs) - _RUN_KWARGS)", "unexpected = []"),),
        (UNIT,),
    ),
    Mutation(
        "shared-root",
        "the private root is per-user, not one shared directory",
        WRAPPER,
        (('return base / "hermes" / "lo-profiles"', 'return Path(tempfile.gettempdir()) / "lo-profiles"'),),
        (UNIT, REAL),
    ),
    Mutation(
        "skip-owner-check",
        "a root or profile owned by someone else is refused",
        WRAPPER,
        (("if not stat.S_ISDIR(st.st_mode) or not _is_ours(st):", "if not stat.S_ISDIR(st.st_mode):"),),
        (UNIT,),
    ),
    Mutation(
        "keep-loose-root-mode",
        "the private root is forced to 0700",
        WRAPPER,
        (("            os.fchmod(fd, 0o700)", "            pass"),),
        (UNIT, REAL),
    ),
    Mutation(
        "follow-symlinked-root",
        "a symlinked root or profile is never followed",
        WRAPPER,
        (('    | getattr(os, "O_NOFOLLOW", 0)\n', ""),),
        (UNIT,),
    ),
    Mutation(
        "keep-profile",
        "the profile is removed when soffice exits",
        WRAPPER,
        (("        os.close(fd)\n        _remove_at(root_fd, root, name)", "        os.close(fd)"),),
        (UNIT,),
    ),
    Mutation(
        "pass-profile-by-name",
        "the profile is handed over by descriptor, not by a swappable name",
        WRAPPER,
        (("yield _pinned_uri(fd) or (root / name).as_uri()", "yield (root / name).as_uri()"),),
        (UNIT, REAL),
    ),
    Mutation(
        "shim-in-shared-temp",
        "the shim is built in the private root, never shared temp",
        WRAPPER,
        (
            ('    shim_dir = root / "shim"', "    shim_dir = Path(tempfile.gettempdir())"),
            ('    dir_fd = _open_private_dir("shim", dir_fd=root_fd)',
             "    dir_fd = os.open(tempfile.gettempdir(), os.O_RDONLY)"),
        ),
        (UNIT,),
    ),
    Mutation(
        "skip-shim-digest-check",
        "the cached shim's SHA-256 is checked before preload",
        WRAPPER,
        (('    if hashlib.sha256(data).hexdigest() != recorded.decode("ascii", "replace").strip():',
          "    if False:"),),
        (UNIT,),
    ),
    Mutation(
        "trust-writable-shim",
        "a shim others can write is never trusted",
        WRAPPER,
        (("if not stat.S_ISREG(st.st_mode) or not _is_ours(st) or st.st_mode & 0o022:",
          "if not stat.S_ISREG(st.st_mode):"),),
        (UNIT,),
    ),
    Mutation(
        "preload-shim-by-path",
        "the checked shim bytes are preloaded from a sealed memfd",
        WRAPPER,
        (("    memfd = _sealed_copy(data)", "    memfd = None"),),
        (UNIT,),
    ),
    Mutation(
        "recalc-direct-launch",
        "recalc.py starts LibreOffice only through the wrapper",
        RECALC,
        (("            wrapper.run_soffice(\n                [", '            subprocess.run(\n                ["libreoffice", '),),
        (RECALC_TESTS, POLICY),
    ),
    Mutation(
        "recalc-walks-up",
        "recalc.py looks for the wrapper only in fixed places",
        RECALC,
        (("    candidates = []\n", "    candidates = [p / _WRAPPER for p in parents]\n"),),
        (RECALC_TESTS,),
    ),
)


def _apply(source: str, mutation: Mutation) -> str:
    for old, new in mutation.edits:
        count = source.count(old)
        if count != 1:
            raise SystemExit(f"{mutation.id}: expected the text to mutate exactly once, found {count}: {old!r}")
        source = source.replace(old, new)
    return source


def _outcome(returncode: int, output: str) -> str:
    if returncode == 1:
        return "killed"
    if returncode != 0:
        return f"error (pytest exit {returncode})"
    if re.search(r"\b\d+ passed\b", output):
        return "survived"
    return "not exercised"


def _run(tree: Path, scratch: Path, tests: tuple[str, ...]) -> tuple[int, str]:
    env = dict(os.environ)
    env.update(
        SOFFICE_GUARD_TREE=str(tree),
        HOME=str(scratch / "home"),
        TMPDIR=str(scratch / "tmp"),
        PYTHONDONTWRITEBYTECODE="1",
    )
    for name in ("XDG_RUNTIME_DIR", "XDG_CACHE_HOME"):
        env.pop(name, None)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *tests, "-q", "-x", "-p", "no:cacheprovider"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    return result.returncode, result.stdout + result.stderr


def _fresh_scratch(base: Path, label: str) -> tuple[Path, Path]:
    scratch = base / label
    tree = scratch / "tree"
    for relative in (WRAPPER, RECALC):
        (tree / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / relative, tree / relative)
    (scratch / "home").mkdir()
    (scratch / "tmp").mkdir()
    (scratch / "tmp").chmod(0o1777)  # other users in the real-LibreOffice tests share it
    return scratch, tree


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-k", dest="keyword", default="", help="only mutations whose id contains this")
    parser.add_argument("--strict", action="store_true", help="fail when a mutation is not exercised")
    args = parser.parse_args()
    selected = [m for m in MUTATIONS if args.keyword in m.id]

    base = Path(tempfile.mkdtemp(prefix="soffice-mutants-"))
    base.chmod(0o755)
    try:
        scratch, tree = _fresh_scratch(base, "baseline")
        all_tests = tuple(dict.fromkeys(t for m in selected for t in m.tests))
        code, output = _run(tree, scratch, all_tests)
        if code != 0:
            print(output)
            print("baseline: the unmutated guard fails its own tests; fix that first")
            return 1
        print(f"baseline: {all_tests} pass on the unmutated guard\n")

        failures = 0
        for mutation in selected:
            scratch, tree = _fresh_scratch(base, mutation.id)
            target = tree / mutation.target
            target.write_text(_apply(target.read_text(encoding="utf-8"), mutation), encoding="utf-8")
            code, output = _run(tree, scratch, mutation.tests)
            outcome = _outcome(code, output)
            bad = outcome != "killed" and (outcome != "not exercised" or args.strict)
            failures += bad
            print(f"{'FAIL' if bad else 'ok  '}  {mutation.id:28} {outcome:14} {mutation.guard}")
            if bad:
                print(output[-3000:])
        print(f"\n{len(selected) - failures}/{len(selected)} mutations handled")
        return 1 if failures else 0
    finally:
        if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
            # Other users' files from the two-user test need root to remove.
            subprocess.run(["sudo", "-n", "rm", "-rf", str(base)], capture_output=True)
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
