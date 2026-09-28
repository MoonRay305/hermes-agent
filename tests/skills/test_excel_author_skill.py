"""excel-author's recalc.py must start LibreOffice only through the shared wrapper."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.skills._soffice_support import (
    RECALC_PATH,
    WRAPPER_PATH,
    cached_value,
    libreoffice_available,
    load_module,
    load_wrapper,
    private_root,
    write_formula_xlsx,
)


@pytest.fixture
def recalc():
    return load_module(RECALC_PATH)


def test_recalc_imports_the_shared_wrapper(recalc):
    wrapper = recalc.load_soffice_wrapper()

    assert wrapper is not None
    assert Path(wrapper.__file__).resolve() == WRAPPER_PATH.resolve()


def test_recalc_launches_through_run_soffice(recalc, monkeypatch, tmp_path):
    workbook = write_formula_xlsx(tmp_path / "model.xlsx")
    calls = []

    class SpyWrapper:
        @staticmethod
        def run_soffice(args, **kwargs):
            calls.append((list(args), kwargs))
            outdir = Path(args[args.index("--outdir") + 1])
            shutil.copy(workbook, outdir / workbook.name)
            return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(recalc, "load_soffice_wrapper", lambda: SpyWrapper)

    result = recalc.recalc(str(workbook), timeout=7)

    assert result["status"] == "success"
    [(args, kwargs)] = calls
    assert args[:4] == ["--headless", "--calc", "--convert-to", "xlsx"]
    assert not any("env:" in arg.lower() for arg in args)
    assert kwargs["timeout"] == 7


def test_recalc_refuses_to_run_without_the_wrapper(recalc, monkeypatch, tmp_path):
    workbook = write_formula_xlsx(tmp_path / "model.xlsx")
    monkeypatch.setattr(recalc, "_wrapper_candidates", lambda: [tmp_path / "missing" / "soffice.py"])

    result = recalc.recalc(str(workbook))

    assert result["status"] == "error"
    assert "refusing" in result["error"]


def test_recalc_reports_missing_libreoffice(recalc, monkeypatch, tmp_path):
    workbook = write_formula_xlsx(tmp_path / "model.xlsx")
    wrapper = load_wrapper()
    monkeypatch.setattr(wrapper, "_find_soffice", lambda: None)
    monkeypatch.setattr(recalc, "load_soffice_wrapper", lambda: wrapper)

    result = recalc.recalc(str(workbook))

    assert result["status"] == "error"
    assert "not installed" in result["error"]


def test_recalc_looks_for_the_wrapper_only_in_fixed_places(tmp_path, monkeypatch):
    # A wrapper planted in an ancestor that is not one of recalc.py's anchors
    # (think /tmp above a copied skill) must never be imported.
    copied = tmp_path / "outer" / "deep" / "finance" / "excel-author" / "scripts" / "recalc.py"
    copied.parent.mkdir(parents=True)
    shutil.copy(RECALC_PATH, copied)
    planted = tmp_path / "productivity" / "powerpoint" / "scripts" / "office" / "soffice.py"
    planted.parent.mkdir(parents=True)
    planted.write_text("raise RuntimeError('planted wrapper imported')\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    monkeypatch.setenv("HERMES_BUNDLED_SKILLS", str(tmp_path / "no-bundled-skills"))

    module = load_module(copied)

    assert all(tmp_path / "productivity" not in c.parents for c in module._wrapper_candidates())
    assert module.load_soffice_wrapper() is None


def test_recalc_finds_the_wrapper_in_an_installed_skills_tree(tmp_path, monkeypatch):
    skills = tmp_path / "hermes-home" / "skills"
    installed = skills / "finance" / "excel-author" / "scripts" / "recalc.py"
    installed.parent.mkdir(parents=True)
    shutil.copy(RECALC_PATH, installed)
    bundled = skills / "productivity" / "powerpoint" / "scripts" / "office" / "soffice.py"
    bundled.parent.mkdir(parents=True)
    shutil.copy(WRAPPER_PATH, bundled)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "elsewhere"))

    wrapper = load_module(installed).load_soffice_wrapper()

    assert Path(wrapper.__file__) == bundled


def _blank_slate(tmp_path: Path) -> tuple[Path, Path]:
    """excel-author installed alone into a profile whose bundled skills were never synced."""
    hermes_home = tmp_path / "hermes-home"
    installed = hermes_home / "skills" / "finance" / "excel-author" / "scripts" / "recalc.py"
    installed.parent.mkdir(parents=True)
    shutil.copy(RECALC_PATH, installed)
    (hermes_home / ".no-bundled-skills").touch()
    return hermes_home, installed


def test_recalc_finds_the_wrapper_in_the_hermes_install_under_blank_slate(tmp_path, monkeypatch):
    hermes_home, installed = _blank_slate(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setenv("HERMES_BUNDLED_SKILLS", str(WRAPPER_PATH.parents[4]))

    wrapper = load_module(installed).load_soffice_wrapper()

    assert wrapper is not None
    assert Path(wrapper.__file__).resolve() == WRAPPER_PATH.resolve()


def test_recalc_uses_the_bundled_override_without_hermes_importable(tmp_path):
    hermes_home, installed = _blank_slate(tmp_path)
    probe = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('recalc', {str(installed)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "print(module.load_soffice_wrapper().__file__)\n"
    )
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "HERMES_HOME": str(hermes_home),
        "HERMES_BUNDLED_SKILLS": str(WRAPPER_PATH.parents[4]),
    }

    # -S: no site-packages, so hermes_constants cannot be imported.
    result = subprocess.run([sys.executable, "-S", "-c", probe], env=env, cwd=tmp_path, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()).resolve() == WRAPPER_PATH.resolve()


@pytest.mark.skipif(os.name != "posix", reason="POSIX only")
@pytest.mark.skipif(not libreoffice_available(), reason="LibreOffice is not installed")
def test_recalc_recalculates_under_blank_slate(tmp_path):
    hermes_home, installed = _blank_slate(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    workbook = write_formula_xlsx(tmp_path / "model.xlsx")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "HERMES_HOME": str(hermes_home),
        "HERMES_BUNDLED_SKILLS": str(WRAPPER_PATH.parents[4]),
    }

    result = subprocess.run(
        [sys.executable, str(installed), str(workbook), "180"],
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert cached_value(workbook, "A2") == "42"
    assert not (home / ".config" / "libreoffice").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX only")
@pytest.mark.skipif(not libreoffice_available(), reason="LibreOffice is not installed")
def test_recalc_with_fresh_home_uses_only_the_wrapper_profile(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    workbook = write_formula_xlsx(tmp_path / "model.xlsx")
    real = load_wrapper()._find_soffice()
    # A stand-in first on PATH records the profile each launch receives,
    # resolved while the launch is live, then hands over to LibreOffice.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "profiles.log"
    stand_in = bin_dir / "soffice"
    stand_in.write_text(
        "#!/bin/sh\n"
        'for arg in "$@"; do\n'
        '  case "$arg" in -env:UserInstallation=file://*)\n'
        f'    readlink -f "${{arg#-env:UserInstallation=file://}}" >> "{log}";;\n'
        "  esac\n"
        "done\n"
        f'exec "{real}" "$@"\n',
        encoding="utf-8",
    )
    stand_in.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(home),
        "LANG": "C.UTF-8",
    }

    result = subprocess.run(
        [sys.executable, str(RECALC_PATH), str(workbook), "180"],
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "success"
    assert cached_value(workbook, "A2") == "42"
    assert not (home / ".config" / "libreoffice").exists()
    [used] = log.read_text(encoding="utf-8").splitlines()
    assert Path(used).parent == private_root(home)
    assert Path(used).name.startswith("lo_profile_")
    assert not Path(used).exists()
