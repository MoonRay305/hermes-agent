import importlib.util
import os
import stat
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

import pytest


WRAPPERS = [
    "skills/productivity/docx/scripts/office/soffice.py",
    "skills/productivity/xlsx/scripts/office/soffice.py",
    "skills/productivity/powerpoint/scripts/office/soffice.py",
]
APPROVED_PROFILE_ROOT = Path("/var/tmp/lo-profiles")


def _load_wrapper(repo_root: Path, relative_path: str):
    module_name = "soffice_" + relative_path.split("/")[2]
    spec = importlib.util.spec_from_file_location(
        module_name, repo_root / relative_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(params=WRAPPERS)
def wrapper(request):
    repo_root = Path(__file__).resolve().parents[1]
    return _load_wrapper(repo_root, request.param)


@pytest.fixture
def approved_root(wrapper, monkeypatch, tmp_path):
    root = tmp_path / "lo-profiles"
    root.mkdir()
    monkeypatch.setattr(wrapper, "_APPROVED_PROFILE_ROOT", root)
    return root


def test_profile_allowlist_uses_one_dedicated_production_root(wrapper):
    assert wrapper._APPROVED_PROFILE_ROOT == APPROVED_PROFILE_ROOT


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
@pytest.mark.parametrize(
    "value",
    [
        "file:///root",
        "file:///",
        "file:///etc",
        "file:///var",
        "file:///home/landon",
        "file:///tmp",
        "file:///var/tmp/lo-profiles",
        "file:///var/tmp/lo-profiles/../../../root",
        "file:///var/tmp/lo-profiles/%2e%2e/%2e%2e/%2e%2e/root",
        "file://",
        "relative-profile",
        "file:relative-profile",
        "file:./relative-profile",
        "file:../relative-profile",
    ],
)
def test_run_soffice_refuses_unsafe_explicit_profile(
    wrapper, monkeypatch, option, value
):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Refusing unsafe LibreOffice user profile"):
        wrapper.run_soffice([f"{option}={value}", "--headless"])

    assert not called


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
def test_run_soffice_refuses_missing_profile_value(wrapper, monkeypatch, option):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Refusing unsafe LibreOffice user profile"):
        wrapper.run_soffice([option, "--headless"])

    assert not called


def test_run_soffice_refuses_multiple_explicit_profiles(wrapper, monkeypatch, tmp_path):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)
    first = (tmp_path / "first").as_uri()
    second = (tmp_path / "second").as_uri()

    with pytest.raises(ValueError, match="exactly one"):
        wrapper.run_soffice([
            f"-env:UserInstallation={first}",
            f"-env:UserInstallation={second}",
            "--headless",
        ])

    assert not called


def test_run_soffice_refuses_mixed_prefix_root_first_profile_override(
    wrapper, monkeypatch, tmp_path
):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)
    safe_profile = (tmp_path / "safe-profile").as_uri()

    with pytest.raises(ValueError, match="exactly one"):
        wrapper.run_soffice([
            "/env:UserInstallation=file:///",
            f"-env:UserInstallation={safe_profile}",
            "--headless",
        ])

    assert not called


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
def test_run_soffice_refuses_profile_symlink_escaping_allowlist(
    wrapper, monkeypatch, approved_root, option
):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)
    root_link = approved_root / "root-link"
    root_link.symlink_to("/root", target_is_directory=True)

    with pytest.raises(ValueError, match="Refusing unsafe LibreOffice user profile"):
        wrapper.run_soffice([
            f"{option}={root_link.as_uri()}",
            "--headless",
        ])

    assert not called


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
def test_run_soffice_accepts_allowlisted_explicit_profile(
    wrapper, monkeypatch, approved_root, option
):
    captured = {}
    profile = approved_root / "profile"

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice([
        f"{option}={profile.as_uri()}",
        "--headless",
    ])

    assert result.returncode == 0
    assert captured["argv"][1] == f"{option}={profile.as_uri()}"


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
def test_run_soffice_accepts_normalized_descendant(
    wrapper, monkeypatch, approved_root, option
):
    captured = {}
    profile_uri = (approved_root / "batch" / "profile").as_uri()
    equivalent = profile_uri.replace(
        "/lo-profiles/", "/lo-profiles//nested/../"
    ) + "/"

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice([
        f"{option}={equivalent}",
        "--headless",
    ])

    assert result.returncode == 0
    assert captured["argv"][1] == f"{option}={equivalent}"


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
def test_run_soffice_accepts_url_encoded_allowlisted_descendant(
    wrapper, monkeypatch, approved_root, option
):
    captured = {}
    profile_uri = (approved_root / "profile with spaces").as_uri()

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice([
        f"{option}={profile_uri}",
        "--headless",
    ])

    assert result.returncode == 0
    assert captured["argv"][1] == f"{option}={profile_uri}"


def test_run_soffice_generates_profile_under_allowlisted_root(
    wrapper, monkeypatch, approved_root
):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        profile_arg = argv[1]
        uri = profile_arg.split("=", 1)[1]
        path = Path(url2pathname(unquote(urlsplit(uri).path))).resolve()
        assert path.is_absolute()
        assert path.is_relative_to(approved_root.resolve())
        assert path != approved_root.resolve()
        assert path.is_dir()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice(["--headless"])

    assert result.returncode == 0
    profile_uri = captured["argv"][1].split("=", 1)[1]
    profile_path = Path(url2pathname(unquote(urlsplit(profile_uri).path)))
    assert not profile_path.exists()
    assert approved_root.exists()
    assert stat.S_IMODE(approved_root.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "nt", reason="Windows drive-root URI semantics")
def test_run_soffice_refuses_windows_drive_root(wrapper, monkeypatch):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Refusing unsafe LibreOffice user profile"):
        wrapper.run_soffice([
            "-env:UserInstallation=file:///C:/",
            "--headless",
        ])

    assert not called
