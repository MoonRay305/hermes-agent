import importlib.util
import os
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


@pytest.mark.parametrize(
    "unsafe_profile",
    [
        "-env:UserInstallation=file://",
        "-env:UserInstallation=file:///",
        "-env:UserInstallation=file:///%2F",
        "-env:UserInstallation=relative-profile",
        "-env:UserInstallation=file:relative-profile",
        "-env:UserInstallation=file:./relative-profile",
        "-env:UserInstallation=file:../relative-profile",
        "-env:UserInstallation",
    ],
)
def test_run_soffice_refuses_unsafe_explicit_profile(
    wrapper, monkeypatch, unsafe_profile
):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="Refusing unsafe LibreOffice user profile"):
        wrapper.run_soffice([unsafe_profile, "--headless"])

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


def test_run_soffice_refuses_profile_symlink_resolving_to_root(
    wrapper, monkeypatch, tmp_path
):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)
    root_link = tmp_path / "root-link"
    root_link.symlink_to("/", target_is_directory=True)

    with pytest.raises(ValueError, match="absolute and non-root"):
        wrapper.run_soffice([
            f"-env:UserInstallation={root_link.as_uri()}",
            "--headless",
        ])

    assert not called


def test_run_soffice_accepts_safe_absolute_explicit_profile(
    wrapper, monkeypatch, tmp_path
):
    captured = {}
    profile = tmp_path / "profile"

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice([
        f"-env:UserInstallation={profile.as_uri()}",
        "--headless",
    ])

    assert result.returncode == 0
    assert captured["argv"][1] == f"-env:UserInstallation={profile.as_uri()}"


def test_run_soffice_generates_non_root_temporary_profile(wrapper, monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        profile_arg = argv[1]
        uri = profile_arg.split("=", 1)[1]
        path = Path(url2pathname(unquote(urlsplit(uri).path))).resolve()
        assert path.is_absolute()
        assert path.parent != path
        assert path.is_dir()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "get_soffice_env", lambda: {})
    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    result = wrapper.run_soffice(["--headless"])

    assert result.returncode == 0
    profile_uri = captured["argv"][1].split("=", 1)[1]
    profile_path = Path(url2pathname(unquote(urlsplit(profile_uri).path)))
    assert not profile_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows drive-root URI semantics")
def test_run_soffice_refuses_windows_drive_root(wrapper, monkeypatch):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(wrapper.subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="absolute and non-root"):
        wrapper.run_soffice([
            "-env:UserInstallation=file:///C:/",
            "--headless",
        ])

    assert not called
