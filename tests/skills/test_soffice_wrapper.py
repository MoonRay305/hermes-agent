"""Unit tests for the LibreOffice wrapper; no LibreOffice needed.

subprocess.run inside the wrapper is replaced by FakeSoffice, which plays
soffice: it inspects the profile and preload the wrapper hands over while they
still exist.
"""

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

import pytest

from tests.skills._soffice_support import (
    WRAPPER_PATH,
    isolate_home,
    load_wrapper,
    private_root,
    profile_dirs,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="profile ownership is enforced on POSIX")
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs /proc and memfd")

FAKE_BINARY = "/opt/fake-libreoffice/program/soffice"
FAKE_SHIM = b"\x7fELF fake shim built by the test"


def _profile_path(argv) -> str:
    option = argv[1]
    assert option.startswith("-env:UserInstallation="), argv
    return url2pathname(urlsplit(option.split("=", 1)[1]).path)


class FakeSoffice:
    def __init__(self, on_launch=None):
        self.on_launch = on_launch
        self.launches = []

    def __call__(self, argv, **kwargs):
        profile = _profile_path(argv)
        env = kwargs["env"]
        launch = {
            "argv": list(argv),
            "kwargs": kwargs,
            "env": env,
            "profile_url_path": profile,
            "profile": Path(os.path.realpath(profile)),
            "profile_mode": stat.S_IMODE(os.stat(profile).st_mode),
        }
        if "LD_PRELOAD" in env:
            launch["preload_bytes"] = Path(env["LD_PRELOAD"]).read_bytes()
        if self.on_launch is not None:
            self.on_launch(launch)
        self.launches.append(launch)
        return subprocess.CompletedProcess(argv, 0)


@pytest.fixture
def home(monkeypatch, tmp_path):
    return isolate_home(monkeypatch, tmp_path)


@pytest.fixture
def wrapper(monkeypatch, home):
    module = load_wrapper()
    monkeypatch.setattr(module, "_find_soffice", lambda: FAKE_BINARY)
    monkeypatch.setattr(module, "_needs_shim", lambda: False)
    return module


@pytest.fixture
def fake(monkeypatch, wrapper):
    recorder = FakeSoffice()
    monkeypatch.setattr(wrapper.subprocess, "run", recorder)
    return recorder


# ---- the wrapper owns a fresh, private profile -------------------------------


def test_launch_uses_fresh_private_profile_and_removes_it(wrapper, fake, home):
    wrapper.run_soffice(["--headless", "--convert-to", "pdf", "in.docx"])

    [launch] = fake.launches
    root = private_root(home)
    assert launch["argv"][0] == FAKE_BINARY
    assert launch["argv"][2:] == ["--headless", "--convert-to", "pdf", "in.docx"]
    assert launch["profile"].parent == root
    assert launch["profile"].name.startswith("lo_profile_")
    assert launch["profile_mode"] == 0o700
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert profile_dirs(root) == []


def test_each_launch_gets_its_own_profile(wrapper, fake):
    wrapper.run_soffice(["--headless"])
    wrapper.run_soffice(["--headless"])

    first, second = (launch["profile"] for launch in fake.launches)
    assert first != second


def test_profile_never_lands_in_shared_temp(wrapper, fake, monkeypatch, tmp_path):
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared))

    wrapper.run_soffice(["--headless"])

    assert list(shared.iterdir()) == []
    assert shared not in fake.launches[0]["profile"].parents


@linux_only
def test_profile_is_passed_by_descriptor(wrapper, fake):
    wrapper.run_soffice(["--headless"])

    url_path = fake.launches[0]["profile_url_path"]
    assert url_path.startswith(f"/proc/{os.getpid()}/fd/")


@linux_only
def test_renaming_the_profile_before_launch_cannot_redirect_it(wrapper, monkeypatch, tmp_path):
    bait = tmp_path / "bait"
    bait.mkdir()

    def swap(launch):
        # What an outside process could do between creation and launch.
        original = launch["profile"]
        os.rename(original, original.with_name(original.name + "-moved"))
        os.symlink(bait, original)
        launch["after_swap"] = Path(os.path.realpath(launch["profile_url_path"]))
        launch["moved"] = original.with_name(original.name + "-moved")

    recorder = FakeSoffice(on_launch=swap)
    monkeypatch.setattr(wrapper.subprocess, "run", recorder)

    wrapper.run_soffice(["--headless"])

    [launch] = recorder.launches
    assert launch["after_swap"] == launch["moved"]
    assert launch["after_swap"] != bait


def test_xdg_runtime_dir_is_used_when_private(wrapper, fake, monkeypatch, tmp_path):
    runtime = tmp_path / "run-user"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

    wrapper.run_soffice(["--headless"])

    assert fake.launches[0]["profile"].parent == runtime / "hermes-lo-profiles"


def test_shared_xdg_runtime_dir_is_ignored(wrapper, fake, monkeypatch, tmp_path, home):
    runtime = tmp_path / "run-shared"
    runtime.mkdir()
    runtime.chmod(0o777)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))

    wrapper.run_soffice(["--headless"])

    assert fake.launches[0]["profile"].parent == private_root(home)
    assert list(runtime.iterdir()) == []


# ---- the private root must really be private --------------------------------


def test_loose_private_root_is_tightened_to_0700(wrapper, fake, home):
    root = private_root(home)
    root.mkdir(parents=True)
    root.chmod(0o777)

    wrapper.run_soffice(["--headless"])

    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_symlinked_private_root_is_refused(wrapper, fake, home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    root = private_root(home)
    root.parent.mkdir(parents=True)
    root.symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(wrapper.UnsafeLaunchError, match="symlink"):
        wrapper.run_soffice(["--headless"])

    assert fake.launches == []
    assert list(elsewhere.iterdir()) == []


def test_private_root_owned_by_someone_else_is_refused(wrapper, fake, home, monkeypatch):
    private_root(home).mkdir(parents=True, mode=0o700)
    real_uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real_uid + 4242)

    with pytest.raises(wrapper.UnsafeLaunchError, match="owned by the current user"):
        wrapper.run_soffice(["--headless"])

    assert fake.launches == []


# ---- callers cannot choose or influence the profile -------------------------


@pytest.mark.parametrize(
    "arg",
    [
        "-env:UserInstallation=file:///",
        "-env:UserInstallation=file:///root",
        "-env:UserInstallation=file:///etc",
        "-env:UserInstallation=file:///var/tmp/lo-profiles/x",
        "/env:UserInstallation=file:///",
        "--env:UserInstallation=file:///",
        "-ENV:userinstallation=file:///",
        "-env:UserInstallation",
        "/env:UserInstallation",
        "-env:BRAND_BASE_DIR=file:///",
        " -env:UserInstallation=file:///",
    ],
)
def test_caller_bootstrap_overrides_are_refused(wrapper, fake, arg):
    with pytest.raises(wrapper.UnsafeLaunchError, match="owns the user profile"):
        wrapper.run_soffice(["--headless", arg, "--convert-to", "pdf", "in.docx"])

    assert fake.launches == []


def test_userinstallation_environment_variable_is_dropped(wrapper, fake, monkeypatch):
    monkeypatch.setenv("UserInstallation", "file:///")

    wrapper.run_soffice(["--headless"])

    env = fake.launches[0]["env"]
    assert not any(key.lower() == "userinstallation" for key in env)
    assert env["SAL_USE_VCLPLUGIN"] == "svp"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"env": {"UserInstallation": "file:///"}},
        {"executable": "/bin/sh"},
        {"shell": True},
        {"preexec_fn": lambda: None},
        {"pass_fds": (0,)},
    ],
)
def test_subprocess_options_that_bypass_the_wrapper_are_refused(wrapper, fake, kwargs):
    with pytest.raises(TypeError, match="does not accept"):
        wrapper.run_soffice(["--headless"], **kwargs)

    assert fake.launches == []


def test_ordinary_subprocess_options_pass_through(wrapper, fake, tmp_path):
    wrapper.run_soffice(["--headless"], cwd=tmp_path, timeout=5, check=True, capture_output=True)

    kwargs = fake.launches[0]["kwargs"]
    assert kwargs["cwd"] == tmp_path
    assert kwargs["timeout"] == 5


def test_missing_libreoffice_raises_before_touching_disk(wrapper, fake, monkeypatch, home):
    monkeypatch.setattr(wrapper, "_find_soffice", lambda: None)

    with pytest.raises(FileNotFoundError):
        wrapper.run_soffice(["--headless"])

    assert not private_root(home).exists()


# ---- command-line entry point: sentinel matrix (the old probe) --------------

UNSAFE_PROFILE_VALUES = [
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
]


@pytest.mark.parametrize("option", ["-env:UserInstallation", "/env:UserInstallation"])
@pytest.mark.parametrize("value", UNSAFE_PROFILE_VALUES)
def test_cli_refuses_caller_profiles_without_launching(tmp_path, option, value):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "sentinel-launched"
    sentinel = bin_dir / "soffice"
    sentinel.write_text(f"#!/bin/sh\necho launched > '{marker}'\n", encoding="utf-8")
    sentinel.chmod(0o755)
    root_mode = stat.S_IMODE(os.stat("/").st_mode)
    env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin", "HOME": str(tmp_path / "home")}

    result = subprocess.run(
        [sys.executable, str(WRAPPER_PATH), f"{option}={value}", "--headless"],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "Refusing LibreOffice launch" in result.stderr
    assert not marker.exists()
    assert stat.S_IMODE(os.stat("/").st_mode) == root_mode


def test_cli_launches_through_the_wrapper_profile(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "argv.log"
    stand_in = bin_dir / "soffice"
    stand_in.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\n', encoding="utf-8")
    stand_in.chmod(0o755)
    home = tmp_path / "home"
    env = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin", "HOME": str(home)}

    result = subprocess.run(
        [sys.executable, str(WRAPPER_PATH), "--headless", "--convert-to", "pdf", "in.docx"],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    argv = log.read_text(encoding="utf-8").splitlines()
    assert argv[0].startswith("-env:UserInstallation=file://")
    assert argv[1:] == ["--headless", "--convert-to", "pdf", "in.docx"]
    assert profile_dirs(private_root(home)) == []


# ---- AF_UNIX socket shim -----------------------------------------------------


@pytest.fixture
def shim_wrapper(wrapper, monkeypatch):
    builds = []

    def fake_compile(source, output):
        builds.append(Path(source))
        Path(output).write_bytes(FAKE_SHIM)

    monkeypatch.setattr(wrapper, "_needs_shim", lambda: True)
    monkeypatch.setattr(wrapper, "_compile_shim", fake_compile)
    wrapper.test_builds = builds
    return wrapper


def _shim_cache(home, wrapper) -> Path:
    return private_root(home) / "shim" / wrapper._shim_name()


@linux_only
def test_shim_is_built_in_private_root_and_recorded(shim_wrapper, fake, home, monkeypatch, tmp_path):
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    # PR #27 reused a shim from this fixed name in the shared temp directory.
    (shared / "lo_socket_shim.so").write_bytes(b"planted by another user")
    monkeypatch.setattr(tempfile, "tempdir", str(shared))

    shim_wrapper.run_soffice(["--headless"])

    cached = _shim_cache(home, shim_wrapper)
    assert cached.read_bytes() == FAKE_SHIM
    recorded = cached.with_name(cached.name + ".sha256").read_text(encoding="ascii").strip()
    assert recorded == hashlib.sha256(FAKE_SHIM).hexdigest()
    assert all(private_root(home) in source.parents for source in shim_wrapper.test_builds)
    assert fake.launches[0]["preload_bytes"] == FAKE_SHIM
    assert sorted(p.name for p in shared.iterdir()) == ["lo_socket_shim.so"]
    assert stat.S_IMODE(cached.parent.stat().st_mode) == 0o700


@linux_only
def test_shim_build_works_under_group_writable_umask(shim_wrapper, fake, home, monkeypatch):
    def compile_like_gcc(source, output):
        shim_wrapper.test_builds.append(Path(source))
        Path(output).write_bytes(FAKE_SHIM)
        Path(output).chmod(0o775)  # what gcc leaves behind under umask 002

    monkeypatch.setattr(shim_wrapper, "_compile_shim", compile_like_gcc)

    shim_wrapper.run_soffice(["--headless"])

    assert fake.launches[0]["preload_bytes"] == FAKE_SHIM
    assert stat.S_IMODE(_shim_cache(home, shim_wrapper).stat().st_mode) == 0o600


@linux_only
def test_verified_shim_is_reused_without_rebuilding(shim_wrapper, fake):
    shim_wrapper.run_soffice(["--headless"])
    shim_wrapper.run_soffice(["--headless"])

    assert len(shim_wrapper.test_builds) == 1
    assert [launch["preload_bytes"] for launch in fake.launches] == [FAKE_SHIM, FAKE_SHIM]


@linux_only
def test_tampered_shim_is_never_preloaded(shim_wrapper, fake, home):
    shim_wrapper.run_soffice(["--headless"])
    cached = _shim_cache(home, shim_wrapper)
    cached.write_bytes(b"tampered after the build")

    shim_wrapper.run_soffice(["--headless"])

    assert fake.launches[1]["preload_bytes"] == FAKE_SHIM
    assert len(shim_wrapper.test_builds) == 2


@linux_only
def test_shim_writable_by_others_is_never_preloaded(shim_wrapper, fake, home):
    shim_wrapper.run_soffice(["--headless"])
    cached = _shim_cache(home, shim_wrapper)
    planted = b"planted by a group member"
    cached.write_bytes(planted)
    cached.with_name(cached.name + ".sha256").write_text(hashlib.sha256(planted).hexdigest(), encoding="ascii")
    cached.chmod(0o664)

    shim_wrapper.run_soffice(["--headless"])

    assert fake.launches[1]["preload_bytes"] == FAKE_SHIM


@linux_only
def test_preloaded_shim_is_sealed(shim_wrapper, monkeypatch):
    def try_to_modify(launch):
        preload = launch["env"]["LD_PRELOAD"]
        launch["preload"] = preload
        with pytest.raises(PermissionError):
            with open(preload, "r+b") as handle:
                handle.write(b"x")

    recorder = FakeSoffice(on_launch=try_to_modify)
    monkeypatch.setattr(shim_wrapper.subprocess, "run", recorder)

    shim_wrapper.run_soffice(["--headless"])

    assert recorder.launches[0]["preload"].startswith(f"/proc/{os.getpid()}/fd/")
