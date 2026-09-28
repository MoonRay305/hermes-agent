"""The LibreOffice wrapper against a real LibreOffice.

Skipped when LibreOffice is not installed; the "LibreOffice guard" CI job
installs libreoffice-calc and runs this file. Tests that act as other users
also need root or passwordless sudo (the CI runner has both).
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
from pathlib import Path

import pytest

from tests.skills._soffice_support import (
    WRAPPER_PATH,
    as_root,
    can_switch_users,
    isolate_home,
    libreoffice_available,
    load_wrapper,
    other_users,
    popen_as,
    private_root,
    profile_dirs,
    run_as,
    system_python,
    write_formula_xlsx,
)

pytestmark = [
    pytest.mark.skipif(os.name != "posix", reason="POSIX only"),
    pytest.mark.skipif(not libreoffice_available(), reason="LibreOffice is not installed"),
]
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs /proc")
needs_other_users = pytest.mark.skipif(
    not can_switch_users() or len(other_users(2)) < 2,
    reason="needs root or passwordless sudo and two unprivileged accounts",
)
LAUNCH_TIMEOUT = 180


def _root_mode() -> int:
    return stat.S_IMODE(os.stat("/").st_mode)


def _cli_env(home: Path) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8"}


@pytest.fixture
def home(monkeypatch, tmp_path):
    return isolate_home(monkeypatch, tmp_path)


@pytest.fixture
def world_traversable(tmp_path_factory):
    """A directory other users can traverse (pytest's own tmp root is 0700)."""
    base = Path(tempfile.mkdtemp(prefix="hermes-lo-test-", dir="/tmp"))
    base.chmod(0o755)
    yield base
    if can_switch_users():
        as_root(["rm", "-rf", str(base)])
    else:
        shutil.rmtree(base, ignore_errors=True)


def _pdf_ok(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0 and path.read_bytes().startswith(b"%PDF")


# ---- the old probe, as a test -----------------------------------------------


def test_real_conversion_uses_a_private_profile(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    doc = write_formula_xlsx(tmp_path / "proof.xlsx")
    out = tmp_path / "out"
    out.mkdir()
    before = _root_mode()

    result = subprocess.run(
        [sys.executable, str(WRAPPER_PATH), "--headless", "--convert-to", "pdf", "--outdir", str(out), str(doc)],
        env=_cli_env(home),
        capture_output=True,
        text=True,
        timeout=LAUNCH_TIMEOUT,
    )

    assert result.returncode == 0, result.stderr
    assert _pdf_ok(out / "proof.pdf")
    assert _root_mode() == before
    root = private_root(home)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert profile_dirs(root) == []
    assert not (home / ".config" / "libreoffice").exists()


def test_concurrent_launches_do_not_collide(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    runs = []
    for index in range(2):
        out = tmp_path / f"out{index}"
        out.mkdir()
        doc = write_formula_xlsx(tmp_path / f"doc{index}.xlsx")
        runs.append((out / f"doc{index}.pdf", subprocess.Popen(
            [sys.executable, str(WRAPPER_PATH), "--headless", "--convert-to", "pdf", "--outdir", str(out), str(doc)],
            env=_cli_env(home),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )))

    for pdf, process in runs:
        _, stderr = process.communicate(timeout=LAUNCH_TIMEOUT)
        assert process.returncode == 0, stderr
        assert _pdf_ok(pdf)
    assert profile_dirs(private_root(home)) == []


# ---- a profile swap between creation and launch must fail ---------------------

_SAME_USER_SWAPPER = textwrap.dedent(
    """
    import os, sys
    for line in sys.stdin:
        target, bait = line.rstrip("\\n").split("\\t")
        try:
            os.rename(target, target + "-moved")
            os.symlink(bait, target)
            print("swapped", flush=True)
        except OSError as exc:
            print(f"failed {exc.errno}", flush=True)
    """
)


def _delegate_after(real_run, before_launch):
    def run(argv, **kwargs):
        if argv and str(argv[0]).endswith(("soffice", "libreoffice")):
            before_launch(argv)
        return real_run(argv, **kwargs)

    return run


def _profile_on_disk(argv) -> Path:
    url = argv[1].split("=", 1)[1]
    return Path(os.path.realpath(url[len("file://"):]))


@linux_only
def test_same_user_swap_between_creation_and_launch_is_defeated(home, tmp_path, monkeypatch):
    wrapper = load_wrapper()
    bait = tmp_path / "bait"
    bait.mkdir()
    doc = write_formula_xlsx(tmp_path / "doc.xlsx")
    out = tmp_path / "out"
    out.mkdir()
    swapper = subprocess.Popen(
        [sys.executable, "-c", _SAME_USER_SWAPPER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    seen = {}

    def swap_from_outside(argv):
        profile = _profile_on_disk(argv)
        seen["profile"] = profile
        swapper.stdin.write(f"{profile}\t{bait}\n")
        swapper.stdin.flush()
        seen["swap"] = swapper.stdout.readline().strip()

    monkeypatch.setattr(wrapper.subprocess, "run", _delegate_after(subprocess.run, swap_from_outside))
    try:
        result = wrapper.run_soffice(
            ["--headless", "--convert-to", "pdf", "--outdir", str(out), str(doc)],
            capture_output=True,
            timeout=LAUNCH_TIMEOUT,
        )
    finally:
        swapper.stdin.close()
        swapper.wait(timeout=30)

    assert seen["swap"] == "swapped"
    assert result.returncode == 0, result.stderr
    assert _pdf_ok(out / "doc.pdf")
    assert list(bait.iterdir()) == []
    moved = seen["profile"].with_name(seen["profile"].name + "-moved")
    assert (moved / "user").is_dir()


_OTHER_USER_ATTACKER = textwrap.dedent(
    """
    import json, os, select, sys, time
    target, bait = sys.stdin.readline().rstrip("\\n").split("\\t")
    attempts = successes = 0
    errors = set()
    print("ready", flush=True)
    while not select.select([sys.stdin], [], [], 0)[0]:
        for action in (lambda: os.rename(target, target + "-moved"), lambda: os.symlink(bait, target)):
            attempts += 1
            try:
                action()
                successes += 1
            except OSError as exc:
                errors.add(exc.errno)
        time.sleep(0.002)
    print(json.dumps({"attempts": attempts, "successes": successes, "errors": sorted(errors)}), flush=True)
    """
)


@linux_only
@needs_other_users
def test_other_user_cannot_swap_the_profile(world_traversable, monkeypatch):
    [attacker] = other_users(1)
    home = world_traversable / "home"
    home.mkdir(mode=0o755)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    # Start from a root anyone could write to: the wrapper must close it.
    root = private_root(home)
    root.mkdir(parents=True)
    for directory in (home / ".cache", home / ".cache" / "hermes"):
        directory.chmod(0o755)
    root.chmod(0o777)
    bait = world_traversable / "bait"
    bait.mkdir(mode=0o777)
    bait.chmod(0o777)
    doc = write_formula_xlsx(world_traversable / "doc.xlsx")
    out = world_traversable / "out"
    out.mkdir()
    wrapper = load_wrapper()
    process = popen_as(
        attacker,
        [system_python(), "-c", _OTHER_USER_ATTACKER],
        {"PATH": "/usr/bin:/bin"},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    def start_attack(argv):
        process.stdin.write(f"{_profile_on_disk(argv)}\t{bait}\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == "ready"

    monkeypatch.setattr(wrapper.subprocess, "run", _delegate_after(subprocess.run, start_attack))
    try:
        result = wrapper.run_soffice(
            ["--headless", "--convert-to", "pdf", "--outdir", str(out), str(doc)],
            capture_output=True,
            timeout=LAUNCH_TIMEOUT,
        )
    finally:
        process.stdin.write("stop\n")
        process.stdin.close()
        report = json.loads(process.stdout.readline())
        process.wait(timeout=30)

    assert result.returncode == 0, result.stderr
    assert _pdf_ok(out / "doc.pdf")
    assert report["attempts"] > 0
    assert report["successes"] == 0, report
    assert list(bait.iterdir()) == []
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


# ---- two users on one host ----------------------------------------------------


@needs_other_users
def test_two_users_can_launch_on_the_same_host(world_traversable):
    users = other_users(2)
    shared = world_traversable / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    wrapper_copy = shared / "soffice.py"
    shutil.copy(WRAPPER_PATH, wrapper_copy)
    wrapper_copy.chmod(0o644)
    doc = write_formula_xlsx(shared / "doc.xlsx")
    doc.chmod(0o644)

    homes = {}
    for user in users:
        home = world_traversable / f"home-{user.pw_name}"
        as_root(["install", "-d", "-o", str(user.pw_uid), "-g", str(user.pw_gid), "-m", "700", str(home)])
        homes[user.pw_name] = home

    def convert(user, label):
        home = homes[user.pw_name]
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8"}
        if "TMPDIR" in os.environ:
            env["TMPDIR"] = os.environ["TMPDIR"]
        return run_as(
            user,
            [system_python(), str(wrapper_copy), "--headless", "--convert-to", "pdf", "--outdir", str(home / label), str(doc)],
            env,
            capture_output=True,
            text=True,
            timeout=LAUNCH_TIMEOUT,
        )

    # Sequential both ways (a shared root locks the second user out), then at once.
    results = [(user, "first", convert(user, "first")) for user in users]
    results += [(users[0], "again", convert(users[0], "again"))]
    concurrent = {}
    threads = [
        threading.Thread(target=lambda u=user: concurrent.__setitem__(u.pw_name, convert(u, "together")))
        for user in users
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    results += [(user, "together", concurrent[user.pw_name]) for user in users]

    for user, label, result in results:
        assert result.returncode == 0, (user.pw_name, label, result.stderr)
    listing = as_root(["find", str(world_traversable), "-name", "*.pdf"], capture_output=True, text=True).stdout
    for user, label, _ in results:
        assert str(homes[user.pw_name] / label / "doc.pdf") in listing
    for user in users:
        root = private_root(homes[user.pw_name])
        owner_mode = as_root(["stat", "-c", "%u %a", str(root)], capture_output=True, text=True).stdout.split()
        assert owner_mode == [str(user.pw_uid), "700"]


# ---- the socket shim, in a sandbox that blocks AF_UNIX -----------------------

# Preloaded after the shim, this makes socket(AF_UNIX, ...) fail the way a
# sandbox does: the shim's real_socket (dlsym RTLD_NEXT) resolves to it, so the
# shim's socketpair fallback is what LibreOffice actually runs on.
_AF_UNIX_BLOCKER = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
int socket(int domain, int type, int protocol) {
    static int (*next)(int, int, int);
    if (!next) next = dlsym(RTLD_NEXT, "socket");
    if (domain == AF_UNIX) { errno = EPERM; return -1; }
    return next(domain, type, protocol);
}
"""


@pytest.fixture
def af_unix_blocker(tmp_path):
    source = tmp_path / "block_af_unix.c"
    source.write_text(_AF_UNIX_BLOCKER, encoding="utf-8")
    library = tmp_path / "block_af_unix.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library), str(source), "-ldl"], check=True)
    return str(library)


def _convert_with_preload(wrapper, monkeypatch, tmp_path, label, extend_preload):
    doc = write_formula_xlsx(tmp_path / f"{label}.xlsx")
    out = tmp_path / f"out-{label}"
    out.mkdir()
    seen = {}
    real_run = subprocess.run

    def run(argv, **kwargs):
        env = kwargs.get("env")
        if env is not None and str(argv[0]).endswith(("soffice", "libreoffice")):
            seen["shim"] = env.get("LD_PRELOAD")
            if seen["shim"]:
                seen["digest"] = hashlib.sha256(Path(seen["shim"]).read_bytes()).hexdigest()
            kwargs["env"] = dict(env, LD_PRELOAD=extend_preload(env.get("LD_PRELOAD")))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(wrapper.subprocess, "run", run)
    result = wrapper.run_soffice(
        ["--headless", "--convert-to", "pdf", "--outdir", str(out), str(doc)],
        capture_output=True,
        timeout=LAUNCH_TIMEOUT,
    )
    return result, out / f"{label}.pdf", seen


@linux_only
@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_blocked_af_unix_breaks_libreoffice_without_the_shim(home, tmp_path, monkeypatch, af_unix_blocker):
    # Control: the blocker really takes away what LibreOffice needs.
    wrapper = load_wrapper()
    monkeypatch.setattr(wrapper, "_needs_shim", lambda: False)

    result, pdf, seen = _convert_with_preload(wrapper, monkeypatch, tmp_path, "unshimmed", lambda _: af_unix_blocker)

    assert seen["shim"] is None
    assert not pdf.exists()


@linux_only
@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_shim_converts_under_blocked_af_unix_from_sealed_memory(home, tmp_path, monkeypatch, af_unix_blocker):
    wrapper = load_wrapper()
    monkeypatch.setattr(wrapper, "_needs_shim", lambda: True)
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared))

    result, pdf, seen = _convert_with_preload(
        wrapper, monkeypatch, tmp_path, "shimmed", lambda shim: f"{shim} {af_unix_blocker}"
    )

    assert result.returncode == 0, result.stderr
    assert _pdf_ok(pdf), "soffice exited without converting under the shim"
    cached = private_root(home) / "shim" / wrapper._shim_name()
    recorded = cached.with_name(cached.name + ".sha256").read_text(encoding="ascii").strip()
    assert seen["shim"].startswith(f"/proc/{os.getpid()}/fd/")
    assert seen["digest"] == recorded == hashlib.sha256(cached.read_bytes()).hexdigest()
    assert list(shared.iterdir()) == []
