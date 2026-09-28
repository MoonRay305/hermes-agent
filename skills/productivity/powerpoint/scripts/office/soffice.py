"""
Run LibreOffice (soffice) with a private, throwaway user profile.

This module is the one place in the repository that starts LibreOffice; every
other caller imports run_soffice(). tests/skills/test_libreoffice_launch_policy.py
fails on any other launch site.

Usage:
    from office.soffice import run_soffice

    result = run_soffice(["--headless", "--convert-to", "pdf", "input.docx"])

or from a shell:
    python scripts/office/soffice.py --headless --convert-to pdf input.pptx

The wrapper owns the profile; a caller cannot name one. For each launch it:

1. opens a per-user private root -- $XDG_RUNTIME_DIR/hermes-lo-profiles when that
   runtime directory is private to the current user, else
   ${XDG_CACHE_HOME:-~/.cache}/hermes/lo-profiles -- and refuses it unless it is a
   real directory (not a symlink) owned by the current user, forcing mode 0700
   through the open descriptor;
2. creates a fresh lo_profile_* directory inside it with mkdtemp semantics
   (random name, exclusive create, mode 0700), relative to the root's
   descriptor, and holds a descriptor to the new directory;
3. hands soffice that descriptor as /proc/<pid>/fd/<n> on Linux, so replacing
   the directory's name with a symlink before soffice starts cannot redirect
   it (elsewhere it passes the directory's file URI);
4. removes the profile directory when soffice exits.

Any caller argument that sets a LibreOffice bootstrap variable (-env:..,
/env:..) is refused, and UserInstallation is dropped from the child's
environment, so only the wrapper's profile ever reaches soffice.

Limit: LibreOffice resolves the descriptor path to the directory's name when it
starts, so a process running as the same user that keeps renaming the
directory while soffice runs can still redirect it. That process could start
soffice with any profile by itself; the private root keeps every other user
out of the directory entirely.

Sandboxes that block AF_UNIX sockets get an LD_PRELOAD shim. It is compiled into
the private root (never a shared temp directory), its SHA-256 is checked
against the digest recorded when it was built before every preload, and on
Linux the checked bytes are preloaded from a sealed memfd so they cannot change
between the check and the load.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

_PROFILE_OPTION = "-env:UserInstallation="
_PROFILE_PREFIX = "lo_profile_"
# Every spelling of a bootstrap-variable override: the two LibreOffice accepts
# (-env:, /env:) and the ones it rejects today (--env:, mixed case).
_BOOTSTRAP_OVERRIDE = re.compile(r"\s*[-/]+env:", re.IGNORECASE)
# subprocess.run() options a caller may pass. env, executable, shell,
# preexec_fn, pass_fds and the rest could swap the binary or the environment.
_RUN_KWARGS = frozenset({
    "capture_output",
    "check",
    "cwd",
    "encoding",
    "errors",
    "input",
    "stderr",
    "stdin",
    "stdout",
    "text",
    "timeout",
})
_SOFFICE_NAMES = ("soffice", "libreoffice")
_PLATFORM_SOFFICE = {
    "darwin": ("/Applications/LibreOffice.app/Contents/MacOS/soffice",),
    "win32": (
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
    ),
}
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
# Descriptor-relative handling of the root and profile needs dir_fd (POSIX).
_USE_DIR_FDS = os.name == "posix" and {os.mkdir, os.open} <= os.supports_dir_fd


class UnsafeLaunchError(ValueError):
    """Raised instead of starting soffice when the launch would not be private."""


def _find_soffice() -> str | None:
    for name in _SOFFICE_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for candidate in _PLATFORM_SOFFICE.get(sys.platform, ()):
        if os.path.isfile(candidate):
            return candidate
    return None


def run_soffice(args: Iterable[str], **kwargs) -> subprocess.CompletedProcess:
    args = [os.fspath(arg) if isinstance(arg, os.PathLike) else str(arg) for arg in args]
    for arg in args:
        if _BOOTSTRAP_OVERRIDE.match(arg):
            raise UnsafeLaunchError(
                f"Refusing LibreOffice launch: {arg.split('=', 1)[0].strip()!r} "
                "overrides a bootstrap variable; the wrapper owns the user profile"
            )
    unexpected = sorted(set(kwargs) - _RUN_KWARGS)
    if unexpected:
        raise TypeError(f"run_soffice() does not accept {', '.join(unexpected)}")
    binary = _find_soffice()
    if binary is None:
        raise FileNotFoundError("LibreOffice (soffice) is not installed or not on PATH")

    with contextlib.ExitStack() as stack:
        root, root_fd = stack.enter_context(_private_root())
        profile_url = stack.enter_context(_fresh_profile(root, root_fd))
        preload = None
        if _needs_shim():
            preload = stack.enter_context(_verified_shim(root, root_fd))
        return subprocess.run(
            [binary, _PROFILE_OPTION + profile_url, *args],
            env=_child_env(preload),
            **kwargs,
        )


def _child_env(preload: str | None) -> dict[str, str]:
    # LibreOffice also reads bootstrap variables from the environment. The
    # command-line profile wins, but drop the variable so nothing else can.
    env = {k: v for k, v in os.environ.items() if k.lower() != "userinstallation"}
    env["SAL_USE_VCLPLUGIN"] = "svp"
    if preload is not None:
        env["LD_PRELOAD"] = preload
    return env


# ---- private root and profile ----------------------------------------------


def _private_root_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime) and _is_private_dir(runtime):
        return Path(runtime) / "hermes-lo-profiles"
    cache = os.environ.get("XDG_CACHE_HOME", "")
    base = Path(cache) if cache and os.path.isabs(cache) else Path.home() / ".cache"
    return base / "hermes" / "lo-profiles"


def _is_ours(st: os.stat_result) -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is None or st.st_uid == geteuid()


def _is_private_dir(path: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and _is_ours(st) and not st.st_mode & 0o077


def _open_private_dir(name: str | Path, dir_fd: int | None = None) -> int:
    """Create *name* if missing and open it, refusing anything but our own directory.

    The directory is opened without following symlinks, checked through the
    descriptor, and forced to mode 0700 through the descriptor.
    """
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o700, dir_fd=dir_fd)
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise UnsafeLaunchError(
            f"Refusing LibreOffice launch: {name} must be a real directory, not a symlink ({exc})"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or not _is_ours(st):
            raise UnsafeLaunchError(
                f"Refusing LibreOffice launch: {name} is not a directory owned by the current user"
            )
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def _private_root() -> Iterator[tuple[Path, int | None]]:
    try:
        root = _private_root_path()
    except RuntimeError as exc:  # Path.home() with no usable HOME
        raise UnsafeLaunchError(f"Refusing LibreOffice launch: no private profile root ({exc})") from exc
    try:
        root.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UnsafeLaunchError(
            f"Refusing LibreOffice launch: cannot create private profile root {root} ({exc})"
        ) from exc
    if not _USE_DIR_FDS:
        root.mkdir(mode=0o700, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise UnsafeLaunchError(
                f"Refusing LibreOffice launch: {root} must be a real directory, not a symlink"
            )
        yield root, None
        return
    fd = _open_private_dir(root)
    try:
        yield root, fd
    finally:
        os.close(fd)


def _mkdtemp_at(dir_fd: int) -> str:
    """tempfile.mkdtemp() relative to *dir_fd*: random name, exclusive create, 0700."""
    for _ in range(100):
        name = _PROFILE_PREFIX + secrets.token_hex(8)
        try:
            os.mkdir(name, 0o700, dir_fd=dir_fd)
        except FileExistsError:
            continue
        return name
    raise FileExistsError("no unused LibreOffice profile name found")


def _pinned_uri(fd: int) -> str | None:
    """file:///proc/<pid>/fd/<fd> when that path reaches the directory held by *fd*."""
    pinned = f"/proc/{os.getpid()}/fd/{fd}"
    try:
        via_proc, held = os.stat(pinned), os.fstat(fd)
    except OSError:
        return None
    if (via_proc.st_dev, via_proc.st_ino) != (held.st_dev, held.st_ino):
        return None
    return Path(pinned).as_uri()


def _remove_at(root_fd: int, root: Path, name: str) -> None:
    # rmtree refuses a symlink, so a swapped-in link is never followed.
    with contextlib.suppress(OSError):
        if sys.version_info >= (3, 11):
            shutil.rmtree(name, dir_fd=root_fd)
        else:
            shutil.rmtree(root / name)


@contextlib.contextmanager
def _fresh_profile(root: Path, root_fd: int | None) -> Iterator[str]:
    if root_fd is None:
        profile = Path(tempfile.mkdtemp(prefix=_PROFILE_PREFIX, dir=root))
        try:
            yield profile.as_uri()
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        return
    name = _mkdtemp_at(root_fd)
    try:
        fd = _open_private_dir(name, dir_fd=root_fd)
    except BaseException:
        _remove_at(root_fd, root, name)
        raise
    try:
        yield _pinned_uri(fd) or (root / name).as_uri()
    finally:
        os.close(fd)
        _remove_at(root_fd, root, name)


# ---- AF_UNIX socket shim ----------------------------------------------------


def _needs_shim() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.close()
        return False
    except OSError:
        return True


def _shim_name() -> str:
    digest = hashlib.sha256(_SHIM_SOURCE.encode("utf-8")).hexdigest()[:16]
    return f"lo_socket_shim-{digest}.so"


def _read_private_file(dir_fd: int, name: str) -> bytes | None:
    """Contents of *name* when it is a regular file we own that no one else can write."""
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not _is_ours(st) or st.st_mode & 0o022:
            return None
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_private_file(dir_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


def _make_owner_only(dir_fd: int, name: str) -> None:
    fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _unlink_quietly(dir_fd: int, name: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(name, dir_fd=dir_fd)


def _compile_shim(source: Path, output: Path) -> None:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        raise FileNotFoundError("gcc is required to build the LibreOffice socket shim")
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-o", str(output), str(source), "-ldl"],
        check=True,
        capture_output=True,
    )


def _load_verified_shim(dir_fd: int, name: str) -> bytes | None:
    """The cached shim, only if it still matches the SHA-256 recorded when it was built."""
    data = _read_private_file(dir_fd, name)
    recorded = _read_private_file(dir_fd, name + ".sha256")
    if data is None or recorded is None:
        return None
    if hashlib.sha256(data).hexdigest() != recorded.decode("ascii", "replace").strip():
        # Never preload a shim that changed after it was built; rebuild it.
        _unlink_quietly(dir_fd, name)
        _unlink_quietly(dir_fd, name + ".sha256")
        return None
    return data


def _build_shim(shim_dir: Path, dir_fd: int, name: str) -> bytes:
    tag = secrets.token_hex(6)
    source, output, digest = f".{name}.{tag}.c", f".{name}.{tag}.tmp", f".{name}.{tag}.sum"
    try:
        _write_private_file(dir_fd, source, _SHIM_SOURCE.encode("utf-8"))
        _compile_shim(shim_dir / source, shim_dir / output)
        _make_owner_only(dir_fd, output)  # the compiler honours umask, which may be 002
        data = _read_private_file(dir_fd, output)
        if data is None:
            raise UnsafeLaunchError(f"Refusing LibreOffice launch: shim build in {shim_dir} was replaced")
        _write_private_file(dir_fd, digest, hashlib.sha256(data).hexdigest().encode("ascii") + b"\n")
        os.replace(output, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.replace(digest, name + ".sha256", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return data
    finally:
        for leftover in (source, output, digest):
            _unlink_quietly(dir_fd, leftover)


def _sealed_copy(data: bytes) -> int | None:
    """A memfd holding *data*, sealed against every further change (Linux)."""
    try:
        import fcntl

        seals = fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL
        fd = os.memfd_create("lo_socket_shim", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except (ImportError, AttributeError, OSError):
        return None
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def _verified_shim(root: Path, root_fd: int | None) -> Iterator[str]:
    """Yield an LD_PRELOAD value for the socket shim, SHA-256-checked first."""
    if root_fd is None:
        raise UnsafeLaunchError("Refusing LibreOffice launch: the socket shim needs POSIX dir_fd support")
    shim_dir = root / "shim"
    name = _shim_name()
    dir_fd = _open_private_dir("shim", dir_fd=root_fd)
    try:
        data = _load_verified_shim(dir_fd, name)
        if data is None:
            data = _build_shim(shim_dir, dir_fd, name)
    finally:
        os.close(dir_fd)
    digest = hashlib.sha256(data).hexdigest()

    memfd = _sealed_copy(data)
    if memfd is None:
        yield str(shim_dir / name)
        return
    try:
        pinned = f"/proc/{os.getpid()}/fd/{memfd}"
        try:
            loaded = Path(pinned).read_bytes()
        except OSError:
            loaded = None
        if loaded is None:
            yield str(shim_dir / name)
            return
        if hashlib.sha256(loaded).hexdigest() != digest:
            raise UnsafeLaunchError("Refusing LibreOffice launch: sealed shim copy failed SHA-256 check")
        yield pinned
    finally:
        os.close(memfd)


_SHIM_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int (*real_socket)(int, int, int);
static int (*real_socketpair)(int, int, int, int[2]);
static int (*real_listen)(int, int);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_close)(int);
static int (*real_read)(int, void *, size_t);

/* Per-FD bookkeeping (FDs >= 1024 are passed through unshimmed). */
static int is_shimmed[1024];
static int peer_of[1024];
static int wake_r[1024];            /* accept() blocks reading this */
static int wake_w[1024];            /* close()  writes to this      */
static int listener_fd = -1;        /* FD that received listen()    */

__attribute__((constructor))
static void init(void) {
    real_socket     = dlsym(RTLD_NEXT, "socket");
    real_socketpair = dlsym(RTLD_NEXT, "socketpair");
    real_listen     = dlsym(RTLD_NEXT, "listen");
    real_accept     = dlsym(RTLD_NEXT, "accept");
    real_close      = dlsym(RTLD_NEXT, "close");
    real_read       = dlsym(RTLD_NEXT, "read");
    for (int i = 0; i < 1024; i++) {
        peer_of[i] = -1;
        wake_r[i]  = -1;
        wake_w[i]  = -1;
    }
}

/* ---- socket ---------------------------------------------------------- */
int socket(int domain, int type, int protocol) {
    if (domain == AF_UNIX) {
        int fd = real_socket(domain, type, protocol);
        if (fd >= 0) return fd;
        /* socket(AF_UNIX) blocked – fall back to socketpair(). */
        int sv[2];
        if (real_socketpair(domain, type, protocol, sv) == 0) {
            if (sv[0] >= 0 && sv[0] < 1024) {
                is_shimmed[sv[0]] = 1;
                peer_of[sv[0]]    = sv[1];
                int wp[2];
                if (pipe(wp) == 0) {
                    wake_r[sv[0]] = wp[0];
                    wake_w[sv[0]] = wp[1];
                }
            }
            return sv[0];
        }
        errno = EPERM;
        return -1;
    }
    return real_socket(domain, type, protocol);
}

/* ---- listen ---------------------------------------------------------- */
int listen(int sockfd, int backlog) {
    if (sockfd >= 0 && sockfd < 1024 && is_shimmed[sockfd]) {
        listener_fd = sockfd;
        return 0;
    }
    return real_listen(sockfd, backlog);
}

/* ---- accept ---------------------------------------------------------- */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (sockfd >= 0 && sockfd < 1024 && is_shimmed[sockfd]) {
        /* Block until close() writes to the wake pipe. */
        if (wake_r[sockfd] >= 0) {
            char buf;
            real_read(wake_r[sockfd], &buf, 1);
        }
        errno = ECONNABORTED;
        return -1;
    }
    return real_accept(sockfd, addr, addrlen);
}

/* ---- close ----------------------------------------------------------- */
int close(int fd) {
    if (fd >= 0 && fd < 1024 && is_shimmed[fd]) {
        int was_listener = (fd == listener_fd);
        is_shimmed[fd] = 0;

        if (wake_w[fd] >= 0) {              /* unblock accept() */
            char c = 0;
            write(wake_w[fd], &c, 1);
            real_close(wake_w[fd]);
            wake_w[fd] = -1;
        }
        if (wake_r[fd] >= 0) { real_close(wake_r[fd]); wake_r[fd]  = -1; }
        if (peer_of[fd] >= 0) { real_close(peer_of[fd]); peer_of[fd] = -1; }

        if (was_listener)
            _exit(0);                        /* conversion done – exit */
    }
    return real_close(fd);
}
"""


if __name__ == "__main__":
    try:
        result = run_soffice(sys.argv[1:])
    except (UnsafeLaunchError, OSError) as exc:
        print(f"soffice.py: {exc}", file=sys.stderr)
        sys.exit(2)
    sys.exit(result.returncode)
