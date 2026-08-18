"""
Helper for running LibreOffice (soffice) in environments where AF_UNIX
sockets may be blocked (e.g., sandboxed VMs).  Detects the restriction
at runtime and applies an LD_PRELOAD shim if needed.

Usage:
    from office.soffice import run_soffice

    result = run_soffice(["--headless", "--convert-to", "pdf", "input.docx"])

Call soffice through run_soffice, which creates the LibreOffice profile inside
the guarded API. Callers that need to reuse a profile receive an opaque profile
identifier from managed_soffice_profile(); they never provide a filesystem path.
"""

import contextlib
import os
import socket
import subprocess
import tempfile
import uuid
from collections.abc import Iterable
from pathlib import Path


def get_soffice_env() -> dict:
    env = os.environ.copy()
    for key in tuple(env):
        if key.casefold() == "userinstallation":
            env.pop(key, None)
    env["SAL_USE_VCLPLUGIN"] = "svp"

    if _needs_shim():
        shim = _ensure_shim()
        env["LD_PRELOAD"] = str(shim)

    return env


_USER_INSTALLATION_OPTION = "-env:UserInstallation"
_USER_INSTALLATION_OPTIONS = (
    _USER_INSTALLATION_OPTION,
    "/env:UserInstallation",
)
_USER_INSTALLATION_PREFIX = f"{_USER_INSTALLATION_OPTION}="
_APPROVED_PROFILE_ROOT = Path("/var/tmp/lo-profiles")
_MANAGED_PROFILES: dict[str, Path] = {}


def _is_user_installation_arg(arg: str) -> bool:
    return any(
        arg == option or arg.startswith(f"{option}=")
        for option in _USER_INSTALLATION_OPTIONS
    )


def _ensure_approved_profile_root() -> Path:
    try:
        if _APPROVED_PROFILE_ROOT.is_symlink():
            raise ValueError("approved profile root must not be a symlink")
        _APPROVED_PROFILE_ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
        if _APPROVED_PROFILE_ROOT.is_symlink():
            raise ValueError("approved profile root must not be a symlink")
        if hasattr(os, "geteuid"):
            owner_uid = _APPROVED_PROFILE_ROOT.stat().st_uid
            if owner_uid != os.geteuid():
                raise ValueError("approved profile root must be owned by the current user")
            _APPROVED_PROFILE_ROOT.chmod(0o700)
        return _APPROVED_PROFILE_ROOT.resolve(strict=True)
    except ValueError as exc:
        raise ValueError(
            f"Refusing unsafe LibreOffice user profile: {exc}"
        ) from exc
    except OSError as exc:
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: "
            f"cannot prepare approved root ({exc})"
        ) from exc


@contextlib.contextmanager
def managed_soffice_profile():
    approved_root = _ensure_approved_profile_root()
    with tempfile.TemporaryDirectory(
        prefix="lo_profile_",
        dir=approved_root,
        ignore_cleanup_errors=True,
    ) as profile_directory:
        profile_id = uuid.uuid4().hex
        _MANAGED_PROFILES[profile_id] = Path(profile_directory)
        try:
            yield profile_id
        finally:
            _MANAGED_PROFILES.pop(profile_id, None)


def _managed_profile_path(profile_id: str) -> Path:
    try:
        return _MANAGED_PROFILES[profile_id]
    except (KeyError, TypeError) as exc:
        raise ValueError("Unknown or expired LibreOffice profile identifier") from exc


def _managed_profile_entry(profile_id: str, relative_path: str | Path) -> Path:
    profile = _managed_profile_path(profile_id)
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("LibreOffice profile entry must be a relative path")
    entry = (profile / relative).resolve(strict=False)
    try:
        entry.relative_to(profile.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("LibreOffice profile entry escapes the managed profile") from exc
    return entry


def soffice_profile_entry_exists(profile_id: str, relative_path: str | Path) -> bool:
    return _managed_profile_entry(profile_id, relative_path).exists()


def write_soffice_profile_file(
    profile_id: str,
    relative_path: str | Path,
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    destination = _managed_profile_entry(profile_id, relative_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding=encoding)


def run_soffice(
    args: Iterable[str],
    *,
    profile_id: str | None = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    args = list(args)
    profile_args = [str(arg) for arg in args if _is_user_installation_arg(str(arg))]
    if profile_args:
        raise ValueError(
            "Refusing caller-supplied LibreOffice user profile; use an opaque profile identifier"
        )

    with contextlib.ExitStack() as stack:
        if profile_id is None:
            profile_id = stack.enter_context(managed_soffice_profile())
        profile = _managed_profile_path(profile_id)
        profile_arg = f"{_USER_INSTALLATION_PREFIX}{profile.as_uri()}"
        args = [profile_arg] + args
        return subprocess.run(["soffice"] + args, env=get_soffice_env(), **kwargs)


_SHIM_SO = Path(tempfile.gettempdir()) / "lo_socket_shim.so"


def _needs_shim() -> bool:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.close()
        return False
    except OSError:
        return True


def _ensure_shim() -> Path:
    if _SHIM_SO.exists():
        return _SHIM_SO

    src = Path(tempfile.gettempdir()) / "lo_socket_shim.c"
    src.write_text(_SHIM_SOURCE, encoding="utf-8")
    subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", str(_SHIM_SO), str(src), "-ldl"],
        check=True,
        capture_output=True,
    )
    src.unlink()
    return _SHIM_SO


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
    import sys

    result = run_soffice(sys.argv[1:])
    sys.exit(result.returncode)
