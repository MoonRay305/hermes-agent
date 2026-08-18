"""
Helper for running LibreOffice (soffice) in environments where AF_UNIX
sockets may be blocked (e.g., sandboxed VMs).  Detects the restriction
at runtime and applies an LD_PRELOAD shim if needed.

Usage:
    from office.soffice import run_soffice

    result = run_soffice(["--headless", "--convert-to", "pdf", "input.docx"])

Call soffice through run_soffice, not through subprocess with get_soffice_env():
the env dict carries the shim but names no user profile, and a non-root sandbox
cannot bootstrap the default one -- soffice aborts with "User installation could
not be completed" and converts nothing. get_soffice_env() stays public for the
callers that build their own argv (they must pass -env:UserInstallation too).
"""

import contextlib
import os
import socket
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname


def get_soffice_env() -> dict:
    env = os.environ.copy()
    env["SAL_USE_VCLPLUGIN"] = "svp"

    if _needs_shim():
        shim = _ensure_shim()
        env["LD_PRELOAD"] = str(shim)

    return env


_USER_INSTALLATION_OPTION = "-env:UserInstallation"
_USER_INSTALLATION_PREFIX = f"{_USER_INSTALLATION_OPTION}="


def _validate_user_installation_arg(arg: str) -> None:
    if not arg.startswith(_USER_INSTALLATION_PREFIX):
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: expected "
            f"{_USER_INSTALLATION_PREFIX}<absolute-file-URI>"
        )

    uri = arg[len(_USER_INSTALLATION_PREFIX) :]
    try:
        parsed = urlsplit(uri)
    except ValueError as exc:
        raise ValueError(
            f"Refusing unsafe LibreOffice user profile: invalid URI ({exc})"
        ) from exc

    if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: expected a local file URI"
        )

    decoded_path = unquote(parsed.path)
    if not decoded_path:
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: profile path is empty"
        )

    raw_profile_path = Path(url2pathname(decoded_path))
    if not raw_profile_path.is_absolute():
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: path must be absolute and non-root"
        )

    try:
        profile_path = raw_profile_path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            f"Refusing unsafe LibreOffice user profile: cannot resolve path ({exc})"
        ) from exc

    if profile_path.parent == profile_path:
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: path must be absolute and non-root"
        )


def run_soffice(args: Iterable[str], **kwargs) -> subprocess.CompletedProcess:
    args = list(args)
    profile_args = [
        str(arg) for arg in args if str(arg).startswith(_USER_INSTALLATION_OPTION)
    ]
    if len(profile_args) > 1:
        raise ValueError(
            "Refusing unsafe LibreOffice user profile: expected exactly one profile"
        )

    with contextlib.ExitStack() as stack:
        if profile_args:
            _validate_user_installation_arg(profile_args[0])
        else:
            profile = stack.enter_context(
                tempfile.TemporaryDirectory(
                    prefix="lo_profile_", ignore_cleanup_errors=True
                )
            )
            profile_arg = f"{_USER_INSTALLATION_PREFIX}{Path(profile).as_uri()}"
            _validate_user_installation_arg(profile_arg)
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
