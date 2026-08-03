"""End-to-end guards for ambient credentials in local terminal sessions."""

import os
import re
from pathlib import Path

from tools.environments.local import LocalEnvironment


_TARGETS = (
    "GH_TOKEN",
    "GITHUB_REVIEWER_PAT",
    "MS_GRAPH_CLIENT_SECRET",
)


def _present_names(env: LocalEnvironment) -> set[str]:
    command = "\n".join(
        f"[[ -v {name} ]] && printf '%s\\n' {name} || true"
        for name in _TARGETS
    )
    result = env.execute(command)
    assert result["returncode"] == 0, result
    return set(result["output"].splitlines())


def _snapshot_names(env: LocalEnvironment) -> set[str]:
    text = Path(env._snapshot_path).read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r"(?m)^declare -x ([A-Za-z_][A-Za-z0-9_]*)=", text))


def test_fresh_terminal_and_snapshot_exclude_ambient_credentials(tmp_path, monkeypatch):
    """The real login-shell bootstrap must not persist ambient credentials."""
    monkeypatch.setenv("GH_TOKEN", "ambient-gateway-token")
    monkeypatch.setenv("GITHUB_REVIEWER_PAT", "scoped-reviewer-token")
    monkeypatch.setenv("MS_GRAPH_CLIENT_SECRET", "graph-client-secret")

    env = LocalEnvironment(cwd=str(tmp_path), timeout=10)
    try:
        assert _present_names(env) == set()
        assert not (set(_TARGETS) & _snapshot_names(env))

        # Sanitizing a child must not mutate the gateway/parent environment.
        assert os.environ["GH_TOKEN"] == "ambient-gateway-token"
        assert os.environ["GITHUB_REVIEWER_PAT"] == "scoped-reviewer-token"
        assert os.environ["MS_GRAPH_CLIENT_SECRET"] == "graph-client-secret"
    finally:
        env.cleanup()


def test_inline_github_binding_is_command_scoped_and_not_snapshotted(tmp_path, monkeypatch):
    """Explicit one-command GH_TOKEN binding still works without persistence."""
    monkeypatch.delenv("GH_TOKEN", raising=False)

    env = LocalEnvironment(cwd=str(tmp_path), timeout=10)
    try:
        result = env.execute(
            "GH_TOKEN=explicit-reviewer-token "
            "bash -c 'test \"$GH_TOKEN\" = explicit-reviewer-token'"
        )
        assert result["returncode"] == 0, result

        assert _present_names(env) == set()
        assert "GH_TOKEN" not in _snapshot_names(env)
    finally:
        env.cleanup()
