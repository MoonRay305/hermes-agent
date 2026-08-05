"""End-to-end guards for ambient credentials in local terminal sessions."""

import os
import re
from pathlib import Path

from tools.environments.local import LocalEnvironment


_TARGETS = (
    "MS_GRAPH_TENANT_ID",
    "WEBHOOK_URL",
    "SESSION",
    "AUTH",
    "ORCHARD",
    "BLUEBIRD",
    "QUARTZ",
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


def test_fresh_terminal_and_snapshot_are_default_deny(tmp_path, monkeypatch):
    """The real login-shell bootstrap must persist only allowlisted names."""
    for index, name in enumerate(_TARGETS):
        monkeypatch.setenv(name, f"hostile-value-{index}")

    env = LocalEnvironment(cwd=str(tmp_path), timeout=10)
    try:
        assert _present_names(env) == set()
        assert not (set(_TARGETS) & _snapshot_names(env))

        runtime = env.execute(
            "[[ -n $PATH && -n $HOME ]] && printf 'runtime-ok\\n'"
        )
        assert runtime["returncode"] == 0, runtime
        assert runtime["output"].strip() == "runtime-ok"
        assert {"PATH", "HOME"} <= _snapshot_names(env)

        # Sanitizing a child must not mutate the gateway/parent environment.
        for index, name in enumerate(_TARGETS):
            assert os.environ[name] == f"hostile-value-{index}"
    finally:
        env.cleanup()


def test_unknown_export_is_not_persisted_to_next_spawn(tmp_path):
    env = LocalEnvironment(cwd=str(tmp_path), timeout=10)
    try:
        exported = env.execute("export SESSION=command-secret")
        assert exported["returncode"] == 0, exported

        next_spawn = env.execute(
            "[[ -v SESSION ]] && printf 'leaked\\n' || printf 'denied\\n'"
        )
        assert next_spawn["returncode"] == 0, next_spawn
        assert next_spawn["output"].strip() == "denied"
        assert "SESSION" not in _snapshot_names(env)
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
