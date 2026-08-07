"""Provider credentials re-hydrate in sanitized TUI/CLI Python children."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.environments.local import hermes_subprocess_env


@pytest.mark.parametrize(
    ("shape", "entry_import"),
    (
        ("slash_worker", "import cli"),
        ("cli.exec", "import hermes_cli.main"),
    ),
)
def test_sanitized_child_rehydrates_provider_from_profile_env(
    tmp_path: Path,
    shape: str,
    entry_import: str,
):
    """Hostile ambient auth is denied before import; profile .env wins inside."""
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    (hermes_home / ".env").write_text(
        "OPENAI_API_KEY=persisted-provider-value\n",
        encoding="utf-8",
    )

    parent_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "OPENAI_API_KEY": "hostile-ambient-provider-value",
    }
    if os.name == "nt":
        system_drive = Path(sys.executable).anchor.rstrip("\\/") or "C:"
        system_root = os.environ.get("SYSTEMROOT", f"{system_drive}\\Windows")
        parent_env.update({
            "SYSTEMDRIVE": system_drive,
            "SYSTEMROOT": system_root,
            "WINDIR": system_root,
            "USERPROFILE": str(tmp_path),
            "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
            "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        })
    with patch.dict(os.environ, parent_env, clear=True):
        child_env = hermes_subprocess_env(inherit_credentials=True)

    assert "OPENAI_API_KEY" not in child_env
    child_env["HERMES_HOME"] = str(hermes_home)

    code = (
        f"{entry_import}; import os; "
        f"print('REHYDRATED:{shape}:' + os.environ.get('OPENAI_API_KEY', 'missing'))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert f"REHYDRATED:{shape}:persisted-provider-value" in result.stdout
