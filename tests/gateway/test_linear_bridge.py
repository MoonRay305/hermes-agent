"""Tests for the Linear -> Kanban bridge (dry-run stage).

Everything runs against injected issue fixtures and a temp kanban home — no
network, no live board. The load-bearing assertions:

  * assignee classification follows the PR #4 fail-loud pattern (unknown ->
    UNROUTABLE, never silently dropped; a typo'd map target is unroutable);
  * dedup on Linear issue id across ticks;
  * the dry-run tick NEVER writes a kanban card (board row count unchanged),
    and the module contains no task-creation call at all;
  * key resolution: process env, then ~/.hermes/.env, else fail loud;
  * dry_run=false refuses (this stage has no action path to fall through to).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from gateway import linear_bridge as lb
from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


BCFG = {
    "enabled": True,
    "dry_run": True,
    "poll_interval_seconds": 300,
    "team_keys": ["BUI"],
    "status_types": ["unstarted"],
    "api_key_env": "LINEAR_API_KEY",
    "assignee_map": {
        "fable@2rook.ai": "fable",          # valid pull lane
        "typo@2rook.ai": "no-such-agent",   # map target itself invalid
    },
    "human_assignees": ["lray24@gmail.com"],
}


def _issue(ident, title, email, name=None, state_type="unstarted", iid=None):
    return {
        "id": iid or f"uuid-{ident}",
        "identifier": ident,
        "title": title,
        "url": f"https://linear.app/x/issue/{ident}",
        "priority": 2,
        "state": {"name": "Todo", "type": state_type},
        "assignee": ({"email": email, "name": name or email} if (email or name) else None),
        "team": {"key": "BUI"},
    }


def test_classify_dispositions(kanban_home):
    # mapped -> validated hermes assignee (fable is a KNOWN_PULL_LANES entry)
    assert lb.classify_linear_assignee("fable@2rook.ai", "Fable", BCFG) == ("mapped", "fable")
    assert lb.classify_linear_assignee("FABLE@2rook.ai", None, BCFG) == ("mapped", "fable")
    # human -> intentionally not bridged
    assert lb.classify_linear_assignee("lray24@gmail.com", "Landon Ray", BCFG) == ("human", None)
    # unassigned
    assert lb.classify_linear_assignee(None, None, BCFG) == ("unassigned", None)
    assert lb.classify_linear_assignee("", "  ", BCFG) == ("unassigned", None)
    # unknown -> UNROUTABLE (fail loud), never a guess
    assert lb.classify_linear_assignee("codex@oauthapp.linear.app", "Codex", BCFG)[0] == "unroutable"
    # a map entry whose TARGET fails Hermes-side validation is unroutable too
    assert lb.classify_linear_assignee("typo@2rook.ai", None, BCFG)[0] == "unroutable"
    # display-name keys work too (OAuth-app agent users have machine emails)
    cfg = dict(BCFG, assignee_map={"fable agent": "fable"})
    assert lb.classify_linear_assignee("weird@oauthapp.linear.app", "Fable Agent", cfg) == ("mapped", "fable")
    # ...and a name-keyed human
    cfg2 = dict(BCFG, human_assignees=["landon ray"])
    assert lb.classify_linear_assignee(None, "Landon Ray", cfg2) == ("human", None)


def test_tick_buckets_and_dedup(kanban_home):
    issues = [
        _issue("BUI-1", "bridge me", "fable@2rook.ai"),
        _issue("BUI-2", "human task", "lray24@gmail.com"),
        _issue("BUI-3", "no assignee", None),
        _issue("BUI-4", "unknown agent", "codex@oauthapp.linear.app"),
        _issue("BUI-5", "already started", "fable@2rook.ai", state_type="started"),
    ]
    r1 = lb.run_bridge_tick(BCFG, issues=issues, now=int(time.time()))
    assert r1["ok"] is True
    assert [c["identifier"] for c in r1["would_create"]] == ["BUI-1"]
    assert r1["would_create"][0]["hermes_assignee"] == "fable"
    assert r1["would_create"][0]["planned_idempotency_key"] == "linear:BUI-1"
    assert [u["identifier"] for u in r1["unroutable"]] == ["BUI-4"]
    assert r1["skipped_human"] == 1
    assert r1["skipped_unassigned"] == 1
    assert r1["skipped_status"] == 1
    assert r1["already_seen"] == 0

    # Second tick with the same issues: BUI-1 deduped via the seen-store.
    r2 = lb.run_bridge_tick(BCFG, issues=issues, now=int(time.time()))
    assert r2["would_create"] == []
    assert r2["already_seen"] == 1
    # Unroutable stays loud every tick until fixed — it must not "dedup away".
    assert [u["identifier"] for u in r2["unroutable"]] == ["BUI-4"]


def test_dry_run_creates_no_kanban_cards(kanban_home):
    conn = kb.connect(board="default")
    before = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    conn.close()

    lb.run_bridge_tick(BCFG, issues=[_issue("BUI-9", "would-be card", "fable@2rook.ai")])

    conn = kb.connect(board="default")
    after = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    conn.close()
    assert before == after == 0, "dry-run must not create kanban cards"

    # Structural guarantee: no task-creation call exists in the module.
    src = Path(lb.__file__).read_text(encoding="utf-8")
    body = "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith(("#", '"', "'"))
    )
    assert "create_task" not in body.replace("``create_task``", "")


def test_key_resolution_order(kanban_home, monkeypatch, tmp_path):
    # 1) process env wins
    monkeypatch.setenv("LINEAR_API_KEY", "from-process-env")
    assert lb.resolve_linear_api_key(BCFG) == ("from-process-env", "env")
    # 2) falls back to the shared ~/.hermes/.env (any lock-winning gateway)
    monkeypatch.delenv("LINEAR_API_KEY", raising=False)
    monkeypatch.setattr(
        "hermes_cli.config.load_env", lambda: {"LINEAR_API_KEY": "from-hermes-env"}
    )
    assert lb.resolve_linear_api_key(BCFG) == ("from-hermes-env", "hermes-env")
    # 3) missing everywhere -> fail loud at the tick
    monkeypatch.setattr("hermes_cli.config.load_env", lambda: {})
    assert lb.resolve_linear_api_key(BCFG) == (None, "missing")
    report = lb.run_bridge_tick(BCFG)  # no injected issues -> needs a key
    assert report["ok"] is False
    assert "key missing" in report["error"]


def test_non_dry_run_refuses(kanban_home):
    cfg = dict(BCFG, dry_run=False)
    report = lb.run_bridge_tick(cfg, issues=[_issue("BUI-1", "x", "fable@2rook.ai")])
    assert report["ok"] is False
    assert "not implemented" in report["error"]
    assert report["would_create"] == []
