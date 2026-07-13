"""Tests for the Linear -> Kanban bridge (dry-run stage).

Everything runs against injected issue fixtures and a temp kanban home — no
network, no live board. The load-bearing assertions:

  * reference-label classification is explicit and fail-loud (no label skips;
    unknown/conflicting agent labels are UNROUTABLE every tick);
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
    (home / "profiles" / "ghost").mkdir(parents=True)
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
    "routing_label_prefix": "agent:",
}


def _issue(ident, title, labels=None, state_type="unstarted", iid=None):
    return {
        "id": iid or f"uuid-{ident}",
        "identifier": ident,
        "title": title,
        "url": f"https://linear.app/x/issue/{ident}",
        "priority": 2,
        "state": {"name": "Todo", "type": state_type},
        "labels": {"nodes": [{"name": name} for name in (labels or [])]},
        "team": {"key": "BUI"},
    }


def test_classify_routing_labels(kanban_home):
    assert lb.classify_linear_labels(["agent:ghost"], BCFG) == (
        "mapped", "ghost", ["agent:ghost"]
    )
    # Matching is case-insensitive; non-routing labels are ignored.
    assert lb.classify_linear_labels(
        ["Bug", "Agent:Ghost"], BCFG
    ) == ("mapped", "ghost", ["Agent:Ghost"])
    # No routing reference means skip, not error.
    assert lb.classify_linear_labels([], BCFG) == ("unlabeled", None, [])
    assert lb.classify_linear_labels(["Bug"], BCFG) == ("unlabeled", None, [])
    # Unknown profile and conflicting references stay loudly unroutable.
    assert lb.classify_linear_labels(
        ["agent:no-such-agent"], BCFG
    )[0] == "unroutable"
    # A known pull lane is not a Hermes profile and is invalid for agent labels.
    assert lb.classify_linear_labels(["agent:fable"], BCFG)[0] == "unroutable"
    assert lb.classify_linear_labels(["agent:"], BCFG)[0] == "unroutable"
    assert lb.classify_linear_labels(["agentish:ghost"], BCFG) == (
        "unlabeled", None, []
    )
    assert lb.classify_linear_labels(
        ["agent:ghost", "agent:patch"], BCFG
    )[0] == "unroutable"


def test_tick_buckets_and_dedup(kanban_home):
    issues = [
        _issue("BUI-1", "bridge me", ["agent:ghost"]),
        _issue("BUI-2", "no routing label"),
        _issue("BUI-3", "ordinary label only", ["Bug"]),
        _issue("BUI-4", "unknown agent", ["agent:no-such-agent"]),
        _issue(
            "BUI-5", "already started", ["agent:ghost"],
            state_type="started",
        ),
        _issue("BUI-6", "conflicting routes", ["agent:ghost", "agent:patch"]),
    ]
    r1 = lb.run_bridge_tick(BCFG, issues=issues, now=int(time.time()))
    assert r1["ok"] is True
    assert [c["identifier"] for c in r1["would_create"]] == ["BUI-1"]
    assert r1["would_create"][0]["hermes_assignee"] == "ghost"
    assert r1["would_create"][0]["routing_label"] == "agent:ghost"
    assert r1["would_create"][0]["planned_idempotency_key"] == "linear:BUI-1"
    assert [u["identifier"] for u in r1["unroutable"]] == ["BUI-4", "BUI-6"]
    assert r1["skipped_unlabeled"] == 2
    assert r1["skipped_status"] == 1
    assert r1["already_seen"] == 0

    # Second tick with the same issues: BUI-1 deduped via the seen-store.
    r2 = lb.run_bridge_tick(BCFG, issues=issues, now=int(time.time()))
    assert r2["would_create"] == []
    assert r2["already_seen"] == 1
    # Unroutable stays loud every tick until fixed — it must not "dedup away".
    assert [u["identifier"] for u in r2["unroutable"]] == ["BUI-4", "BUI-6"]


def test_linear_query_reads_labels_not_assignee():
    assert "labels { nodes { name } }" in lb._ISSUES_QUERY
    assert "assignee" not in lb._ISSUES_QUERY.casefold()


def test_dedup_uses_linear_issue_id(kanban_home):
    first = _issue(
        "BUI-10", "first title", ["agent:ghost"], iid="linear-uuid-stable"
    )
    renamed = _issue(
        "BUI-999", "renamed issue", ["agent:ghost"], iid="linear-uuid-stable"
    )
    r1 = lb.run_bridge_tick(BCFG, issues=[first], now=1)
    assert [card["identifier"] for card in r1["would_create"]] == ["BUI-10"]
    r2 = lb.run_bridge_tick(BCFG, issues=[renamed], now=2)
    assert r2["would_create"] == []
    assert r2["already_seen"] == 1


def test_dry_run_creates_no_kanban_cards(kanban_home):
    conn = kb.connect(board="default")
    before = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    conn.close()

    report = lb.run_bridge_tick(
        BCFG,
        issues=[_issue("BUI-9", "would-be card", ["agent:ghost"])],
    )
    assert report["would_create"][0]["hermes_assignee"] == "ghost"

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
    report = lb.run_bridge_tick(
        cfg, issues=[_issue("BUI-1", "x", ["agent:ghost"])]
    )
    assert report["ok"] is False
    assert "not implemented" in report["error"]
    assert report["would_create"] == []
