"""Linear -> Kanban bridge (DRY-RUN stage).

Mirrors Linear issues that are assigned to a MAPPED Hermes agent onto the
kanban board, so project work assigned in Linear flows to the fleet without a
human re-keying cards. This module is the polling/classification half; it is
called from the gateway's embedded dispatcher tick loop
(``gateway/kanban_watchers.py``), which means:

  * Only the dispatcher-LOCK-HOLDING gateway ever polls Linear — the exact
    same single-poller gating kanban dispatch itself relies on. A standby
    that takes over the lock starts polling on its next tick.
  * A bridge failure must never break dispatch: the caller wraps the tick in
    a broad try/except, and everything here is best-effort with loud logs.

THIS STAGE IS DRY-RUN BY CONSTRUCTION. The module reports the kanban cards it
WOULD create and creates none: there is intentionally NO import of, or call
to, any task-creation API anywhere in this file (grep for ``create_task`` —
absent). Setting ``kanban.linear_bridge.dry_run`` to false does not unlock an
action path; it logs a refusal, because proving the mapping correct comes
before letting it act. The create path arrives in a later stage, and will use
``idempotency_key="linear:<identifier>"`` for DB-level dedup on top of the
seen-store here.

Assignee routing follows the PR #4 validation pattern exactly: a Linear
assignee resolves to ``mapped`` (bridge it), ``human`` (intentionally not
bridged), ``unassigned``, or ``UNROUTABLE`` — and unroutable is FAIL-LOUD
(warning log + report bucket), never a silent drop and never a guess. Even a
*mapped* entry whose Hermes-side target fails ``kanban_db.classify_assignee``
(neither a profile nor a known pull lane) is demoted to unroutable, so a typo
in the map itself cannot silently strand work.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("gateway.linear_bridge")

LINEAR_GRAPHQL_URL = "https://api.linear.app/graphql"

# GraphQL: read-only query for issues in the watched teams. Deliberately the
# ONLY Linear operation in this module — the bridge never mutates Linear.
_ISSUES_QUERY = """
query BridgeIssues($teamKeys: [String!]!, $after: String) {
  issues(
    first: 50
    after: $after
    filter: { team: { key: { in: $teamKeys } } }
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      identifier
      title
      url
      priority
      state { name type }
      assignee { name email }
      team { key }
    }
  }
}
"""


# ---------------------------------------------------------------------------
# Config / key resolution
# ---------------------------------------------------------------------------

def bridge_config() -> dict:
    """Return the ``kanban.linear_bridge`` config dict (defaults merged)."""
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
        kcfg = cfg.get("kanban", {}) if isinstance(cfg, dict) else {}
        bcfg = kcfg.get("linear_bridge", {})
        return bcfg if isinstance(bcfg, dict) else {}
    except Exception:
        return {}


def resolve_linear_api_key(bcfg: Optional[dict] = None) -> "tuple[Optional[str], str]":
    """Resolve the Linear API key as an INTENTIONAL dispatcher-role grant.

    Resolution order:
      1. the process environment (``api_key_env``, default LINEAR_API_KEY) —
         covers Doppler-injected service env;
      2. the shared ``~/.hermes/.env`` secrets store via
         ``hermes_cli.config.load_env()`` — covers EVERY gateway on the host,
         so a standby that wins the dispatcher lock after a failover can
         still poll. This is the fix for the survey finding that Linear
         access only worked because one specific gateway's process happened
         to inherit the key.

    Returns ``(key, source)`` where source is ``"env"`` / ``"hermes-env"`` /
    ``"missing"``. The key VALUE is never logged by any caller in this
    module; only the source label is.
    """
    bcfg = bcfg if bcfg is not None else bridge_config()
    env_name = str(bcfg.get("api_key_env") or "LINEAR_API_KEY")
    key = (os.environ.get(env_name) or "").strip()
    if key:
        return key, "env"
    try:
        from hermes_cli.config import load_env

        key = (load_env().get(env_name) or "").strip()
        if key:
            return key, "hermes-env"
    except Exception:
        logger.debug("linear bridge: ~/.hermes/.env resolution failed", exc_info=True)
    return None, "missing"


# ---------------------------------------------------------------------------
# Assignee classification (PR #4 pattern, applied to Linear users)
# ---------------------------------------------------------------------------

def classify_linear_assignee(
    assignee_email: Optional[str],
    assignee_name: Optional[str],
    bcfg: dict,
) -> "tuple[str, Optional[str]]":
    """Classify a Linear issue's assignee for bridging.

    Returns ``(disposition, hermes_assignee)`` with disposition one of:
      ``"mapped"``      — bridge it; ``hermes_assignee`` is the kanban
                          assignee (validated: profile or known pull lane).
      ``"human"``       — a human's issue; intentionally NOT bridged.
      ``"unassigned"``  — no assignee; nothing to route yet.
      ``"unroutable"``  — assignee is in neither the map nor the human list,
                          OR the map's own target fails Hermes-side
                          validation. FAIL-LOUD; never silently dropped.
    """
    email = (assignee_email or "").strip().lower()
    name = (assignee_name or "").strip().lower()
    if not email and not name:
        return "unassigned", None

    # Match config keys against BOTH the email and the display name: emails
    # are the stable primary key for humans, but Linear OAuth-app users
    # (agents) carry machine-generated emails, so their natural key is the
    # display name. Both are workspace-controlled identities.
    idents = {v for v in (email, name) if v}

    humans = {str(h).strip().lower() for h in (bcfg.get("human_assignees") or [])}
    if idents & humans:
        return "human", None

    amap = bcfg.get("assignee_map") or {}
    target = None
    for k, v in amap.items():
        if str(k).strip().lower() in idents:
            target = str(v).strip()
            break
    if target is None:
        return "unroutable", None

    # A map entry is only as good as its Hermes-side target: validate it with
    # the same classifier the dispatcher uses (PR #4). A typo'd target must
    # surface as unroutable here, not strand a card later.
    try:
        from hermes_cli.kanban_db import classify_assignee

        if classify_assignee(target) == "unroutable":
            return "unroutable", None
    except Exception:
        logger.debug("linear bridge: hermes-side target validation unavailable", exc_info=True)
    return "mapped", target


# ---------------------------------------------------------------------------
# Seen-store (dedup on Linear issue id; atomic like the dispatcher heartbeat)
# ---------------------------------------------------------------------------

def seen_store_path() -> Path:
    from hermes_cli.kanban_db import kanban_home

    return kanban_home() / "kanban" / ".linear_bridge_seen.json"


def load_seen() -> "dict[str, dict]":
    try:
        raw = seen_store_path().read_text(encoding="utf-8")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        logger.warning("linear bridge: seen-store unreadable; treating as empty", exc_info=True)
        return {}


def save_seen(seen: "dict[str, dict]") -> None:
    """Atomic write (tmp + os.replace) so a reader never sees a torn file."""
    try:
        path = seen_store_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps(seen, indent=0, sort_keys=True), encoding="utf-8")
        os.replace(str(tmp), str(path))
    except Exception:
        logger.warning("linear bridge: seen-store write failed", exc_info=True)


# ---------------------------------------------------------------------------
# Linear fetch (read-only)
# ---------------------------------------------------------------------------

def fetch_issues(api_key: str, team_keys: "list[str]") -> "list[dict]":
    """Fetch issues for the watched teams via GraphQL. READ-ONLY, paginated."""
    out: list[dict] = []
    after: Optional[str] = None
    for _page in range(20):  # hard cap: 1000 issues/poll
        payload = json.dumps({
            "query": _ISSUES_QUERY,
            "variables": {"teamKeys": list(team_keys), "after": after},
        }).encode("utf-8")
        req = urllib.request.Request(
            LINEAR_GRAPHQL_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": api_key,
                "User-Agent": "hermes-linear-bridge",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        if body.get("errors"):
            raise RuntimeError(f"Linear GraphQL errors: {body['errors']!r}")
        conn = (body.get("data") or {}).get("issues") or {}
        out.extend(conn.get("nodes") or [])
        page = conn.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            break
        after = page.get("endCursor")
    return out


# ---------------------------------------------------------------------------
# The tick (DRY-RUN ONLY in this stage)
# ---------------------------------------------------------------------------

def run_bridge_tick(
    bcfg: Optional[dict] = None,
    *,
    issues: "Optional[list[dict]]" = None,
    now: Optional[int] = None,
) -> dict:
    """Run one bridge poll and return a structured report. CREATES NOTHING.

    ``issues`` may be injected (tests / offline dry-runs against pre-fetched
    Linear data); otherwise they are fetched live with the resolved key.

    Report shape:
      {"ok": bool, "would_create": [...], "unroutable": [...],
       "skipped_human": int, "skipped_unassigned": int,
       "skipped_status": int, "already_seen": int, "error": str|None}
    """
    bcfg = bcfg if bcfg is not None else bridge_config()
    now = int(now if now is not None else time.time())
    report: dict[str, Any] = {
        "ok": True, "would_create": [], "unroutable": [],
        "skipped_human": 0, "skipped_unassigned": 0,
        "skipped_status": 0, "already_seen": 0, "error": None,
    }

    if not bool(bcfg.get("dry_run", True)):
        # This stage implements ONLY dry-run. Refuse loudly rather than act:
        # there is no action path in this module to fall through to.
        logger.critical(
            "linear bridge: dry_run=false requested but this build implements "
            "DRY-RUN ONLY — no card is created. Leave dry_run=true until the "
            "create stage ships."
        )
        report["ok"] = False
        report["error"] = "non-dry-run not implemented in this stage"
        return report

    if issues is None:
        key, source = resolve_linear_api_key(bcfg)
        if not key:
            # FAIL LOUD: an armed bridge with no key must be visible — this
            # is exactly the silent-failover-break the key-resolution order
            # exists to prevent.
            logger.critical(
                "linear bridge: enabled but %s is set in neither the process "
                "env nor ~/.hermes/.env on this gateway — polling DISABLED "
                "here. Grant the key to the dispatcher role on every gateway "
                "host so failover cannot silently stop the bridge.",
                str(bcfg.get("api_key_env") or "LINEAR_API_KEY"),
            )
            report["ok"] = False
            report["error"] = "linear api key missing"
            return report
        logger.info("linear bridge: polling Linear (key source: %s)", source)
        try:
            issues = fetch_issues(key, list(bcfg.get("team_keys") or ["BUI"]))
        except Exception as exc:
            logger.warning("linear bridge: Linear fetch failed: %s", exc)
            report["ok"] = False
            report["error"] = f"fetch failed: {exc}"
            return report

    wanted_status = {str(s) for s in (bcfg.get("status_types") or ["unstarted"])}
    seen = load_seen()
    new_seen_entries: dict[str, dict] = {}

    for issue in issues:
        state_type = ((issue.get("state") or {}).get("type") or "").strip()
        if state_type not in wanted_status:
            report["skipped_status"] += 1
            continue
        assignee = issue.get("assignee") or {}
        disposition, hermes_assignee = classify_linear_assignee(
            assignee.get("email"), assignee.get("name"), bcfg,
        )
        if disposition == "unassigned":
            report["skipped_unassigned"] += 1
            continue
        if disposition == "human":
            report["skipped_human"] += 1
            continue
        ident = str(issue.get("identifier") or issue.get("id") or "?")
        if disposition == "unroutable":
            entry = {
                "identifier": ident,
                "title": str(issue.get("title") or "")[:80],
                "linear_assignee": assignee.get("email") or assignee.get("name"),
            }
            report["unroutable"].append(entry)
            logger.warning(
                "linear bridge UNROUTABLE: %s (%r) is assigned to %r — in "
                "neither kanban.linear_bridge.assignee_map nor "
                "human_assignees. It will NOT be bridged until mapped. "
                "(fail-loud per the PR #4 assignee-validation rule)",
                ident, entry["title"], entry["linear_assignee"],
            )
            continue
        # mapped
        issue_id = str(issue.get("id") or ident)
        if issue_id in seen:
            report["already_seen"] += 1
            continue
        card = {
            "identifier": ident,
            "linear_id": issue_id,
            "title": str(issue.get("title") or "")[:200],
            "url": issue.get("url"),
            "hermes_assignee": hermes_assignee,
            "linear_assignee": assignee.get("email") or assignee.get("name"),
            "state": (issue.get("state") or {}).get("name"),
            "priority": issue.get("priority"),
            # The future create stage keys DB-level dedup on this:
            "planned_idempotency_key": f"linear:{ident}",
        }
        report["would_create"].append(card)
        new_seen_entries[issue_id] = {"identifier": ident, "first_seen": now, "dry_run": True}
        logger.info(
            "linear bridge DRY-RUN: WOULD CREATE Kanban card: %s %r -> "
            "assignee=%s (idempotency_key=%s). No card was created.",
            ident, card["title"][:60], hermes_assignee, card["planned_idempotency_key"],
        )

    if new_seen_entries:
        seen.update(new_seen_entries)
        save_seen(seen)
    return report
