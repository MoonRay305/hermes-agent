"""Structured audit records for approval-gate bypasses.

The dangerous-command approval gate has several paths that return
``approved`` WITHOUT ever showing the user a prompt: ``approvals.mode: off``,
process-scoped ``--yolo`` and the session ``/yolo`` toggle, a
``command_allowlist`` match (exact command text/glob or detector pattern
key), ``approvals.cron_mode: approve``, the historical non-interactive
auto-approve, a smart-approval LLM grant, and a Tirith fail-open. Before
this module existed those paths were indistinguishable from a clean
command: no log line, no hook, no artifact.

This module gives every such path one chokepoint: :func:`record_bypass`
builds a structured record, redacts it, appends it to
``<hermes_home>/logs/approval_bypass.jsonl``, and fires the
``approval_bypassed`` plugin hook (a sibling of ``pre_approval_request`` /
``post_approval_response``) so downstream consumers see bypasses the same
way they see grants and denials.

Emission policy (kept here so call sites cannot drift): a record is written
only when the command was actually FLAGGED — detector findings are
non-empty, Tirith reported findings, or Tirith failed open (scan could not
run, so safety is unknown). A clean command approved under yolo behaves
exactly like a clean command in manual mode — no prompt either way — so it
produces no record. Blind spot, stated plainly: a dangerous command that NO
detector matches emits nothing here; that is the same blind spot the
approval gate itself has, and ``hermes approvals coverage`` exists to
measure it.

Secrets: the command string is passed through
``agent.redact.redact_sensitive_text(..., force=True)`` before the record
is built. ``force=True`` deliberately ignores ``security.redact_secrets:
false`` — an audit artifact must never contain a live credential regardless
of the user's display preference.

Reason vocabulary (the ``reason`` field):

- ``mode_off``                      — ``approvals.mode: off`` in config
- ``process_yolo``                  — ``--yolo`` / ``HERMES_YOLO_MODE``
- ``session_yolo``                  — gateway ``/yolo`` toggle
- ``exact_command_allowlist``       — command text matched a
                                      ``command_allowlist`` entry/glob
- ``pattern_key_allowlist``         — every flagged detector key was already
                                      approved (permanent config entry or an
                                      earlier session-scoped grant)
- ``cron_approve_mode``             — ``approvals.cron_mode: approve``
- ``non_interactive_auto_approve``  — historical fail-open: no CLI, no
                                      gateway, not cron
- ``smart_approval``                — auxiliary-LLM grant, no human prompt
- ``tirith_fail_open``              — Tirith could not run and
                                      ``security.tirith_fail_open`` allowed
                                      the command through unscanned

Never raises: audit failures are logged and swallowed — observability must
not break the approval flow it observes.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Bound the stored command so one giant execute_code script cannot bloat the
# audit log. Redaction runs BEFORE truncation so a secret can never straddle
# the cut and survive it.
_MAX_COMMAND_LEN = 4000

_BYPASS_LOG_NAME = "approval_bypass.jsonl"

_write_lock = threading.Lock()

# Once-per-process dedup for records whose ONLY content is "tirith could not
# scan" (no detector findings). On a host where the tirith binary is absent,
# every command fails open — one record per (reason, summary) captures the
# state without turning the audit log into a firehose. Records for FLAGGED
# commands are never deduplicated.
_once_only_seen: set = set()


def bypass_log_path() -> Path:
    """Return the profile-aware path of the bypass audit log."""
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "logs" / _BYPASS_LOG_NAME


def _profile_name_for_home(home: Path) -> str:
    """Derive the profile name from a resolved Hermes home path.

    Mirrors the ``hermes_cli.profiles`` layout: the platform default home is
    the ``default`` profile and named profiles live at
    ``<default_home>/profiles/<name>/``. Falls back to the directory name so
    an unconventional ``HERMES_HOME`` still yields something identifying.
    """
    try:
        if home.parent.name == "profiles":
            return home.name
        return "default"
    except Exception:
        return "unknown"


def _redact(text: str) -> str:
    """Redact secrets from *text*; fail closed to a placeholder.

    ``force=True`` because this is a safety-boundary artifact: the user's
    ``security.redact_secrets: false`` display preference must not put live
    credentials into an audit file. If the redactor itself cannot be
    imported or crashes, the raw text is NOT written — a lost command string
    is recoverable from session history, a leaked secret is not.
    """
    try:
        from agent.redact import redact_sensitive_text

        return redact_sensitive_text(text or "", force=True)
    except Exception:
        return "<unredactable: redaction module unavailable>"


def build_bypass_record(
    *,
    reason: str,
    command: str,
    findings: list | None,
    session_key: str,
    surface: str,
    env_type: str = "",
    detail: dict | None = None,
    tirith: dict | None = None,
) -> dict:
    """Build (but do not write) a structured bypass record.

    ``findings`` is a list of ``(pattern_key, description)`` pairs from the
    dangerous-command detectors. ``tirith`` is the raw result dict from
    ``tools.tirith_security.check_command_security`` when that scan ran in
    the calling flow (it is summarized, never embedded verbatim).
    """
    redacted_command = _redact(command)[:_MAX_COMMAND_LEN]
    finding_dicts = [
        {"pattern_key": key, "description": desc}
        for key, desc in (findings or [])
    ]

    # detail can carry command-shaped text too (a matched command_allowlist
    # entry is command text the user wrote into config) — redact every
    # string leaf so no field of the record can hold a live secret.
    def _redact_detail(value):
        if isinstance(value, str):
            return _redact(value)[:_MAX_COMMAND_LEN]
        if isinstance(value, dict):
            return {k: _redact_detail(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_redact_detail(v) for v in value]
        return value

    tirith_summary = None
    if tirith is not None:
        tirith_summary = {
            "action": tirith.get("action", ""),
            "summary": _redact(str(tirith.get("summary", "")))[:500],
            "fail_open": bool(tirith.get("fail_open", False)),
            "findings_count": len(tirith.get("findings") or []),
        }

    try:
        from hermes_constants import get_hermes_home

        profile = _profile_name_for_home(get_hermes_home())
    except Exception:
        profile = "unknown"

    now = time.time()
    return {
        "schema": 1,
        "event": "approval_bypass",
        "ts": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "epoch": round(now, 3),
        "reason": reason,
        "detail": _redact_detail(detail or {}),
        "profile": profile,
        "session_key": session_key or "",
        "surface": surface,
        "env_type": env_type or "",
        "command": redacted_command,
        "findings": finding_dicts,
        "tirith": tirith_summary,
    }


def _append_record(record: dict) -> None:
    """Append *record* to the JSONL audit log. Best-effort, never raises."""
    try:
        path = bypass_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with _write_lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception as exc:
        logger.warning("Failed to write approval bypass record: %s", exc)


def record_bypass(
    *,
    reason: str,
    command: str,
    findings: list | None,
    session_key: str,
    surface: str,
    env_type: str = "",
    detail: dict | None = None,
    tirith: dict | None = None,
) -> dict | None:
    """Emit a bypass audit record (JSONL + ``approval_bypassed`` hook).

    Applies the emission policy from the module docstring: returns ``None``
    without writing anything when the command was not flagged (no detector
    findings, no Tirith findings, no Tirith fail-open). Returns the record
    dict when one was emitted. Never raises.
    """
    try:
        flagged = bool(findings)
        if tirith is not None:
            if tirith.get("fail_open") or (tirith.get("findings") or []):
                flagged = True
        if not flagged:
            return None

        if not findings and tirith is not None and tirith.get("fail_open"):
            # Pure "scan could not run" record — dedupe per process so a
            # missing tirith binary yields one record, not one per command.
            once_key = (reason, str(tirith.get("summary", "")))
            with _write_lock:
                if once_key in _once_only_seen:
                    return None
                _once_only_seen.add(once_key)

        record = build_bypass_record(
            reason=reason,
            command=command,
            findings=findings,
            session_key=session_key,
            surface=surface,
            env_type=env_type,
            detail=detail,
            tirith=tirith,
        )
        _append_record(record)

        pattern_keys = [f["pattern_key"] for f in record["findings"]]
        description = "; ".join(
            f["description"] for f in record["findings"]
        ) or (record["tirith"] or {}).get("summary", "")
        logger.info(
            "Approval bypass (%s): %s [keys=%s session=%s profile=%s]",
            reason,
            record["command"][:200],
            ",".join(pattern_keys) or "-",
            record["session_key"],
            record["profile"],
        )

        # Fire the sibling hook through the same dispatcher the grant/deny
        # hooks use, so turn_id/tool_call_id correlation IDs are attached
        # identically and plugin errors are swallowed identically.
        try:
            from tools.approval import _fire_approval_hook

            _fire_approval_hook(
                "approval_bypassed",
                command=record["command"],
                description=description,
                pattern_key=pattern_keys[0] if pattern_keys else "",
                pattern_keys=pattern_keys,
                session_key=record["session_key"],
                surface=surface,
                reason=reason,
                record=record,
            )
        except Exception as exc:
            logger.debug("approval_bypassed hook dispatch failed: %s", exc)

        return record
    except Exception as exc:
        # The audit layer must never break the approval flow it observes.
        logger.warning("Approval bypass audit failed: %s", exc)
        return None
