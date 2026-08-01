"""Bypass audit records for the dangerous-command approval gate (BUI-1100).

Every path through tools/approval.py that returns ``approved`` WITHOUT
showing a prompt must leave a structured record in
``<hermes_home>/logs/approval_bypass.jsonl`` and fire the
``approval_bypassed`` plugin hook — when (and only when) the command was
actually flagged by a detector. These tests prove each of the five audited
bypass branches emits a record, that the pre-existing grant/deny hook
records still emit, that records never contain a secret, and that clean
commands stay silent.
"""
import json
from unittest.mock import patch

import pytest

import tools.approval as approval_module
import tools.approval_audit as audit_module
from tools.approval import (
    check_all_command_guards,
    check_execute_code_guard,
    clear_session,
    enable_session_yolo,
    request_tool_approval,
    set_current_session_key,
)

SESSION = "test:session:bypass_audit"

CLEAN_TIRITH = {"action": "allow", "findings": [], "summary": ""}


def _read_records():
    path = audit_module.bypass_log_path()
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


@pytest.fixture
def audit_env(monkeypatch, tmp_path):
    """Interactive-CLI approval context with isolated state and audit log."""
    token = set_current_session_key(SESSION)
    monkeypatch.setenv("HERMES_SESSION_KEY", SESSION)
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    monkeypatch.delenv("HERMES_YOLO_MODE", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
    monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
    monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
    monkeypatch.setattr(approval_module, "_get_approval_mode", lambda: "manual")
    # Deterministic tirith: clean allow (no fail-open) unless a test opts out.
    import tools.tirith_security as tirith_module
    monkeypatch.setattr(tirith_module, "check_command_security",
                        lambda command: dict(CLEAN_TIRITH))

    saved_permanent = approval_module._permanent_approved.copy()
    approval_module._permanent_approved.clear()
    audit_module._once_only_seen.clear()
    try:
        yield SESSION
    finally:
        approval_module._permanent_approved.clear()
        approval_module._permanent_approved.update(saved_permanent)
        audit_module._once_only_seen.clear()
        try:
            approval_module._approval_session_key.reset(token)
        except Exception:
            pass
        clear_session(SESSION)


class TestFiveBypassBranchesEmitRecords:
    """The five branches from the BUI-1100 audit, one record each."""

    def test_mode_off_emits_record(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_get_approval_mode", lambda: "off")
        result = check_all_command_guards("rm -rf /tmp/bypass-test", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "mode_off"
        assert rec["surface"] == "terminal"
        assert rec["env_type"] == "local"
        assert rec["session_key"] == SESSION
        assert rec["ts"] and rec["epoch"] > 0
        assert rec["profile"]
        keys = {f["pattern_key"] for f in rec["findings"]}
        assert "recursive delete" in keys

    def test_process_yolo_emits_record(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        result = check_all_command_guards("rm -rf /tmp/bypass-test", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "process_yolo"

    def test_session_yolo_emits_record(self, audit_env):
        enable_session_yolo(SESSION)
        result = check_all_command_guards("rm -rf /tmp/bypass-test", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "session_yolo"

    def test_exact_command_allowlist_emits_record(self, audit_env):
        approval_module.approve_permanent("rm -rf /tmp/cache-dir")
        result = check_all_command_guards("rm -rf /tmp/cache-dir", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "exact_command_allowlist"
        assert rec["detail"]["matched_entry"] == "rm -rf /tmp/cache-dir"
        assert any(f["pattern_key"] == "recursive delete"
                   for f in rec["findings"])

    def test_pattern_key_allowlist_permanent_emits_record(self, audit_env):
        approval_module.approve_permanent("recursive delete")
        result = check_all_command_guards("rm -rf build-dir", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "pattern_key_allowlist"
        assert rec["detail"]["approved_keys"]["recursive delete"] == "permanent"

    def test_pattern_key_allowlist_session_scope_reported(self, audit_env):
        approval_module.approve_session(SESSION, "recursive delete")
        result = check_all_command_guards("rm -rf build-dir", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "pattern_key_allowlist"
        assert rec["detail"]["approved_keys"]["recursive delete"] == "session"


class TestBypassHookFires:
    def test_approval_bypassed_hook_receives_record(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_get_approval_mode", lambda: "off")
        captured = []

        def fake_invoke_hook(hook_name, **kwargs):
            captured.append((hook_name, kwargs))
            return []

        with patch("hermes_cli.plugins.invoke_hook", side_effect=fake_invoke_hook):
            check_all_command_guards("rm -rf /tmp/hook-test", "local")

        assert [name for name, _ in captured] == ["approval_bypassed"]
        kwargs = captured[0][1]
        assert kwargs["reason"] == "mode_off"
        assert kwargs["session_key"] == SESSION
        assert kwargs["surface"] == "terminal"
        assert "recursive delete" in kwargs["pattern_keys"]
        assert kwargs["record"]["event"] == "approval_bypass"

    def test_hook_crash_does_not_break_bypass(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_get_approval_mode", lambda: "off")

        def boom(hook_name, **kwargs):
            raise RuntimeError("plugin crashed")

        with patch("hermes_cli.plugins.invoke_hook", side_effect=boom):
            result = check_all_command_guards("rm -rf /tmp/crash-test", "local")
        assert result["approved"] is True
        # The JSONL record was still written despite the hook crash.
        assert len(_read_records()) == 1


class TestGrantAndDenyRecordsStillEmit:
    """The pre-existing prompt-path hooks are unchanged by the audit layer."""

    def _run(self, choice, captured):
        def fake_invoke_hook(hook_name, **kwargs):
            captured.append((hook_name, kwargs))
            return []

        def cb(command, description, *, allow_permanent=True):
            return choice

        with patch("hermes_cli.plugins.invoke_hook", side_effect=fake_invoke_hook):
            return check_all_command_guards(
                "rm -rf /tmp/prompt-test", "local", approval_callback=cb)

    def test_granted_approval_emits_grant_record_not_bypass(self, audit_env):
        captured = []
        result = self._run("once", captured)
        assert result["approved"] is True
        names = [name for name, _ in captured]
        assert "pre_approval_request" in names
        assert "post_approval_response" in names
        assert "approval_bypassed" not in names
        post = next(kw for name, kw in captured
                    if name == "post_approval_response")
        assert post["choice"] == "once"
        # A prompt was shown — no bypass record may exist.
        assert _read_records() == []

    def test_denied_approval_emits_deny_record_not_bypass(self, audit_env):
        captured = []
        result = self._run("deny", captured)
        assert result["approved"] is False
        post = next(kw for name, kw in captured
                    if name == "post_approval_response")
        assert post["choice"] == "deny"
        assert _read_records() == []


class TestEmissionPolicy:
    def test_clean_command_under_yolo_emits_nothing(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        result = check_all_command_guards("git status", "local")
        assert result["approved"] is True
        assert _read_records() == []

    def test_clean_command_manual_mode_emits_nothing(self, audit_env):
        result = check_all_command_guards("git status", "local")
        assert result["approved"] is True
        assert _read_records() == []

    def test_secret_never_written_to_record(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        secret = "ghp_AbCdEfGh1234567890IjKlMnOpQrStUvWxYz12"
        doppler_token = "dp.st.prd.AbCdEf1234567890XyZ"
        check_all_command_guards(
            f"rm -rf /tmp/x && export T={secret} D={doppler_token}", "local")
        records = _read_records()
        assert len(records) == 1
        raw = json.dumps(records[0])
        assert secret not in raw
        assert doppler_token not in raw

    def test_tirith_fail_open_emits_once_per_process(self, audit_env, monkeypatch):
        import tools.tirith_security as tirith_module
        monkeypatch.setattr(
            tirith_module, "check_command_security",
            lambda command: {"action": "allow", "findings": [],
                             "summary": "tirith path unavailable",
                             "fail_open": True})
        r1 = check_all_command_guards("git status", "local")
        r2 = check_all_command_guards("git log", "local")
        assert r1["approved"] and r2["approved"]
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "tirith_fail_open"
        assert records[0]["tirith"]["fail_open"] is True


class TestNonInteractiveAndCronPaths:
    def test_non_interactive_auto_approve_emits_record(self, audit_env, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "")
        result = check_all_command_guards("rm -rf /tmp/headless", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "non_interactive_auto_approve"

    def test_cron_approve_mode_emits_record(self, audit_env, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "")
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
        monkeypatch.setattr(approval_module, "_get_cron_approval_mode",
                            lambda: "approve")
        result = check_all_command_guards("rm -rf /tmp/cron-job", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "cron_approve_mode"


class TestSmartApprovalEmitsRecord:
    def test_smart_grant_records_bypass(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_get_approval_mode",
                            lambda: "smart")
        monkeypatch.setattr(approval_module, "_smart_approve",
                            lambda command, description: "approve")
        result = check_all_command_guards("rm -rf /tmp/smart-test", "local")
        assert result["approved"] is True
        assert result.get("smart_approved") is True
        records = _read_records()
        assert len(records) == 1
        assert records[0]["reason"] == "smart_approval"


class TestExecuteCodeGuardEmitsRecords:
    def test_yolo_in_gateway_context_emits(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
        result = check_execute_code_guard("print('hi')", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "process_yolo"
        assert rec["surface"] == "execute_code"
        assert rec["findings"][0]["pattern_key"] == "execute_code"

    def test_yolo_pure_local_emits_nothing(self, audit_env, monkeypatch):
        """Local non-gateway execute_code is out of the guard's designed
        scope (per-call terminal guards cover it), so no record."""
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        result = check_execute_code_guard("print('hi')", "local")
        assert result["approved"] is True
        assert _read_records() == []

    def test_session_approved_execute_code_emits(self, audit_env, monkeypatch):
        monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
        approval_module.approve_session(SESSION, "execute_code")
        result = check_execute_code_guard("print('hi')", "local")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "pattern_key_allowlist"
        assert rec["detail"]["approved_keys"]["execute_code"] == "session"


class TestPluginEscalationGateEmitsRecords:
    def test_request_tool_approval_yolo_emits(self, audit_env, monkeypatch):
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", True)
        result = request_tool_approval("write_file", "writes to ~/.ssh")
        assert result["approved"] is True
        records = _read_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["reason"] == "process_yolo"
        assert rec["surface"] == "tool_approval"
        assert rec["findings"][0]["description"] == "writes to ~/.ssh"
