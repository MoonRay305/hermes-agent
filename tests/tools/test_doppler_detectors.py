"""Semantic detectors for Doppler credential operations (BUI-1100 item 3).

Doppler read and write gated in ZERO of the audited profiles because no
detector existed. These detectors key on the OPERATION — ``doppler …
secrets … <op>`` with anything in between — so a flag-order rephrasing,
wrapper command, or quote-splitting does not evade them. They must gate
(prompt) in a default manual-mode profile and must NOT be pre-approved by
anything in code.
"""
import pytest

import tools.approval as approval_module
from tools.approval import (
    check_all_command_guards,
    clear_session,
    detect_all_dangerous_patterns,
    detect_dangerous_command,
    is_approved,
    set_current_session_key,
)

READ_KEYS = {
    "Doppler credential read (secrets get/download/substitute)",
    "Doppler credential read (doppler run injects secrets into child env)",
}
WRITE_KEYS = {
    "Doppler credential write (secrets set/delete/upload)",
    "Doppler credential write (service token create)",
}


def _keys(command):
    return {key for key, _ in detect_all_dangerous_patterns(command)}


class TestOperationDetection:
    @pytest.mark.parametrize("command", [
        "doppler secrets get DATABASE_URL",
        "doppler secrets get DATABASE_URL --plain",
        "doppler secrets download --no-file --format env",
        "doppler secrets substitute deploy.template.yaml",
        "doppler run -- npm start",
    ])
    def test_read_operations_fire(self, command):
        assert _keys(command) & READ_KEYS, command

    @pytest.mark.parametrize("command", [
        "doppler secrets set STRIPE_KEY sk_live_value",
        "doppler secrets delete OLD_KEY",
        "doppler secrets upload .env.production",
        "doppler configs tokens create ci-token --config prd",
    ])
    def test_write_operations_fire(self, command):
        assert _keys(command) & WRITE_KEYS, command

    @pytest.mark.parametrize("command", [
        "doppler setup",
        "doppler login",
        "doppler configs",
        "doppler projects list",
        "echo doppler is a secrets manager",
    ])
    def test_non_credential_operations_stay_clean(self, command):
        assert not (_keys(command) & (READ_KEYS | WRITE_KEYS)), command


class TestRephrasingResistance:
    """The audit's core finding was syntactic-not-semantic coverage; these
    detectors must survive the standard evasion spellings."""

    @pytest.mark.parametrize("command", [
        # Global flags between the words
        "doppler --project api --config prd secrets get DATABASE_URL",
        "doppler secrets --project api get DATABASE_URL",
        # Wrapper commands
        "sudo doppler secrets get DATABASE_URL",
        "env DOPPLER_TOKEN=x doppler secrets get DATABASE_URL",
        "time doppler secrets get DATABASE_URL",
        "command doppler secrets get DATABASE_URL",
        # Case variants (detection lowercases)
        "DOPPLER SECRETS GET DATABASE_URL",
        # Quote-splitting on the command word
        "dop''pler secrets get DATABASE_URL",
        r"dopp\ler secrets get DATABASE_URL",
        # Chained after a benign command
        "cd /srv/app && doppler secrets get DATABASE_URL",
        # Line continuation
        "doppler \\\nsecrets get DATABASE_URL",
    ])
    def test_read_survives_rephrasing(self, command):
        assert _keys(command) & READ_KEYS, command

    @pytest.mark.parametrize("command", [
        "doppler --project api secrets set KEY value",
        "sudo doppler secrets delete KEY",
        "DOPPLER SECRETS SET KEY value",
    ])
    def test_write_survives_rephrasing(self, command):
        assert _keys(command) & WRITE_KEYS, command

    def test_segment_bounded_no_cross_command_match(self):
        """The operation word must be in the SAME command segment — a later
        command containing 'get' must not turn `doppler login` into a read."""
        assert not (_keys("doppler login; git fetch && apt-get update")
                    & (READ_KEYS | WRITE_KEYS))


class TestGatesAndNotAllowlisted:
    def test_keys_not_approved_by_default(self):
        session = "test:session:doppler"
        for key in READ_KEYS | WRITE_KEYS:
            assert not is_approved(session, key), key

    def test_doppler_read_prompts_in_manual_mode(self, monkeypatch):
        """End to end: a manual-mode interactive session must PROMPT (here:
        deny via callback → blocked), not silently allow."""
        session = "test:session:doppler-gate"
        token = set_current_session_key(session)
        monkeypatch.setenv("HERMES_SESSION_KEY", session)
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
        monkeypatch.delenv("HERMES_EXEC_ASK", raising=False)
        monkeypatch.delenv("HERMES_CRON_SESSION", raising=False)
        monkeypatch.setattr(approval_module, "_YOLO_MODE_FROZEN", False)
        monkeypatch.setattr(approval_module, "_get_approval_mode",
                            lambda: "manual")
        import tools.tirith_security as tirith_module
        monkeypatch.setattr(
            tirith_module, "check_command_security",
            lambda command: {"action": "allow", "findings": [], "summary": ""})
        saved = approval_module._permanent_approved.copy()
        approval_module._permanent_approved.clear()
        try:
            result = check_all_command_guards(
                "doppler secrets get DATABASE_URL --plain", "local",
                approval_callback=lambda c, d, allow_permanent=True: "deny",
            )
            assert result["approved"] is False
            assert "Doppler" in result.get("description", "")
        finally:
            approval_module._permanent_approved.clear()
            approval_module._permanent_approved.update(saved)
            approval_module._approval_session_key.reset(token)
            clear_session(session)

    def test_first_match_key_is_doppler_specific(self):
        is_dangerous, key, _ = detect_dangerous_command(
            "doppler secrets get DATABASE_URL")
        assert is_dangerous
        assert key in READ_KEYS


class TestDopplerTokenRedaction:
    """Companion to the detectors: a Doppler service token must never
    survive into an audit record or approval prompt rendering."""

    @pytest.mark.parametrize("token", [
        "dp.st.prd.AbCdEf1234567890XyZ",
        "dp.st.AbCdEf1234567890XyZ",
        "dp.ct.QwErTy0987654321Zx",
        "dp.pt.aB3dE6gH9jK2mN5pQ8s",
        "dp.sa.SvcAcct123456789012",
    ])
    def test_doppler_tokens_redacted(self, token):
        from agent.redact import redact_sensitive_text

        out = redact_sensitive_text(f"doppler configure set token {token}",
                                    force=True)
        assert token not in out

    @pytest.mark.parametrize("text", [
        "update dpkg and dp.stats file",
        "no token here dp. st. prose",
        "see docs/dp.standards.md",
    ])
    def test_prose_not_redacted(self, text):
        from agent.redact import redact_sensitive_text

        assert redact_sensitive_text(text, force=True) == text
