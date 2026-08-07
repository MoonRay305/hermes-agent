"""Tests for the centralized default-deny non-terminal subprocess env."""

import os
from unittest.mock import patch

from tools.environments.local import (
    hermes_subprocess_env,
    _ALWAYS_STRIP_KEYS,
    _HERMES_PROVIDER_ENV_FORCE_PREFIX,
)


_TIER1_SAMPLE = {
    "GH_TOKEN": "ghp_secret",
    "TELEGRAM_BOT_TOKEN": "bot-token",
    "SLACK_APP_TOKEN": "xapp-secret",
    "MODAL_TOKEN_SECRET": "modal-secret",
    "HERMES_DASHBOARD_SESSION_TOKEN": "dash-secret",
}

_PROVIDER_SAMPLE = {
    "OPENAI_API_KEY": "sk-fake",
    "ANTHROPIC_API_KEY": "ant-fake",
    "OPENROUTER_API_KEY": "or-fake",
}

_SAFE_SAMPLE = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/user",
    "USER": "testuser",
}

_OPAQUE_SAMPLE = {
    "MS_GRAPH_TENANT_ID": "tenant-secret",
    "SESSION": "session-secret",
    "AUTH": "auth-secret",
    "ORCHARD": "opaque-secret-one",
    "BLUEBIRD": "opaque-secret-two",
    "QUARTZ": "opaque-secret-three",
}

_AWS_OPERATOR_SAMPLE = {
    "AWS_ACCESS_KEY_ID": "sentinel-access",
    "AWS_SECRET_ACCESS_KEY": "sentinel-secret",
    "AWS_SESSION_TOKEN": "sentinel-session",
    "AWS_PROFILE": "sentinel-profile",
    "AWS_DEFAULT_REGION": "sentinel-default-region",
    "AWS_REGION": "sentinel-region",
    "AWS_SHARED_CREDENTIALS_FILE": "/sentinel/credentials",
    "AWS_CONFIG_FILE": "/sentinel/config",
    "AWS_WEB_IDENTITY_TOKEN_FILE": "/sentinel/web-token",
    "AWS_ROLE_ARN": "sentinel-role",
}


def _build(extra=None, *, inherit_credentials=False):
    env = dict(_SAFE_SAMPLE)
    if extra:
        env.update(extra)
    with patch.dict(os.environ, env, clear=True):
        return hermes_subprocess_env(inherit_credentials=inherit_credentials)


class TestStripByDefault:
    def test_provider_keys_stripped_by_default(self):
        result = _build(_PROVIDER_SAMPLE)
        for var in _PROVIDER_SAMPLE:
            assert var not in result, f"{var} leaked with inherit_credentials=False"

    def test_tier1_secrets_stripped_by_default(self):
        result = _build(_TIER1_SAMPLE)
        for var in _TIER1_SAMPLE:
            assert var not in result, f"{var} leaked (Tier-1) with inherit_credentials=False"

    def test_unknown_names_stripped_by_default(self):
        result = _build(_OPAQUE_SAMPLE)
        assert not (_OPAQUE_SAMPLE.keys() & result.keys())

    def test_safe_vars_preserved(self):
        result = _build()
        assert result["HOME"] == "/home/user"
        assert result["USER"] == "testuser"
        assert "PATH" in result

    def test_force_prefix_hints_stripped(self):
        result = _build({f"{_HERMES_PROVIDER_ENV_FORCE_PREFIX}OPENAI_API_KEY": "sk-x"})
        assert f"{_HERMES_PROVIDER_ENV_FORCE_PREFIX}OPENAI_API_KEY" not in result
        assert "OPENAI_API_KEY" not in result

    def test_pythonutf8_set(self):
        result = _build()
        assert result.get("PYTHONUTF8") == "1"


class TestInheritCredentials:
    def test_legacy_inherit_flag_does_not_widen_allowlist(self):
        result = _build(_PROVIDER_SAMPLE, inherit_credentials=True)
        for var in _PROVIDER_SAMPLE:
            assert var not in result

    def test_tier1_secrets_stripped_even_when_inheriting(self):
        """The whole point of Tier 1: gateway/GitHub/infra secrets never reach
        a child, even a model-driving CLI that legitimately needs provider keys."""
        result = _build({**_PROVIDER_SAMPLE, **_TIER1_SAMPLE}, inherit_credentials=True)
        for var in _TIER1_SAMPLE:
            assert var not in result, (
                f"{var} (Tier-1) must be stripped even with inherit_credentials=True"
            )
        for var in _PROVIDER_SAMPLE:
            assert var not in result

    def test_unknown_names_stay_stripped_when_inheriting(self):
        result = _build({**_PROVIDER_SAMPLE, **_OPAQUE_SAMPLE}, inherit_credentials=True)
        assert not (_OPAQUE_SAMPLE.keys() & result.keys())
        for var in _PROVIDER_SAMPLE:
            assert var not in result

    def test_pythonutf8_set_when_inheriting(self):
        assert _build(inherit_credentials=True).get("PYTHONUTF8") == "1"


class TestExplicitPassthrough:
    def test_exact_passthrough_name_reaches_centralized_child(self):
        from tools.env_passthrough import clear_env_passthrough, register_env_passthrough

        clear_env_passthrough()
        try:
            register_env_passthrough(["ORCHARD"])
            result = _build({"ORCHARD": "explicit-value"})
        finally:
            clear_env_passthrough()

        assert result.get("ORCHARD") == "explicit-value"


class TestAwsOperatorBoundary:
    def test_chain_observe_absent_at_boundary_four(self):
        """Central non-terminal children never inherit the AWS operator chain."""
        for inherit in (False, True):
            result = _build(_AWS_OPERATOR_SAMPLE, inherit_credentials=inherit)
            assert not (_AWS_OPERATOR_SAMPLE.keys() & result.keys())

    def test_passthrough_cannot_promote_aws_at_boundary_four(self):
        """Generic passthrough is not an escape hatch for boundary-4 AWS."""
        from tools.env_passthrough import clear_env_passthrough, register_env_passthrough

        clear_env_passthrough()
        try:
            register_env_passthrough(list(_AWS_OPERATOR_SAMPLE))
            result = _build(_AWS_OPERATOR_SAMPLE)
        finally:
            clear_env_passthrough()

        assert not (_AWS_OPERATOR_SAMPLE.keys() & result.keys())

    def test_chain_observe_absent_from_snapshot_boundary(self):
        from tools.environments.local import _snapshot_allowed_env_names

        names = set(_snapshot_allowed_env_names(_AWS_OPERATOR_SAMPLE))
        assert not (_AWS_OPERATOR_SAMPLE.keys() & names)


class TestTierInvariants:
    def test_tier1_always_stripped_both_paths(self):
        """Behavioral invariant: every Tier-1 key is stripped on BOTH the
        default path and the inherit_credentials=True path. This is what
        guarantees no gap, regardless of whether the key also happens to be
        in the provider blocklist."""
        sample = {k: f"secret-{k}" for k in _ALWAYS_STRIP_KEYS}
        for inherit in (False, True):
            result = _build(sample, inherit_credentials=inherit)
            leaked = {k for k in _ALWAYS_STRIP_KEYS if k in result}
            assert not leaked, (
                f"Tier-1 keys leaked with inherit_credentials={inherit}: {sorted(leaked)}"
            )

    def test_tier1_covers_gateway_bot_token(self):
        assert "TELEGRAM_BOT_TOKEN" in _ALWAYS_STRIP_KEYS

    def test_tier1_covers_github_auth(self):
        assert {"GH_TOKEN", "GITHUB_TOKEN"} <= _ALWAYS_STRIP_KEYS

    def test_tier1_covers_infra_secrets(self):
        assert {"MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "DAYTONA_API_KEY"} <= _ALWAYS_STRIP_KEYS


class TestBrowserPassthroughPattern:
    def test_browser_keys_recoverable_after_strip(self):
        """Browser tool pattern: strip everything, then re-add the browser
        backend keys agent-browser actually needs."""
        from tools.browser_tool import _build_browser_env

        leaked = {
            "BROWSERBASE_API_KEY": "bb-key",
            "BROWSERBASE_PROJECT_ID": "bb-proj",
            "FIRECRAWL_API_KEY": "fc-key",
            "ANTHROPIC_API_KEY": "ant-should-go",
            "TELEGRAM_BOT_TOKEN": "bot-should-go",
            **_AWS_OPERATOR_SAMPLE,
        }
        with patch.dict(os.environ, {**_SAFE_SAMPLE, **leaked}, clear=True):
            env = _build_browser_env()

        assert env["BROWSERBASE_API_KEY"] == "bb-key"
        assert env["FIRECRAWL_API_KEY"] == "fc-key"
        # Provider + gateway secrets must NOT come back.
        assert "ANTHROPIC_API_KEY" not in env
        assert "TELEGRAM_BOT_TOKEN" not in env
        assert not (_AWS_OPERATOR_SAMPLE.keys() & env.keys())


_INTERNAL_DYNAMIC_SAMPLE = {
    "AUXILIARY_VISION_API_KEY": "sk-vision",
    "AUXILIARY_VISION_BASE_URL": "http://internal:1234/v1",
    "AUXILIARY_WEB_EXTRACT_API_KEY": "sk-webx",
    "GATEWAY_RELAY_SECRET": "relay-secret",
    "GATEWAY_RELAY_DELIVERY_KEY": "relay-delivery",
}


class TestInternalDynamicSecrets:
    """Internal secrets stay denied even through compatibility call paths."""

    def test_stripped_by_default(self):
        result = _build(_INTERNAL_DYNAMIC_SAMPLE)
        for var in _INTERNAL_DYNAMIC_SAMPLE:
            assert var not in result, f"{var} leaked with inherit_credentials=False"

    def test_stripped_even_when_inheriting(self):
        result = _build(
            {**_PROVIDER_SAMPLE, **_INTERNAL_DYNAMIC_SAMPLE},
            inherit_credentials=True,
        )
        for var in _INTERNAL_DYNAMIC_SAMPLE:
            assert var not in result, (
                f"{var} must be stripped even with inherit_credentials=True"
            )
        for var in _PROVIDER_SAMPLE:
            assert var not in result

    def test_auxiliary_non_secrets_require_explicit_passthrough(self):
        result = _build(
            {"AUXILIARY_VISION_PROVIDER": "openai", "AUXILIARY_VISION_MODEL": "gpt-4o"},
        )
        assert "AUXILIARY_VISION_PROVIDER" not in result
        assert "AUXILIARY_VISION_MODEL" not in result

    def test_gateway_relay_id_stripped_even_when_inheriting(self):
        """GATEWAY_RELAY_ID has no secret suffix (predicate skips it) but is
        gateway-identifying auth material provisioned alongside the relay
        secret. It's in _ALWAYS_STRIP_KEYS so it's stripped on the inherit path
        too — closes the codex/copilot leak the predicate alone would miss."""
        result = _build(
            {**_PROVIDER_SAMPLE, "GATEWAY_RELAY_ID": "relay-id"},
            inherit_credentials=True,
        )
        assert "GATEWAY_RELAY_ID" not in result
        for var in _PROVIDER_SAMPLE:
            assert var not in result

    def test_relay_triplet_in_always_strip(self):
        assert {
            "GATEWAY_RELAY_ID", "GATEWAY_RELAY_SECRET", "GATEWAY_RELAY_DELIVERY_KEY",
        } <= _ALWAYS_STRIP_KEYS
