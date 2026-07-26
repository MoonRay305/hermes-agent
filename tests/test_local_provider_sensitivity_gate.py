import json
import pathlib
from types import SimpleNamespace

import pytest

from agent.local_provider_sensitivity_gate import (
    LocalProviderSensitivityBlocked,
    assert_local_provider_request_allowed,
    classify_request,
    evaluate_local_provider_request,
    is_local_provider_route,
)


def test_ollama_personal_health_data_is_blocked_without_approved_route(tmp_path, monkeypatch):
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "get_hermes_home", lambda: str(tmp_path))
    messages = [
        {
            "role": "user",
            "content": (
                "Summarize veterinary medication notes for a private subject and use "
                "API_KEY=REDACTMEVALUE1234567890 for the lookup."
            ),
        }
    ]

    with pytest.raises(LocalProviderSensitivityBlocked) as excinfo:
        assert_local_provider_request_allowed(
            provider="ollama",
            base_url="http://127.0.0.1:11434/v1",
            model="llama3.2",
            messages=messages,
            config={},
        )

    err = str(excinfo.value)
    assert "veterinary medication notes for a private subject" not in err
    assert "REDACTMEVALUE1234567890" not in err
    decision = excinfo.value.decision
    assert decision.allowed is False
    assert decision.local_route is True
    assert {"personal_health", "private", "secret", "production"}.issubset(set(decision.data_classes))
    assert decision.redaction_counts["api_key_assignment"] == 1

    audit_path = tmp_path / "logs" / "local_provider_sensitivity_gate.jsonl"
    logged = audit_path.read_text()
    assert "REDACTMEVALUE1234567890" not in logged
    assert "veterinary medication notes for a private subject" not in logged
    event = json.loads(logged.splitlines()[-1])
    assert event["decision"] == "deny"
    assert event["provider"] == "ollama"
    assert event["base_url_host"] == "127.0.0.1"
    assert event["request_sha256"]
    assert event["redaction_counts"]["api_key_assignment"] == 1


def test_approved_worker_contract_route_allows_matching_sensitive_ollama_request():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "Medication summary for private care notes"}],
        config={
            "worker_contract": {
                "data_class": "personal_health",
                "allowed_model_routes": [
                    {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "llama3.2",
                        "data_classes": ["personal_health", "private"],
                        "approved": True,
                        "approval_id": "unit-test-route",
                    }
                ],
            }
        },
    )

    assert decision.allowed is True
    assert decision.approved_route is True
    approval_id = decision.route_approval_id
    assert approval_id is not None
    assert approval_id.startswith("sha256:")
    assert "unit-test-route" not in approval_id
    assert set(decision.data_classes) >= {"personal_health", "private"}


@pytest.mark.parametrize("route", [{}, {"data_classes": []}, {"allowed_data_classes": []}])
def test_approved_route_must_declare_non_empty_class_coverage(route):
    route.update(
        {
            "provider": "ollama",
            "base_url": "http://127.0.0.1:11434/v1",
            "model": "llama3.2",
            "approved": True,
        }
    )

    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "Review lawsuit notes on the client file for a contract dispute"}],
        config={"local_provider_sensitivity": {"approved_routes": [route]}},
    )

    assert decision.allowed is False
    assert {"client", "legal"}.issubset(set(decision.data_classes))


def test_approved_route_wildcard_class_coverage_is_explicit_and_allowed():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "Review lawsuit notes on the client file for a contract dispute"}],
        config={
            "local_provider_sensitivity": {
                "approved_routes": [
                    {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "llama3.2",
                        "data_classes": ["*"],
                        "approved": True,
                    }
                ]
            }
        },
    )

    assert decision.allowed is True
    assert decision.approved_route is True


def test_approved_route_must_cover_detected_classes():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "Review lawsuit notes on the client file for a contract dispute"}],
        config={
            "local_provider_sensitivity": {
                "approved_routes": [
                    {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "llama3.2",
                        "data_classes": ["client"],
                        "approved": True,
                    }
                ]
            }
        },
    )

    assert decision.allowed is False
    assert {"client", "legal"}.issubset(set(decision.data_classes))


def test_audit_payload_sanitizes_config_labels_prompt_snippets_and_approval_ids(tmp_path, monkeypatch):
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "get_hermes_home", lambda: str(tmp_path))
    private_label = "_".join(["raw", "subject", "lane", "42"])
    prompt_snippet = " ".join(["subject", "alpha", "medication", "note"])
    secret_value = "REDACT" + "MEVALUE" + "1234567890"

    decision = assert_local_provider_request_allowed(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": f"{prompt_snippet} API_KEY={secret_value}"}],
        config={
            "worker_contract": {
                "data_class": private_label,
                "allowed_model_routes": [
                    {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "llama3.2",
                        "data_classes": [private_label, "personal_health", "private", "secret", "production"],
                        "approved": True,
                        "approval_id": f"approval-{private_label}-secret",
                    }
                ],
            },
            "local_provider_sensitivity": {
                "sensitive_classes": [private_label, "personal_health", "private", "secret", "production"]
            },
        },
    )

    assert decision.allowed is True
    assert decision.route_approval_id is not None
    assert decision.route_approval_id.startswith("sha256:")
    assert private_label not in decision.route_approval_id
    assert decision.declared_data_class == "private_subject"
    assert private_label not in decision.data_classes

    audit_path = tmp_path / "logs" / "local_provider_sensitivity_gate.jsonl"
    logged = audit_path.read_text()
    assert private_label not in logged
    assert prompt_snippet not in logged
    assert secret_value not in logged
    event = json.loads(logged.splitlines()[-1])
    assert event["declared_data_class"] == "private_subject"
    assert "private_subject" in event["data_classes"]
    assert private_label not in event["data_classes"]
    assert event["route_approval_id"].startswith("sha256:")
    assert private_label not in event["route_approval_id"]


def test_non_local_route_is_not_blocked_by_local_gate():
    decision = evaluate_local_provider_request(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4",
        messages=[{"role": "user", "content": "Medication notes"}],
        config={},
    )

    assert decision.allowed is True
    assert decision.local_route is False
    assert decision.reason == "non_local_route"


@pytest.mark.parametrize(
    "provider,base_url",
    [
        ("ollama", "http://10.0.0.2:11434/v1"),
        ("custom:lmstudio", "http://192.168.1.10:1234/v1"),
        ("custom:local-router", "http://localhost:8080/v1"),
    ],
)
def test_local_route_detection(provider, base_url):
    assert is_local_provider_route(provider, base_url) is True


def test_classifier_redacts_secret_values_from_debug_redacted_text():
    classes, redacted, counts, request_hash = classify_request(
        [{"role": "user", "content": "TOKEN=REDACTMEVALUE1234567890 and prod database"}]
    )

    assert "REDACTMEVALUE1234567890" not in redacted
    assert "[REDACTED]" in redacted
    assert "secret" in classes
    assert "production" in classes
    assert counts["api_key_assignment"] == 1
    assert len(request_hash) == 64


# ---------------------------------------------------------------------------
# Fail-closed contract (BUI-370 G5)
#
# The gate's whole purpose is to be the last thing between sensitive data and
# a local endpoint.  "The gate crashed" must therefore never be indistinguishable
# from "the gate approved".  These tests pin that an evaluation failure denies
# the send rather than falling through to it.
# ---------------------------------------------------------------------------


def _explode(*args, **kwargs):
    raise RuntimeError("classifier exploded")


def test_evaluation_failure_blocks_the_send_on_a_local_route(monkeypatch):
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "classify_request", _explode)

    with pytest.raises(LocalProviderSensitivityBlocked) as excinfo:
        assert_local_provider_request_allowed(
            provider="ollama",
            base_url="http://127.0.0.1:11434/v1",
            model="llama3.2",
            messages=[{"role": "user", "content": "anything at all"}],
            config={},
        )

    decision = excinfo.value.decision
    assert decision.allowed is False
    assert decision.local_route is True
    assert decision.reason == "gate_evaluation_failed"
    # The operator has to be able to tell this apart from a policy denial.
    assert "could not evaluate" in str(excinfo.value)
    assert "classifier exploded" not in str(excinfo.value)


def test_evaluation_failure_is_not_silently_downgraded_to_allow(monkeypatch):
    """evaluate_* must not leak the exception *or* return allowed=True."""
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "_sensitive_classes", _explode)

    decision = evaluate_local_provider_request(
        provider="lmstudio",
        base_url="http://192.168.1.10:1234/v1",
        model="qwen",
        messages=[{"role": "user", "content": "hello"}],
        config={},
    )

    assert decision.allowed is False
    assert decision.reason == "gate_evaluation_failed"


def test_config_read_failure_denies_the_local_route(monkeypatch):
    """An unreadable config is an evaluation failure, not a clean classification.

    Regression for the fail-open found by review at 75a375c49: the ``config is
    None`` branch caught ``load_config()`` failures and substituted ``{}``
    before the fail-closed wrapper could see them, so a PermissionError on the
    config file produced ``allowed=True`` /
    ``reason=no_sensitive_classes_detected`` — a normal classification of a
    payload the gate had in fact never managed to evaluate under policy.
    """
    import agent.local_provider_sensitivity_gate as gate

    def _unreadable_config():
        raise PermissionError("[Errno 13] Permission denied: 'cli-config.yaml'")

    monkeypatch.setattr(gate, "load_config", _unreadable_config)

    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "anything at all"}],
    )

    assert decision.allowed is False
    assert decision.local_route is True
    assert decision.reason == "gate_evaluation_failed"


def test_config_read_failure_blocks_the_send_on_a_local_route(monkeypatch):
    """The deny is enforced at the call site, not merely reported."""
    import agent.local_provider_sensitivity_gate as gate

    def _unreadable_config():
        raise OSError("config volume went away mid-turn")

    monkeypatch.setattr(gate, "load_config", _unreadable_config)

    with pytest.raises(LocalProviderSensitivityBlocked) as excinfo:
        assert_local_provider_request_allowed(
            provider="lmstudio",
            base_url="http://192.168.1.10:1234/v1",
            model="qwen",
            messages=[{"role": "user", "content": "hello"}],
        )

    decision = excinfo.value.decision
    assert decision.allowed is False
    assert decision.reason == "gate_evaluation_failed"
    assert "could not evaluate" in str(excinfo.value)
    # The operator message must not leak filesystem internals as prompt text.
    assert "config volume went away" not in str(excinfo.value)


def test_config_read_failure_on_a_cloud_route_does_not_take_the_agent_offline(monkeypatch):
    """Same jurisdiction rule as any other evaluation failure."""
    import agent.local_provider_sensitivity_gate as gate

    def _unreadable_config():
        raise PermissionError("nope")

    monkeypatch.setattr(gate, "load_config", _unreadable_config)

    decision = evaluate_local_provider_request(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4",
        messages=[{"role": "user", "content": "hello"}],
    )

    assert decision.allowed is True
    assert decision.local_route is False
    assert decision.reason == "gate_evaluation_failed"


def test_unparseable_route_is_treated_as_local_not_as_cloud(monkeypatch):
    """Route classification is total: an unreadable route still gets gated."""
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "_normalize_provider", _explode)

    assert is_local_provider_route("whatever", "https://api.openai.com/v1") is True


def test_evaluation_failure_on_a_cloud_route_does_not_take_the_agent_offline(monkeypatch):
    """The gate governs local routes only; a bug here must not block cloud sends."""
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "classify_request", _explode)

    decision = evaluate_local_provider_request(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4",
        messages=[{"role": "user", "content": "hello"}],
        config={},
    )

    assert decision.allowed is True
    assert decision.local_route is False
    assert decision.reason == "gate_evaluation_failed"


def test_audit_write_failure_cannot_turn_a_deny_into_a_send(monkeypatch):
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "_write_audit", _explode)

    with pytest.raises(LocalProviderSensitivityBlocked):
        assert_local_provider_request_allowed(
            provider="ollama",
            base_url="http://127.0.0.1:11434/v1",
            model="llama3.2",
            messages=[
                {"role": "user", "content": "the client file covers a wire transfer"}
            ],
            config={},
        )


# ---------------------------------------------------------------------------
# False-positive regression (the CI failure this PR shipped with)
#
# The first cut matched bare words, so Hermes' own system prompt — which embeds
# AGENTS.md — classified as client/production/trading/personal_health and the
# gate denied 100% of local-provider traffic.
# ---------------------------------------------------------------------------


ORDINARY_DEVELOPER_TEXT = """
The agent connects to it through the built-in MCP client; slash commands are
curated client-side then dispatched to the backend.
npm start         # production
Run `concurrent.futures` executors with the config.yaml options below.
A good fix reproduces the symptom on current main and points at the diagnosis.
resolved_api_key = api_key or explicit_api_key
summary_kwargs = {"max_tokens": max_tokens}
session_completion_tokens = skipped_nonspawnable + skill_matches_platform
"""


def test_ordinary_developer_context_is_not_classified_as_sensitive():
    classes, _redacted, counts, _hash = classify_request(
        [{"role": "system", "content": ORDINARY_DEVELOPER_TEXT}]
    )

    assert classes == [], f"ordinary engineering text classified as {classes} via {counts}"


def test_ordinary_developer_context_is_allowed_through_a_local_route():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://localhost:11434/v1",
        model="qwen2.5-coder",
        messages=[
            {"role": "system", "content": ORDINARY_DEVELOPER_TEXT},
            {"role": "user", "content": "read the file"},
        ],
        config={},
    )

    assert decision.allowed is True
    assert decision.local_route is True
    assert decision.reason == "no_sensitive_classes_detected"


@pytest.mark.parametrize(
    "text,expected",
    [
        ("counsel advised we hold the release", "legal"),
        ("serve the subpoena on Monday", "legal"),
        ("the malpractice claim is still open", "legal"),
        ("pull the invoice and check the total", "financial"),
        ("invoices went out late again", "financial"),
        ("send the remittance advice", "financial"),
        ("the prognosis was not good", "personal_health"),
        ("comorbidity was noted in the chart", "personal_health"),
    ],
)
def test_high_signal_bare_tokens_classify(text, expected):
    """Phrase anchoring alone missed these; they carry the same exposure."""
    classes, _redacted, _counts, _hash = classify_request([{"role": "user", "content": text}])

    assert expected in classes, f"missed {expected} in {text!r}"


@pytest.mark.parametrize(
    "token",
    ["client", "production", "options", "futures", "symptom", "privileged", "diagnosis"],
)
def test_outage_causing_bare_tokens_stay_out(token):
    """These bare words are why the first cut denied 100% of local traffic.

    `client`, `production`, `options` and `symptom` occur in AGENTS.md, which
    is embedded verbatim into Hermes' system prompt, so restoring any of them
    denies every local turn.  `futures` is `concurrent.futures`, `privileged`
    is container vocabulary, `diagnosis` is ordinary debugging prose.  Pinned
    so a future "just add a few more tokens" pass has to argue with a test.
    """
    classes, _redacted, _counts, _hash = classify_request(
        [{"role": "user", "content": f"the {token} was fine"}]
    )

    assert classes == [], f"bare {token!r} classified as {classes} — restores the outage"


def test_the_real_system_prompt_source_does_not_classify_as_sensitive():
    """The strongest regression available: gate the actual embedded document.

    AGENTS.md is embedded into Hermes' system prompt on every turn.  If it
    classifies, every local-provider request is denied — which is exactly the
    failure this gate was remediated for.
    """
    agents_md = pathlib.Path(__file__).resolve().parents[1] / "AGENTS.md"
    if not agents_md.is_file():  # pragma: no cover - repo layout guard
        pytest.skip("AGENTS.md not present")

    classes, _redacted, counts, _hash = classify_request(
        [{"role": "system", "content": agents_md.read_text(encoding="utf-8")}]
    )

    assert classes == [], (
        f"AGENTS.md classified as {classes} via {counts} — this denies every local turn"
    )


def test_strict_mode_denies_a_local_route_with_no_declared_data_class():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "perfectly ordinary text"}],
        config={"local_provider_sensitivity": {"require_declared_data_class": True}},
    )

    assert decision.allowed is False
    assert decision.reason == "no_declared_data_class"
    assert decision.declared_data_class is None


def test_strict_mode_allows_the_route_once_the_class_is_declared():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "perfectly ordinary text"}],
        config={
            "local_provider_sensitivity": {
                "require_declared_data_class": True,
                "data_class": "internal",
            }
        },
    )

    assert decision.allowed is True
    assert decision.reason == "no_sensitive_classes_detected"


def test_strict_mode_is_off_by_default_so_a_stock_install_is_not_an_outage():
    """Defaulting this on would deny 100% of local traffic — nothing declares."""
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "perfectly ordinary text"}],
        config={},
    )

    assert decision.allowed is True
    assert decision.reason == "no_sensitive_classes_detected"


def test_strict_mode_does_not_apply_to_cloud_routes():
    decision = evaluate_local_provider_request(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4",
        messages=[{"role": "user", "content": "perfectly ordinary text"}],
        config={"local_provider_sensitivity": {"require_declared_data_class": True}},
    )

    assert decision.allowed is True
    assert decision.reason == "non_local_route"


@pytest.mark.parametrize(
    "text",
    [
        'api_key = "sk-proj-AbCdEf0123456789AbCdEf0123456789"',
        # Unquoted .env-style value.  Deliberately not a recognisable vendor
        # prefix — a realistic one trips GitHub push protection on this file.
        "APP_SECRET=Zx9Qw2Rt7Yu4Io1Pa6Sd3Fg8Hj5Kl0Mn7Bv",
        "use ghp_AbCdEf0123456789AbCdEf0123456789abcd for the push",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "DATABASE_URL=postgres://u:pw@db.example.com:5432/prod",
        "AKIAIOSFODNN7EXAMPLE",
    ],
)
def test_real_secret_shapes_still_classify_as_secret(text):
    """Narrowing the patterns must not have cost us the actual threat."""
    classes, _redacted, _counts, _hash = classify_request([{"role": "user", "content": text}])

    assert "secret" in classes, f"missed secret in {text!r}"


@pytest.mark.parametrize(
    "text",
    [
        "max_tokens=max_tokens",
        "api_key: Optional[str] = None",
        "return client.chat.completions.create(api_key=api_key)",
        "session_store_max_age_days = 30",
        "skipped_nonspawnable, skill_matches_platform, skip_tool_request_middleware",
    ],
)
def test_identifier_shaped_code_is_not_a_secret(text):
    classes, _redacted, counts, _hash = classify_request([{"role": "user", "content": text}])

    assert "secret" not in classes, f"{text!r} misread as a secret via {counts}"


# ---------------------------------------------------------------------------
# End-to-end: the guarantee is "nothing left the process", not "a function
# raised".  These drive the real conversation loop against a fake provider
# client and assert the client was never called.
# ---------------------------------------------------------------------------


class _RecordingCompletions:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="done", reasoning=None, tool_calls=[]),
                    finish_reason="stop",
                )
            ],
            usage=None,
        )


class _RecordingClient:
    def __init__(self):
        self.chat = SimpleNamespace(completions=_RecordingCompletions())


def _local_agent(monkeypatch, client):
    import run_agent

    monkeypatch.setattr("run_agent.OpenAI", lambda **kwargs: client)
    agent = run_agent.AIAgent(
        model="test-model",
        api_key="test-key",
        base_url="http://localhost:8080/v1",
        platform="cli",
        max_iterations=2,
        quiet_mode=True,
        skip_memory=True,
    )
    agent._disable_streaming = True
    return agent


def test_gate_failure_blocks_the_actual_send(monkeypatch, tmp_path):
    """If the gate cannot evaluate, the provider must never be called."""
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "get_hermes_home", lambda: str(tmp_path))
    monkeypatch.setattr(gate, "classify_request", _explode)

    client = _RecordingClient()
    agent_obj = _local_agent(monkeypatch, client)

    result = agent_obj.run_conversation("read the file")

    assert client.chat.completions.calls == 0, "request reached the local provider"
    assert result["failed"] is True
    assert result["completed"] is False
    assert "could not evaluate" in result["final_response"]


def test_ordinary_local_turn_still_reaches_the_provider(monkeypatch, tmp_path):
    """The companion guarantee: a benign local turn is not blocked.

    This is the CI regression. Hermes' system prompt embeds AGENTS.md, and the
    first cut of the gate classified that as client/production/trading and
    denied the send, so `test (1)` failed on an unrelated test.
    """
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "get_hermes_home", lambda: str(tmp_path))

    client = _RecordingClient()
    agent_obj = _local_agent(monkeypatch, client)

    result = agent_obj.run_conversation("read the file")

    assert client.chat.completions.calls >= 1, "benign local turn was blocked"
    assert str(result["final_response"]).startswith("done")
