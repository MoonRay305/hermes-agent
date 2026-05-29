import json

import pytest

from agent.local_provider_sensitivity_gate import (
    LocalProviderSensitivityBlocked,
    assert_local_provider_request_allowed,
    classify_request,
    evaluate_local_provider_request,
    is_local_provider_route,
)


def test_ollama_doogie_private_data_is_blocked_without_approved_route(tmp_path, monkeypatch):
    import agent.local_provider_sensitivity_gate as gate

    monkeypatch.setattr(gate, "get_hermes_home", lambda: str(tmp_path))
    messages = [
        {
            "role": "user",
            "content": (
                "Summarize Doogie's veterinary medication notes and use "
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
    assert "Doogie's veterinary medication notes" not in err
    assert "REDACTMEVALUE1234567890" not in err
    decision = excinfo.value.decision
    assert decision.allowed is False
    assert decision.local_route is True
    assert {"doogie", "private", "secret", "production"}.issubset(set(decision.data_classes))
    assert decision.redaction_counts["api_key_assignment"] == 1

    audit_path = tmp_path / "logs" / "local_provider_sensitivity_gate.jsonl"
    logged = audit_path.read_text()
    assert "REDACTMEVALUE1234567890" not in logged
    assert "Doogie's veterinary medication notes" not in logged
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
        messages=[{"role": "user", "content": "Doogie medication summary for private care notes"}],
        config={
            "worker_contract": {
                "data_class": "doogie",
                "allowed_model_routes": [
                    {
                        "provider": "ollama",
                        "base_url": "http://127.0.0.1:11434/v1",
                        "model": "llama3.2",
                        "data_classes": ["doogie", "private"],
                        "approved": True,
                        "approval_id": "unit-test-route",
                    }
                ],
            }
        },
    )

    assert decision.allowed is True
    assert decision.approved_route is True
    assert decision.route_approval_id == "unit-test-route"
    assert set(decision.data_classes) >= {"doogie", "private"}


def test_approved_route_must_cover_detected_classes():
    decision = evaluate_local_provider_request(
        provider="ollama",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        messages=[{"role": "user", "content": "Review lawsuit notes for a client contract dispute"}],
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


def test_non_local_route_is_not_blocked_by_local_gate():
    decision = evaluate_local_provider_request(
        provider="openrouter",
        base_url="https://openrouter.ai/api/v1",
        model="anthropic/claude-sonnet-4",
        messages=[{"role": "user", "content": "Doogie medication notes"}],
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
