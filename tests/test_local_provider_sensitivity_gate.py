import json

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
    assert decision.route_approval_id.startswith("sha256:")
    assert "unit-test-route" not in decision.route_approval_id
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
        messages=[{"role": "user", "content": "Review lawsuit notes for a client contract dispute"}],
        config={"local_provider_sensitivity": {"approved_routes": [route]}},
    )

    assert decision.allowed is False
    assert {"client", "legal"}.issubset(set(decision.data_classes))


def test_approved_route_wildcard_class_coverage_is_explicit_and_allowed():
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
