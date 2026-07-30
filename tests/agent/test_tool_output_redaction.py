"""Final-boundary tool-output redaction contracts.

Every credential-shaped fixture in this file is synthesized locally. None is a
live or previously issued secret.
"""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from agent.redact import (
    ToolOutputRedactionPolicy,
    normalize_tool_output,
    resolve_tool_output_redaction_policy,
)
from agent.tool_dispatch_helpers import make_tool_result_message
from tools.tool_result_storage import (
    _last_retention_sweep,
    maybe_persist_tool_result,
    sweep_expired_results,
)


def _synthetic_jwt() -> str:
    def _part(value):
        encoded = base64.urlsafe_b64encode(json.dumps(value).encode("utf-8"))
        return encoded.decode("ascii").rstrip("=")

    return f"{_part({'alg': 'HS256', 'typ': 'JWT'})}.{_part({'sub': 'synthetic-user'})}.{'S1gN4tUr3' * 4}"


def _synthetic_high_entropy() -> str:
    # Deterministic bytes encoded locally; this is not credential material.
    return base64.urlsafe_b64encode(bytes(range(1, 49))).decode("ascii")


@pytest.mark.parametrize("variant", ["a", "b", "y"])
def test_bcrypt_variants_are_class_labelled(variant):
    literal = f"$2{variant}$12$" + "A" * 53
    result = normalize_tool_output(literal)
    assert result == f"[REDACTED:BCRYPT_2{variant.upper()}]"


def test_bcrypt_grep_regression_redacts_all_matched_lines():
    literals = [
        "$2a$04$" + "A" * 53,
        "$2b$10$" + "B" * 53,
        "$2y$12$" + "C" * 53,
    ]
    grep_output = "\n".join(
        f"src/synthetic_users.py:{line}:{literal}"
        for line, literal in enumerate(literals, start=17)
    )
    result = normalize_tool_output(grep_output)
    assert all(literal not in result for literal in literals)
    assert result.count("[REDACTED:BCRYPT_") == 3
    assert "src/synthetic_users.py:17:" in result


@pytest.mark.parametrize("label", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"])
def test_pem_private_key_blocks_are_redacted(label):
    block = (
        f"-----BEGIN {label}-----\n"
        "U1lOVEhFVElDLU5PVC1LRVktBVEVSSUFM\n"
        f"-----END {label}-----"
    )
    assert normalize_tool_output(block) == "[REDACTED:PEM_PRIVATE_KEY]"


@pytest.mark.parametrize(
    "prefix",
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
)
def test_github_token_prefixes_are_redacted(prefix):
    literal = prefix + ("Synthetic123" * 4)
    result = normalize_tool_output(literal)
    assert literal not in result
    assert result == "[REDACTED:GITHUB_TOKEN]"


def test_jwt_is_redacted():
    literal = _synthetic_jwt()
    assert normalize_tool_output(literal) == "[REDACTED:JWT]"


@pytest.mark.parametrize("prefix", ["AKIA", "ASIA", "AIDA", "AROA"])
def test_aws_access_key_ids_are_redacted(prefix):
    literal = prefix + "SYNTHETIC1234567"
    assert len(literal) == 20
    assert normalize_tool_output(literal) == "[REDACTED:AWS_ACCESS_KEY_ID]"


def test_configured_secret_name_is_resolved_at_runtime_without_a_value_lookup():
    raw_config = {
        "security": {
            "tool_output_redaction": {
                "secret_names": ["deployment_credential"],
            }
        }
    }
    with patch("hermes_cli.config.read_raw_config", return_value=raw_config):
        policy = resolve_tool_output_redaction_policy()
        result = normalize_tool_output(
            'deployment_credential = "synthetic-literal"',
            policy=policy,
        )
    assert result == 'deployment_credential = "[REDACTED:NAME:DEPLOYMENT_CREDENTIAL]"'


def test_generic_high_entropy_uses_configurable_thresholds():
    literal = _synthetic_high_entropy()
    assert normalize_tool_output(literal) == "[REDACTED:HIGH_ENTROPY]"

    policy = ToolOutputRedactionPolicy(
        secret_names=(),
        entropy_min_length=40,
        entropy_floor=7.0,
    )
    assert normalize_tool_output(literal, policy=policy) == literal


def test_redaction_is_idempotent():
    text = (
        "password=synthetic-password\n"
        + "$2b$12$"
        + "D" * 53
        + "\n"
        + _synthetic_jwt()
    )
    once = normalize_tool_output(text)
    assert normalize_tool_output(once) == once


def test_serializer_normalizes_before_returning_to_model():
    literal = "$2b$12$" + "E" * 53
    message = make_tool_result_message(
        "terminal",
        f"src/synthetic_users.py:31:{literal}",
        "call-synthetic",
    )
    assert literal not in message["content"]
    assert "[REDACTED:BCRYPT_2B]" in message["content"]


def test_spill_path_writes_only_normalized_content():
    literal = "$2b$12$" + "F" * 53
    env = MagicMock()
    env.get_temp_dir.return_value = "/tmp"
    env.execute.return_value = {"output": "", "returncode": 0}
    policy = ToolOutputRedactionPolicy(secret_names=())

    result = maybe_persist_tool_result(
        content=f"src/synthetic_users.py:44:{literal}\n" + "ordinary output\n" * 20,
        tool_name="terminal",
        tool_use_id="call-spill-redaction",
        env=env,
        threshold=0,
        redaction_policy=policy,
    )

    spill_write = next(
        call for call in env.execute.call_args_list
        if "stdin_data" in call.kwargs
    )
    persisted = spill_write.kwargs["stdin_data"]
    assert literal not in persisted
    assert "[REDACTED:BCRYPT_2B]" in persisted
    assert literal not in result


def test_retention_sweep_uses_configured_max_age_and_regular_files_only():
    env = MagicMock()
    env.execute.return_value = {"output": "", "returncode": 0}
    _last_retention_sweep.clear()
    assert sweep_expired_results(
        env,
        storage_dir="/tmp/hermes-results",
        max_age_seconds=24 * 60 * 60,
        force=True,
        now=100.0,
    )
    command = env.execute.call_args.args[0]
    assert "find /tmp/hermes-results -maxdepth 1 -type f -mmin +1440 -delete" in command


def test_ordinary_source_code_is_not_mangled():
    source = """\
def calculate_token_count(document):
    api_key_name = "OPENAI_API_KEY"
    max_tokens = 4096
    digest = "sha512-AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789"
    return document, api_key_name, max_tokens, digest
"""
    assert normalize_tool_output(source) == source


def test_ordinary_prose_is_not_mangled():
    prose = (
        "The deployment guide explains how credentials are provisioned, but it "
        "does not print them. The token count and password policy are ordinary "
        "documentation terms, not assignments or credential literals."
    )
    assert normalize_tool_output(prose) == prose


def test_inline_source_map_is_not_mangled():
    source_map = (
        "//# sourceMappingURL=data:application/json;charset=utf-8;base64,"
        + _synthetic_high_entropy()
    )
    assert normalize_tool_output(source_map) == source_map


def test_high_entropy_url_path_is_not_mangled():
    path_segment = _synthetic_high_entropy().rstrip("=")
    url = f"https://github.com/synthetic-org/{path_segment}/module.py#L847"
    assert normalize_tool_output(url) == url


def test_jwt_like_version_string_is_not_mangled():
    text = "artifact eyJnot-json.payload-segment.signature-segment-123 release"
    assert normalize_tool_output(text) == text
