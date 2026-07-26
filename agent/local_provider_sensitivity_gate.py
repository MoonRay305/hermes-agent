"""Pre-send sensitivity guard for local OpenAI-compatible providers.

Local providers (Ollama, LM Studio, llama.cpp, localhost/private-IP custom
endpoints) are useful for speed and cost, but they do not automatically inherit
Hermes' cloud-provider contractual/privacy boundary.  This module classifies the
outbound request just before the API call and blocks sensitive/private data from
leaving the process unless the active worker contract/config explicitly approves
that local route for the observed data classes.

The guard intentionally logs only hashes/counts/classes.  It never emits raw
message text, matched snippets, or secret values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from hermes_cli.config import get_hermes_home, load_config

logger = logging.getLogger(__name__)

LOCAL_PROVIDER_IDS = frozenset({
    "ollama",
    "ollama-cloud-local",
    "lmstudio",
    "lm-studio",
    "llama-cpp",
    "llamacpp",
    "local",
    "jan",
    "kobold",
    "text-generation-webui",
})

DEFAULT_SENSITIVE_CLASSES = frozenset({
    "client",
    "legal",
    "financial",
    "trading",
    "personal_health",
    "production",
    "private",
    "secret",
})

_PUBLIC_CLASSES = frozenset({"public", "internal"})
_CANONICAL_AUDIT_CLASSES = DEFAULT_SENSITIVE_CLASSES | _PUBLIC_CLASSES | frozenset({
    "medical_private",
    "private_subject",
})
_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}



@dataclass(frozen=True)
class PatternDef:
    name: str
    regex: re.Pattern[str]
    data_classes: tuple[str, ...]
    replacement: str


@dataclass
class SensitivityDecision:
    allowed: bool
    local_route: bool
    provider: str
    model: str
    base_url_host: str
    data_classes: list[str] = field(default_factory=list)
    declared_data_class: str | None = None
    reason: str = ""
    approved_route: bool = False
    request_sha256: str = ""
    redaction_counts: dict[str, int] = field(default_factory=dict)
    route_approval_id: str | None = None

    def audit_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "event": "local_provider_sensitivity_gate",
            "decision": "allow" if self.allowed else "deny",
            "local_route": self.local_route,
            "provider": self.provider,
            "model": self.model,
            "base_url_host": self.base_url_host,
            "data_classes": self.data_classes,
            "declared_data_class": self.declared_data_class,
            "approved_route": self.approved_route,
            "request_sha256": self.request_sha256,
            "redaction_counts": self.redaction_counts,
            "reason": self.reason,
        }
        if self.route_approval_id:
            payload["route_approval_id"] = self.route_approval_id
        return payload


class LocalProviderSensitivityBlocked(RuntimeError):
    """Raised when a local provider request carries unapproved sensitive data."""

    def __init__(self, decision: SensitivityDecision):
        self.decision = decision
        where = (
            f"sent to {decision.provider or 'local provider'} "
            f"({decision.base_url_host or 'unknown host'})"
        )
        if decision.reason == "gate_evaluation_failed":
            super().__init__(
                "Local provider sensitivity gate could not evaluate this request "
                f"before it was {where}, so the send was blocked. The gate fails "
                "closed: an unreadable payload is treated as sensitive. See the "
                "agent log for the failure type. No raw prompt text or secret "
                "values were logged."
            )
            return
        if decision.reason == "no_declared_data_class":
            super().__init__(
                "Local provider sensitivity gate blocked this request before it "
                f"was {where}. This deployment sets "
                "local_provider_sensitivity.require_declared_data_class, so a "
                "local route needs an explicit data class: set HERMES_DATA_CLASS "
                "or worker_contract.data_class. Content matching alone is not "
                "accepted here. No raw prompt text or secret values were logged."
            )
            return
        classes = ", ".join(decision.data_classes) or "sensitive"
        super().__init__(
            "Local provider sensitivity gate blocked this request before it was "
            f"{where}. "
            f"Observed data classes: {classes}. Attach an approved worker "
            "contract/local_provider_sensitivity.approved_routes entry for this "
            "provider/model/base_url before routing sensitive/private data to a "
            "local endpoint. No raw prompt text or secret values were logged."
        )


PATTERNS: tuple[PatternDef, ...] = (
    PatternDef(
        "private_key_block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.I | re.S),
        ("secret", "production"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    PatternDef(
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I),
        ("secret", "production"),
        "Bearer [REDACTED]",
    ),
    PatternDef(
        # Matches a secret-ish NAME bound to a secret-ish VALUE.  The value
        # constraint is what makes this usable: the original pattern accepted
        # any 8+ non-space characters, so ordinary Python — `max_tokens=max_tokens`,
        # `api_key: Optional[str]`, `api_key=api_key)` — read as a leaked
        # credential (1,389 hits across this repo's own source).  A quoted
        # value must be >=12 chars; an unquoted value must be >=20 chars drawn
        # from a key charset, which no short identifier satisfies.
        "api_key_assignment",
        re.compile(
            r"(?i)\b([A-Z0-9_\-]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|"
            r"PRIVATE[_-]?KEY|WEBHOOK[_-]?URL|DATABASE[_-]?URL|DSN)[A-Z0-9_\-]*)\b"
            r"\s*[:=]\s*"
            r"(?:"
            r"(['\"])[^\s'\"]{12,}\2"
            r"|"
            # Unquoted (.env-style) value.  Single-case snake_case is excluded:
            # `session_completion_tokens = skipped_nonspawnable` is code, and a
            # generated credential is essentially never pure lower/UPPER snake.
            r"(?!(?-i:(?:[a-z0-9]+_)+[a-z0-9]+)(?:[\s,;)\]}]|$))"
            r"(?!(?-i:(?:[A-Z0-9]+_)+[A-Z0-9]+)(?:[\s,;)\]}]|$))"
            r"[A-Za-z0-9+/=_\-.]{20,}(?=[\s,;)\]}]|$)"
            r")"
        ),
        ("secret", "production"),
        "\\1=[REDACTED]",
    ),
    PatternDef(
        # Provider token shapes.  The separator is mandatory and the match is
        # case-sensitive: with `-?` optional and re.I, the prefixes swallowed
        # ordinary snake_case identifiers (`skill_matches_platform`,
        # `session_completion_tokens`, `skipped_nonspawnable` — 126 hits here).
        # Real tokens always carry their separator.
        "openai_like_token",
        re.compile(
            r"\b(?:"
            r"(?:sk|pk|rk|sess)-[A-Za-z0-9_-]{20,}"
            r"|gh[pousr]_[A-Za-z0-9]{30,}"
            r"|github_pat_[A-Za-z0-9_]{40,}"
            r"|xox[baprs]-[A-Za-z0-9-]{12,}"
            r")\b"
        ),
        ("secret", "production"),
        "[REDACTED_TOKEN]",
    ),
    PatternDef(
        "aws_access_key",
        re.compile(r"\bA(?:KIA|SIA|GPA|IDA)[A-Z0-9]{16}\b"),
        ("secret", "production"),
        "[REDACTED_AWS_KEY]",
    ),
    PatternDef(
        "connection_string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+", re.I),
        ("secret", "production"),
        "[REDACTED_CONNECTION_STRING]",
    ),
    # --- Topical classes -------------------------------------------------
    #
    # These are deliberately phrase-anchored rather than single-token.  The
    # first cut of this gate matched bare words (``client``, ``production``,
    # ``options``, ``futures``, ``symptom``, ``privileged``) and therefore
    # fired on ordinary engineering prose — Hermes' own system prompt embeds
    # AGENTS.md, which says "MCP client", "npm start # production",
    # "reproduces the symptom" and "config.yaml options".  That made every
    # local-provider request classify as client/production/trading/
    # personal_health and blocked the local route outright.  A gate that
    # denies 100% of traffic is not a gate; it is an outage, and it trains
    # operators to switch it off, which is strictly worse than not shipping
    # it.  Each token below must be one that does not occur in routine
    # source code or developer documentation.
    #
    # Content matching is a backstop.  The authoritative signal is the
    # operator-declared data class (HERMES_DATA_CLASS, or
    # worker_contract.data_class), which is applied regardless of what the
    # text scan finds — see _declared_data_class().
    PatternDef(
        "legal",
        re.compile(
            r"\b(?:attorney[- ]client\s+privilege|legally\s+privileged|lawsuit|litigation|"
            r"legal\s+hold|contract\s+dispute|opposing\s+counsel|settlement\s+agreement)\b",
            re.I,
        ),
        ("legal",),
        "[LEGAL_TERM]",
    ),
    PatternDef(
        "financial",
        re.compile(
            r"\b(?:routing\s+number|account\s+number|wire\s+transfer|bank\s+account|"
            r"payroll|tax\s+return|credit\s+card|form\s+1099|1099-(?:MISC|NEC|K)|"
            r"w-9\s+form|invoice\s+(?:number|total|amount))\b",
            re.I,
        ),
        ("financial",),
        "[FINANCIAL_TERM]",
    ),
    PatternDef(
        "trading",
        re.compile(
            r"\b(?:trading\s+(?:account|desk|strategy)|trade\s+order|market\s+order|"
            r"limit\s+order|stop\s+loss|brokerage|coinbase|\bIBKR\b|"
            r"portfolio\s+(?:balance|holdings|value|positions))\b",
            re.I,
        ),
        ("trading",),
        "[TRADING_TERM]",
    ),
    PatternDef(
        "personal_health",
        re.compile(
            r"\b(?:veterinary|vet\s+visit|medication|lab\s+result|medical\s+record|"
            r"medical\s+diagnosis|patient\s+(?:record|chart|history))\b",
            re.I,
        ),
        ("personal_health", "private"),
        "[PRIVATE_TERM]",
    ),
    PatternDef(
        "client",
        re.compile(
            r"\b(?:client\s+(?:file|data|record|matter|engagement)|"
            r"customer\s+(?:data|record|list|pii)|statement\s+of\s+work)\b",
            re.I,
        ),
        ("client",),
        "[CLIENT_TERM]",
    ),
    PatternDef(
        # Case-sensitive: SOW/MSA/NDA as bare lowercase words are too common
        # ("sow" the verb, "nda" inside identifiers) to be evidence.
        "legal_doc_acronym",
        re.compile(r"\b(?:SOW|MSA|NDA)\b"),
        ("legal", "client"),
        "[LEGAL_TERM]",
    ),
    # --- High-signal bare tokens -----------------------------------------
    #
    # Phrase anchoring alone leaves real gaps: "counsel advised against it"
    # and "pull the invoice" carry the same exposure as the phrases above but
    # match nothing.  These are the bare tokens that survived measurement.
    #
    # The test each one had to pass: zero occurrences in AGENTS.md — which is
    # embedded verbatim into Hermes' system prompt, so a token appearing there
    # denies *every* local turn — and near-zero occurrence across this repo's
    # 5,782-file corpus.  Measured hits (corpus files / AGENTS.md):
    #
    #     counsel      2 /0     invoice   8 /0     subpoena   0 /0
    #     malpractice  0 /0     prognosis 0 /0     retainer   0 /0
    #
    # and the `counsel`/`invoice` corpus hits are this module and docs prose.
    #
    # Deliberately NOT restored, with their measurements, so this is not
    # re-litigated from intuition later:
    #
    #     client     904 files / 4 in AGENTS.md      production 407 / 1
    #     options    415 / 1                         symptom     90 / 2
    #     futures     93 / 0  (`concurrent.futures`) privileged  32 / 0
    #     diagnosis   26 / 0  ("diagnosis" of a bug, in troubleshooting docs)
    #
    # The first four appear in the system prompt itself and would restore the
    # 100%-denial outage this gate was remediated for.  `futures` is a stdlib
    # module name, `privileged` is container-security vocabulary, and bare
    # `diagnosis` is ordinary debugging prose; `medical diagnosis` is already
    # covered as a phrase above.
    PatternDef(
        "legal_bare_token",
        re.compile(r"\b(?:counsel|subpoena|malpractice|disbarment|deposed)\b", re.I),
        ("legal",),
        "[LEGAL_TERM]",
    ),
    PatternDef(
        "financial_bare_token",
        re.compile(r"\b(?:invoice|invoices|invoiced|remittance|garnishment)\b", re.I),
        ("financial",),
        "[FINANCIAL_TERM]",
    ),
    PatternDef(
        "personal_health_bare_token",
        re.compile(r"\b(?:prognosis|comorbidity|immunization)\b", re.I),
        ("personal_health", "private"),
        "[PRIVATE_TERM]",
    ),
    PatternDef(
        "production",
        re.compile(
            r"\b(?:prod(?:uction)?\s+(?:database|db|credentials|secrets?)|"
            r"kubernetes\s+secret|deploy\s+key|live\s+credentials|root\s+password)\b",
            re.I,
        ),
        ("production",),
        "[PRODUCTION_TERM]",
    ),
)


def _normalize_provider(provider: Any) -> str:
    value = str(provider or "").strip().lower()
    if value.startswith("custom:"):
        value = value.split(":", 1)[1].strip().lower()
    return value


def _host_from_base_url(base_url: Any) -> str:
    value = str(base_url or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"http://{value}")
    return (parsed.hostname or "").strip().lower().strip("[]")


def is_local_provider_route(provider: Any, base_url: Any) -> bool:
    """Return True when the route terminates at a local/private endpoint.

    Total by construction: an unparseable provider/base_url yields ``True``
    (assume local), because the caller uses this answer to decide whether the
    gate has jurisdiction.  Guessing "not local" on an input we failed to
    understand would silently disable the gate — the exact fail-open this
    module exists to prevent.
    """
    try:
        provider_id = _normalize_provider(provider)
        if provider_id in LOCAL_PROVIDER_IDS:
            return True

        host = _host_from_base_url(base_url)
        if not host:
            return False
        if host in {"localhost", "0.0.0.0"} or host.endswith(".localhost") or host.endswith(".local"):
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local)
    except Exception:
        logger.warning(
            "local_provider_sensitivity_gate: route classification failed; "
            "treating the route as local so the gate still applies"
        )
        return True


def _message_text(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, bytes):
        try:
            yield value.decode("utf-8", "replace")
        except Exception:
            return
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"content", "text", "input", "arguments", "name", "role", "tool_call_id"}:
                yield from _message_text(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _message_text(item)
        return


def _canonical_request_text(messages: Any) -> str:
    return "\n".join(part for part in _message_text(messages) if part)


def classify_request(messages: Any, *, declared_data_class: str | None = None) -> tuple[list[str], str, dict[str, int], str]:
    """Classify outbound messages and return classes/redacted/counts/hash.

    The returned redacted string is intended for tests/debugging only. Callers
    should log ``request_sha256`` and ``redaction_counts`` instead of the text.
    """
    text = _canonical_request_text(messages)
    redacted = text
    counts: dict[str, int] = {}
    classes: set[str] = set()

    if declared_data_class:
        normalized = _normalize_class(declared_data_class)
        if normalized:
            classes.add(normalized)

    for pattern in PATTERNS:
        matches = list(pattern.regex.finditer(redacted))
        if not matches:
            continue
        counts[pattern.name] = len(matches)
        classes.update(pattern.data_classes)
        redacted = pattern.regex.sub(pattern.replacement, redacted)

    request_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return sorted(classes), redacted, counts, request_hash


def _normalize_class(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "customer": "client",
        "customers": "client",
        "legal_privileged": "legal",
        "finance": "financial",
        "payment": "financial",
        "payments": "financial",
        "prod": "production",
        "credential": "secret",
        "credentials": "secret",
        "secrets": "secret",
        "pii": "private",
        "personal": "private",
        "health": "personal_health",
        "medical": "personal_health",
        "medical_record": "personal_health",
    }
    return aliases.get(normalized, normalized)


def _sanitize_data_class(value: Any) -> str:
    normalized = _normalize_class(value)
    if not normalized:
        return ""
    if normalized in _CANONICAL_AUDIT_CLASSES:
        return normalized
    if any(token in normalized for token in ("health", "medical", "patient", "vet", "care")):
        return "personal_health"
    if any(token in normalized for token in ("subject", "person", "profile", "name", "lane")):
        return "private_subject"
    return "private_subject"


def _sanitize_data_classes(values: Iterable[Any]) -> list[str]:
    return sorted({sanitized for value in values if (sanitized := _sanitize_data_class(value))})


def _sanitize_approval_id(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _declared_data_class(config: dict[str, Any]) -> str | None:
    env_value = os.getenv("HERMES_DATA_CLASS") or os.getenv("HERMES_WORKER_DATA_CLASS")
    if env_value:
        return _normalize_class(env_value)

    sections = [
        config.get("worker_contract") if isinstance(config, dict) else None,
        config.get("local_provider_sensitivity") if isinstance(config, dict) else None,
        config.get("data_routing") if isinstance(config, dict) else None,
    ]
    for section in sections:
        if not isinstance(section, dict):
            continue
        for key in ("data_class", "classification", "dataClass"):
            if section.get(key):
                return _normalize_class(section[key])
    return None


def _sensitive_classes(config: dict[str, Any]) -> set[str]:
    section = config.get("local_provider_sensitivity") if isinstance(config, dict) else None
    if isinstance(section, dict) and isinstance(section.get("sensitive_classes"), list):
        configured = {_normalize_class(v) for v in section["sensitive_classes"]}
        configured = {v for v in configured if v}
        if configured:
            return configured
    return set(DEFAULT_SENSITIVE_CLASSES)


def _require_declared_data_class(config: dict[str, Any]) -> bool:
    """Opt-in strict mode: a local route with no declared data class denies.

    Off by default, and that default is a deliberate trade rather than an
    oversight.  Nothing in Hermes *produces* a declaration — it is operator
    input (``HERMES_DATA_CLASS`` or a config section), so defaulting this on
    would deny 100% of local-provider traffic on a stock install, which is the
    outage this gate was remediated for.  Operators who genuinely route
    regulated work to a local endpoint need a way to demand the strong
    guarantee rather than the content backstop, and this is it.
    """
    env = os.getenv("HERMES_REQUIRE_DECLARED_DATA_CLASS", "").strip().lower()
    if env in _TRUTHY:
        return True
    if env in _FALSEY:
        return False
    section = config.get("local_provider_sensitivity") if isinstance(config, dict) else None
    if isinstance(section, dict) and "require_declared_data_class" in section:
        return bool(section.get("require_declared_data_class"))
    return False


def _enabled(config: dict[str, Any]) -> bool:
    env = os.getenv("HERMES_LOCAL_PROVIDER_SENSITIVITY_GATE", "").strip().lower()
    if env in _FALSEY:
        return False
    if env in _TRUTHY:
        return True
    section = config.get("local_provider_sensitivity") if isinstance(config, dict) else None
    if isinstance(section, dict) and "enabled" in section:
        return bool(section.get("enabled"))
    return True


def _approved_routes(config: dict[str, Any]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    section = config.get("local_provider_sensitivity") if isinstance(config, dict) else None
    if isinstance(section, dict) and isinstance(section.get("approved_routes"), list):
        routes.extend(r for r in section["approved_routes"] if isinstance(r, dict))

    contract = config.get("worker_contract") if isinstance(config, dict) else None
    if isinstance(contract, dict):
        for key in ("allowed_model_routes", "approved_routes", "allowed_routes"):
            value = contract.get(key)
            if isinstance(value, list):
                routes.extend(r for r in value if isinstance(r, dict))
    return routes


def _url_matches(route_url: Any, actual_url: Any) -> bool:
    expected = str(route_url or "").strip().rstrip("/").lower()
    if not expected:
        return True
    actual = str(actual_url or "").strip().rstrip("/").lower()
    if not actual:
        return False
    return expected == actual


def _matches_route(route: dict[str, Any], *, provider: str, base_url: str, model: str, classes: set[str]) -> bool:
    if route.get("approved") is False:
        return False

    route_provider = _normalize_provider(route.get("provider") or route.get("provider_id"))
    if route_provider and route_provider not in {"*", provider}:
        return False

    route_model = str(route.get("model") or route.get("model_name") or "").strip().lower()
    if route_model and route_model not in {"*", (model or "").strip().lower()}:
        return False

    route_url = route.get("base_url") or route.get("url") or route.get("endpoint")
    if route_url and not _url_matches(route_url, base_url):
        return False

    declared = route.get("data_classes") or route.get("allowed_data_classes") or route.get("data_class")
    if isinstance(declared, str):
        route_classes = {_normalize_class(v) for v in re.split(r"[,\s]+", declared) if v.strip()}
    elif isinstance(declared, (list, tuple, set)):
        route_classes = {_normalize_class(v) for v in declared}
    else:
        route_classes = set()
    route_classes = {v for v in route_classes if v}
    if classes and not route_classes:
        return False
    if route_classes and "*" not in route_classes and "all" not in route_classes:
        if not classes.issubset(route_classes):
            return False

    return True


def _find_approved_route(config: dict[str, Any], *, provider: str, base_url: str, model: str, classes: set[str]) -> dict[str, Any] | None:
    for route in _approved_routes(config):
        if _matches_route(route, provider=provider, base_url=base_url, model=model, classes=classes):
            return route
    return None


def _write_audit(decision: SensitivityDecision) -> None:
    payload = decision.audit_payload()
    payload["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        logs_dir = Path(get_hermes_home()) / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        path = logs_dir / "local_provider_sensitivity_gate.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    except Exception as exc:
        logger.debug("Could not write local provider sensitivity audit log: %s", exc)

    # Central log visibility for cockpit/guardrail dashboards.  Payload is
    # intentionally raw-text-free.
    log_fn = logger.warning if not decision.allowed else logger.info
    log_fn("local_provider_sensitivity_gate %s", json.dumps(payload, sort_keys=True))


def _evaluate_local_provider_request_unguarded(
    *,
    provider: Any,
    base_url: Any,
    model: Any,
    messages: Any,
    config: dict[str, Any] | None = None,
) -> SensitivityDecision:
    if config is None:
        # Deliberately unguarded.  A config we cannot read is an *evaluation
        # failure*, not an empty policy: substituting {} here would silently
        # disable the enable-flag, the sensitive-class set and every approved
        # route, then classify the payload against that empty policy and
        # return a normal `no_sensitive_classes_detected` allow.  Letting this
        # raise hands the decision to the fail-closed wrapper, which denies
        # local routes with reason="gate_evaluation_failed".
        config = load_config() or {}

    provider_id = _normalize_provider(provider)
    base_url_str = str(base_url or "")
    model_str = str(model or "")
    host = _host_from_base_url(base_url_str)
    local_route = is_local_provider_route(provider_id, base_url_str)
    declared = _declared_data_class(config)
    classes, _redacted, counts, request_hash = classify_request(messages, declared_data_class=declared)
    observed_classes = {_normalize_class(c) for c in classes if _normalize_class(c)}
    sensitive = observed_classes & _sensitive_classes(config)
    audit_classes = _sanitize_data_classes(observed_classes)
    audit_declared = _sanitize_data_class(declared) if declared else None

    if not _enabled(config):
        return SensitivityDecision(
            allowed=True,
            local_route=local_route,
            provider=provider_id,
            model=model_str,
            base_url_host=host,
            data_classes=audit_classes,
            declared_data_class=audit_declared,
            reason="gate_disabled",
            request_sha256=request_hash,
            redaction_counts=counts,
        )

    if not local_route:
        return SensitivityDecision(
            allowed=True,
            local_route=False,
            provider=provider_id,
            model=model_str,
            base_url_host=host,
            data_classes=audit_classes,
            declared_data_class=audit_declared,
            reason="non_local_route",
            request_sha256=request_hash,
            redaction_counts=counts,
        )

    if declared is None and _require_declared_data_class(config):
        # Strict mode: without a declaration the only signal left is the
        # content backstop, and the operator has said that is not good enough
        # for this deployment.  Deny before the backstop gets a vote.
        return SensitivityDecision(
            allowed=False,
            local_route=True,
            provider=provider_id,
            model=model_str,
            base_url_host=host,
            data_classes=audit_classes,
            declared_data_class=None,
            reason="no_declared_data_class",
            request_sha256=request_hash,
            redaction_counts=counts,
        )

    if not sensitive or observed_classes <= _PUBLIC_CLASSES:
        decision = SensitivityDecision(
            allowed=True,
            local_route=True,
            provider=provider_id,
            model=model_str,
            base_url_host=host,
            data_classes=audit_classes,
            declared_data_class=audit_declared,
            reason="no_sensitive_classes_detected",
            request_sha256=request_hash,
            redaction_counts=counts,
        )
        return decision

    approved = _find_approved_route(
        config,
        provider=provider_id,
        base_url=base_url_str,
        model=model_str,
        classes=sensitive,
    )
    if approved:
        return SensitivityDecision(
            allowed=True,
            local_route=True,
            provider=provider_id,
            model=model_str,
            base_url_host=host,
            data_classes=audit_classes,
            declared_data_class=audit_declared,
            reason="approved_local_sensitive_route",
            approved_route=True,
            route_approval_id=_sanitize_approval_id(approved.get("approval_id") or approved.get("id")),
            request_sha256=request_hash,
            redaction_counts=counts,
        )

    return SensitivityDecision(
        allowed=False,
        local_route=True,
        provider=provider_id,
        model=model_str,
        base_url_host=host,
        data_classes=audit_classes,
        declared_data_class=audit_declared,
        reason="unapproved_sensitive_local_route",
        request_sha256=request_hash,
        redaction_counts=counts,
    )


def evaluate_local_provider_request(
    *,
    provider: Any,
    base_url: Any,
    model: Any,
    messages: Any,
    config: dict[str, Any] | None = None,
) -> SensitivityDecision:
    """Classify an outbound request and decide whether it may be sent.

    Fail-closed wrapper.  If the evaluation itself raises for any reason —
    malformed config, an unexpected message shape, a regex or filesystem
    failure — a local route is *denied*.  "The gate crashed" and "the gate
    approved" must never be the same outcome: an exception here means we do
    not know what is in the payload, and an unknown payload does not get to
    leave the process over a local route.

    Non-local routes are still allowed on internal failure: this gate has no
    jurisdiction over cloud providers, which carry their own contractual
    boundary, and failing those closed would take the agent offline on a bug
    in code that was never meant to govern them.
    """
    try:
        return _evaluate_local_provider_request_unguarded(
            provider=provider,
            base_url=base_url,
            model=model,
            messages=messages,
            config=config,
        )
    except Exception as exc:
        local_route = is_local_provider_route(provider, base_url)
        logger.warning(
            "local_provider_sensitivity_gate: evaluation failed (%s); "
            "%s. No raw prompt text was logged.",
            type(exc).__name__,
            "denying the local route (fail closed)" if local_route
            else "allowing the non-local route (gate has no jurisdiction)",
        )
        try:
            host = _host_from_base_url(base_url)
        except Exception:
            host = ""
        return SensitivityDecision(
            allowed=not local_route,
            local_route=local_route,
            provider=_normalize_provider(provider) if isinstance(provider, str) else "",
            model=str(model or ""),
            base_url_host=host,
            data_classes=[],
            declared_data_class=None,
            reason="gate_evaluation_failed",
        )


def assert_local_provider_request_allowed(**kwargs: Any) -> SensitivityDecision:
    decision = evaluate_local_provider_request(**kwargs)
    if decision.local_route and (decision.redaction_counts or decision.data_classes or not decision.allowed):
        # Audit writing must never be able to turn a deny into a send.
        try:
            _write_audit(decision)
        except Exception as exc:  # pragma: no cover - _write_audit is already defensive
            logger.debug("local provider sensitivity audit write failed: %s", exc)
    if not decision.allowed:
        raise LocalProviderSensitivityBlocked(decision)
    return decision
