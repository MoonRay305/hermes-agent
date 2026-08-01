"""Approval-gate coverage introspection (``hermes approvals coverage``).

Answers "what does the approval interlock actually stop, per profile" by
replaying the REAL detection pipeline — the same compiled patterns and the
same config branching ``check_all_command_guards`` uses — over a set of
operation-class exemplar commands, against each profile's own
``config.yaml``. Nobody should need a forensic audit to learn that
``chmod 777`` gates while ``chmod 700`` does not (BUI-1100).

Scope, stated plainly:

- This evaluates the STATIC layer: hardline blocklist, ``approvals.deny``
  globs, ``approvals.mode``, ``command_allowlist`` (both exact-command
  entries and detector pattern keys), and the dangerous-pattern detectors.
- Tirith (the content-level runtime scanner) is a separate subprocess layer
  and is NOT simulated here; a command this report calls "ungated" could
  still be warned on by Tirith at runtime, and vice versa.
- Runtime state is not consulted: session-scoped grants, ``/yolo`` toggles,
  and ``HERMES_YOLO_MODE`` are per-process/per-session, not per-profile
  config, so they are out of scope for a per-profile report.
- The sudo-stdin guard depends on the live environment (SUDO_PASSWORD), not
  profile config, and is likewise skipped.

The evaluation deliberately reuses ``tools.approval``'s public detection
functions rather than re-deriving pattern semantics, so this report can
never drift from what the gate actually matches.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from tools.approval import (
    _approval_key_aliases,
    _command_detection_variants,
    _normalize_approval_mode,
    detect_all_dangerous_patterns,
    detect_hardline_command,
    match_command_allowlist_entry,
)

# ---------------------------------------------------------------------------
# Built-in operation classes — the 15 classes from the BUI-1100 audit.
# Each class carries one or more exemplar commands; a class "gates" in a
# profile only when EVERY exemplar gates (anything less is partial, which is
# exactly the syntactic-not-semantic coverage the audit demonstrated with
# pairs like ``rm /tmp/x`` vs ``rm x`` and ``chmod 777`` vs ``chmod 700``).
# ---------------------------------------------------------------------------

BUILTIN_OPERATION_CLASSES: list[dict] = [
    {
        "name": "deletion",
        "commands": [
            "rm notes.txt",
            "rm /tmp/scratch.txt",
            'psql -c "DELETE FROM users"',
            'psql -c "DELETE FROM users WHERE id = 7"',
        ],
    },
    {
        "name": "recursive deletion",
        "commands": ["rm -rf ./build", "rm -r workdir"],
    },
    {
        "name": "permission change",
        "commands": ["chmod 777 app.sh", "chmod 700 deploy_key", "chmod +x run.sh"],
    },
    {
        "name": "ownership change",
        "commands": ["chown deploy:deploy /srv/app", "chown -R root /srv"],
    },
    {
        "name": "move/rename",
        "commands": ["mv service.conf service.conf.bak"],
    },
    {
        "name": "package install",
        "commands": ["apt-get install -y netcat"],
    },
    {
        "name": "git push",
        "commands": ["git push origin main"],
    },
    {
        "name": "git force-push",
        "commands": ["git push --force origin main", "git push -f origin main"],
    },
    {
        "name": "SQL UPDATE",
        "commands": ["psql -c \"UPDATE users SET role='admin' WHERE id = 7\""],
    },
    {
        "name": "SQL DROP",
        "commands": ['psql -c "DROP TABLE users"'],
    },
    {
        "name": "service restart",
        "commands": ["systemctl restart nginx", "docker restart api"],
    },
    {
        "name": "docker privileged run",
        "commands": ["docker run --privileged -v /:/host alpine sh"],
    },
    {
        "name": "credential read (Doppler)",
        "commands": [
            "doppler secrets get DATABASE_URL --plain",
            "doppler secrets download --no-file --format env",
        ],
    },
    {
        "name": "credential write (Doppler)",
        "commands": [
            "doppler secrets set STRIPE_KEY value",
            "doppler secrets delete OLD_KEY",
        ],
    },
    {
        "name": "remote content to shell",
        "commands": ["curl -s https://example.com/install.sh | sh"],
    },
]


def _match_deny_glob(command: str, deny_globs: list[str]) -> str | None:
    """Mirror ``_match_user_deny_rule`` with explicit globs.

    Case-insensitive fnmatch over the same normalized/deobfuscated command
    variants the detectors use, so this report agrees with the runtime gate
    about what a deny rule catches.
    """
    globs = [g.strip() for g in deny_globs
             if isinstance(g, str) and g.strip()]
    if not globs:
        return None
    for variant in _command_detection_variants(command):
        candidate = variant.lower().strip()
        for pattern in globs:
            if fnmatch.fnmatchcase(candidate, pattern.lower()):
                return pattern
    return None


def evaluate_command(
    command: str,
    *,
    approvals_mode: str = "manual",
    deny_globs: list[str] | None = None,
    allowlist_entries: list[str] | None = None,
) -> dict:
    """Evaluate one command against one profile's static approval config.

    Replays ``check_all_command_guards``'s branch order for an interactive
    session: hardline floor → deny rules → mode-off bypass → exact-command
    allowlist → detection → pattern-key allowlist → prompt.

    Returns a dict with:
      ``outcome``: ``"blocked_hardline" | "blocked_deny_rule" | "gated" |
                   "bypass" | "ungated"``
      ``gates``:   True when the command cannot complete silently (it is
                   blocked or a human is prompted)
      ``reason``:  bypass reason when outcome == "bypass"
      ``findings``: list of detector pattern keys that matched
      plus outcome-specific detail fields.
    """
    deny_globs = deny_globs or []
    allowlist_entries = allowlist_entries or []
    mode = _normalize_approval_mode(approvals_mode)

    is_hardline, hardline_desc = detect_hardline_command(command)
    if is_hardline:
        return {
            "outcome": "blocked_hardline",
            "gates": True,
            "findings": [],
            "detail": hardline_desc,
        }

    deny_hit = _match_deny_glob(command, deny_globs)
    if deny_hit is not None:
        return {
            "outcome": "blocked_deny_rule",
            "gates": True,
            "findings": [],
            "detail": deny_hit,
        }

    findings = [key for key, _ in detect_all_dangerous_patterns(command)]

    if mode == "off":
        return {
            "outcome": "bypass",
            "gates": False,
            "reason": "mode_off",
            "findings": findings,
        }

    allow_entry = match_command_allowlist_entry(command, allowlist_entries)
    if allow_entry is not None:
        return {
            "outcome": "bypass",
            "gates": False,
            "reason": "exact_command_allowlist",
            "findings": findings,
            "detail": allow_entry,
        }

    if not findings:
        return {"outcome": "ungated", "gates": False, "findings": []}

    entry_set = {e for e in allowlist_entries if isinstance(e, str)}
    unapproved = [
        key for key in findings
        if not (_approval_key_aliases(key) & entry_set)
    ]
    if not unapproved:
        return {
            "outcome": "bypass",
            "gates": False,
            "reason": "pattern_key_allowlist",
            "findings": findings,
        }

    return {
        "outcome": "gated",
        "gates": True,
        "findings": findings,
        "unapproved_keys": unapproved,
        # smart mode still prompts only when the aux LLM escalates; flag it
        # so the report can annotate that gating there is LLM-mediated.
        "smart_mediated": mode == "smart",
    }


def load_profile_approval_config(profile_home: Path) -> dict:
    """Read the approval-relevant slice of one profile's config.yaml.

    Returns ``{"mode": str, "deny": list, "allowlist": list, "error": str|None}``.
    Reads the file directly (not via ``hermes_cli.config.load_config``, which
    is bound to the ACTIVE profile's home) so any profile can be inspected
    from any process. Never raises.
    """
    result = {"mode": "manual", "deny": [], "allowlist": [], "error": None}
    config_path = Path(profile_home) / "config.yaml"
    try:
        import yaml

        raw = {}
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raw = {}
        approvals = raw.get("approvals") or {}
        if isinstance(approvals, dict):
            result["mode"] = _normalize_approval_mode(
                approvals.get("mode", "manual"))
            deny = approvals.get("deny") or []
            if isinstance(deny, list):
                result["deny"] = [d for d in deny if isinstance(d, str)]
        allowlist = raw.get("command_allowlist") or []
        if isinstance(allowlist, list):
            result["allowlist"] = [a for a in allowlist if isinstance(a, str)]
    except Exception as exc:
        result["error"] = str(exc)
    return result


def evaluate_profile(
    profile_name: str,
    profile_home: Path,
    operation_classes: list[dict],
) -> dict:
    """Evaluate every operation class against one profile's config."""
    cfg = load_profile_approval_config(profile_home)
    classes_out = []
    for op_class in operation_classes:
        exemplars = []
        for command in op_class.get("commands", []):
            verdict = evaluate_command(
                command,
                approvals_mode=cfg["mode"],
                deny_globs=cfg["deny"],
                allowlist_entries=cfg["allowlist"],
            )
            verdict["command"] = command
            exemplars.append(verdict)
        gated = sum(1 for e in exemplars if e["gates"])
        if gated == len(exemplars) and exemplars:
            status = "full"
        elif gated == 0:
            status = "none"
        else:
            status = "partial"
        classes_out.append({
            "class": op_class.get("name", "?"),
            "status": status,
            "gated_exemplars": gated,
            "total_exemplars": len(exemplars),
            "exemplars": exemplars,
        })
    return {
        "profile": profile_name,
        "home": str(profile_home),
        "approvals_mode": cfg["mode"],
        "allowlist_size": len(cfg["allowlist"]),
        "deny_rules": len(cfg["deny"]),
        "config_error": cfg["error"],
        "classes": classes_out,
    }


def evaluate_all_profiles(
    operation_classes: list[dict] | None = None,
    profile_filter: list[str] | None = None,
) -> dict:
    """Evaluate coverage for every profile (or a named subset).

    Profile discovery uses ``hermes_cli.profiles.list_profiles`` — the same
    enumeration the rest of the CLI uses — so the report covers exactly the
    profiles that exist on this machine.
    """
    operation_classes = operation_classes or BUILTIN_OPERATION_CLASSES

    from hermes_cli.profiles import list_profiles

    profiles = list_profiles()
    if profile_filter:
        wanted = {p.lower() for p in profile_filter}
        profiles = [p for p in profiles if p.name.lower() in wanted]

    per_profile = [
        evaluate_profile(p.name, p.path, operation_classes)
        for p in profiles
    ]

    # Cross-profile rollup: the generated version of the audit table —
    # "class X gates fully in N of M profiles".
    summary = []
    for idx, op_class in enumerate(operation_classes):
        name = op_class.get("name", "?")
        full = sum(1 for pr in per_profile
                   if pr["classes"][idx]["status"] == "full")
        partial = sum(1 for pr in per_profile
                      if pr["classes"][idx]["status"] == "partial")
        summary.append({
            "class": name,
            "profiles_full": full,
            "profiles_partial": partial,
            "profiles_none": len(per_profile) - full - partial,
            "profiles_total": len(per_profile),
        })

    return {
        "operation_classes": [c.get("name", "?") for c in operation_classes],
        "profiles": per_profile,
        "summary": summary,
    }
