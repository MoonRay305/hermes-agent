"""``hermes approvals`` subcommand handlers.

``hermes approvals coverage`` renders the per-profile approval-gate coverage
report produced by ``tools.approval_coverage`` — which operation classes the
dangerous-command interlock actually gates in each profile, generated from
the real detectors and each profile's own config instead of hand-derived
(BUI-1100).
"""

from __future__ import annotations

import json
import sys


_STATUS_ICON = {"full": "✔", "partial": "◐", "none": "✘"}
_STATUS_WORD = {"full": "gates", "partial": "partial", "none": "ungated"}


def _load_extra_classes(path: str) -> list[dict]:
    """Load user-supplied operation classes from a YAML or JSON file.

    Expected shape: a list of ``{name: str, commands: [str, ...]}`` entries
    (either bare or under a top-level ``classes:`` key). Raises ValueError
    with a readable message on a malformed file.
    """
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if isinstance(data, dict):
        data = data.get("classes")
    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a list of {{name, commands}} entries "
            "(optionally under a top-level 'classes:' key)"
        )
    classes = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict) or not entry.get("name") \
                or not isinstance(entry.get("commands"), list):
            raise ValueError(
                f"{path}: entry {i} must be a mapping with 'name' and a "
                "'commands' list"
            )
        classes.append({
            "name": str(entry["name"]),
            "commands": [str(c) for c in entry["commands"]],
        })
    return classes


def _render_exemplar_line(exemplar: dict) -> str:
    """One-line explanation of why an exemplar does not gate."""
    outcome = exemplar["outcome"]
    command = exemplar["command"]
    if outcome == "ungated":
        return f"'{command}' — no detector matches"
    if outcome == "bypass":
        reason = exemplar.get("reason", "bypass")
        detail = exemplar.get("detail")
        suffix = f" [{detail}]" if detail else ""
        return f"'{command}' — bypass: {reason}{suffix}"
    return f"'{command}' — {outcome}"


def cmd_approvals_coverage(args) -> int:
    """Run the coverage report. Returns a process exit code."""
    from tools.approval_coverage import (
        BUILTIN_OPERATION_CLASSES,
        evaluate_all_profiles,
    )

    operation_classes = list(BUILTIN_OPERATION_CLASSES)
    classes_file = getattr(args, "classes_file", None)
    if classes_file:
        try:
            operation_classes.extend(_load_extra_classes(classes_file))
        except Exception as exc:
            print(f"✗ Could not load --classes-file: {exc}", file=sys.stderr)
            return 1

    profile_filter = getattr(args, "profile", None) or None
    report = evaluate_all_profiles(
        operation_classes=operation_classes,
        profile_filter=profile_filter,
    )

    if not report["profiles"]:
        if profile_filter:
            print(f"✗ No profiles matched: {', '.join(profile_filter)}",
                  file=sys.stderr)
            return 1
        print("✗ No profiles found (is Hermes set up on this machine?)",
              file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    n_profiles = len(report["profiles"])
    n_classes = len(report["operation_classes"])
    print(f"Approval-gate coverage — {n_classes} operation classes × "
          f"{n_profiles} profile(s)")
    print("Static pattern + config layer (hardline, deny rules, mode, "
          "command_allowlist, detectors).")
    print("Tirith runtime content scanning and session-scoped state "
          "(/yolo, session grants) are NOT simulated.\n")

    # Cross-profile rollup — the generated audit table.
    width = max(len(s["class"]) for s in report["summary"]) + 2
    print("SUMMARY (profiles where the class fully gates)")
    for s in report["summary"]:
        icon = ("✔" if s["profiles_full"] == s["profiles_total"]
                else ("✘" if s["profiles_full"] == 0 else "◐"))
        extra = ""
        if s["profiles_partial"]:
            extra = f" (+{s['profiles_partial']} partial)"
        print(f"  {icon} {s['class']:<{width}} "
              f"{s['profiles_full']}/{s['profiles_total']}{extra}")
    print()

    for profile in report["profiles"]:
        header = (f"Profile: {profile['profile']}  "
                  f"[mode={profile['approvals_mode']}, "
                  f"allowlist={profile['allowlist_size']} entries, "
                  f"deny={profile['deny_rules']} rules]")
        print(header)
        if profile.get("config_error"):
            print(f"  ! config unreadable: {profile['config_error']}")
        for cls in profile["classes"]:
            icon = _STATUS_ICON[cls["status"]]
            word = _STATUS_WORD[cls["status"]]
            print(f"  {icon} {cls['class']:<{width}} {word:<8} "
                  f"({cls['gated_exemplars']}/{cls['total_exemplars']} "
                  f"exemplars gate)")
            if cls["status"] != "full" or getattr(args, "verbose", False):
                for exemplar in cls["exemplars"]:
                    if not exemplar["gates"] or getattr(args, "verbose", False):
                        print(f"      {_render_exemplar_line(exemplar)}")
        print()

    return 0


def cmd_approvals(args) -> int:
    """Dispatch ``hermes approvals <subcmd>``."""
    sub = getattr(args, "approvals_command", None)
    if sub in ("coverage", None):
        return cmd_approvals_coverage(args)
    print(f"unknown approvals subcommand: {sub}", file=sys.stderr)
    return 2
