"""``hermes approvals`` subcommand parser.

Follows the extracted-parser pattern (see ``subcommands/security.py``):
the parser lives here, the handler is injected to avoid importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_approvals_parser(subparsers, *, cmd_approvals: Callable) -> None:
    """Attach the ``approvals`` subcommand to ``subparsers``."""
    # =========================================================================
    approvals_parser = subparsers.add_parser(
        "approvals",
        help="Introspect the dangerous-command approval gate",
        description=(
            "Tools for understanding what the command-approval interlock "
            "actually stops. 'coverage' replays the real detectors against "
            "operation-class exemplar commands for every profile's config "
            "and reports which classes gate, which bypass, and which are "
            "not detected at all."
        ),
    )
    approvals_subparsers = approvals_parser.add_subparsers(
        dest="approvals_command",
        metavar="<subcommand>",
    )

    coverage_parser = approvals_subparsers.add_parser(
        "coverage",
        help="Report per-profile approval coverage for operation classes",
        description=(
            "Evaluate operation-class exemplar commands (deletion, "
            "permission change, credential read/write, service restart, …) "
            "against each profile's hardline blocklist, deny rules, "
            "approvals.mode, and command_allowlist, using the same "
            "detection code the live gate runs. Static layer only — Tirith "
            "runtime scanning and session-scoped yolo state are not "
            "simulated."
        ),
    )
    coverage_parser.add_argument(
        "--profile",
        action="append",
        metavar="NAME",
        help="Only evaluate this profile (repeatable; default: all profiles)",
    )
    coverage_parser.add_argument(
        "--classes-file",
        metavar="PATH",
        help=(
            "YAML/JSON file of extra operation classes to evaluate in "
            "addition to the built-in set: a list of "
            "{name, commands: [...]} entries"
        ),
    )
    coverage_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full machine-readable report instead of text",
    )
    coverage_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show every exemplar verdict, including ones that gate",
    )
    coverage_parser.set_defaults(func=cmd_approvals)
    approvals_parser.set_defaults(func=cmd_approvals)
