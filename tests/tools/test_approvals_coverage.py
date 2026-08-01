"""``hermes approvals coverage`` — per-profile gate introspection (BUI-1100).

The expectations below are derived INDEPENDENTLY of the evaluator: each
expected outcome is hand-reasoned from the profile config and the published
pattern semantics (which exemplar matches which detector, which allowlist
entry captures which key), then compared against what the coverage engine
reports. If the engine and the hand derivation disagree, the report is
lying about what the gate does.
"""
import json

import pytest

from tools.approval_coverage import (
    BUILTIN_OPERATION_CLASSES,
    evaluate_command,
    evaluate_profile,
)


def _class(report, name):
    return next(c for c in report["classes"] if c["class"] == name)


@pytest.fixture
def profile_homes(tmp_path):
    """Three on-disk profile configs mirroring the audited fleet's shapes."""
    manual = tmp_path / "manual-default"
    manual.mkdir()
    (manual / "config.yaml").write_text(
        "approvals:\n  mode: manual\n")

    off = tmp_path / "mode-off"
    off.mkdir()
    (off / "config.yaml").write_text(
        "approvals:\n  mode: off\n")

    allowlisted = tmp_path / "allowlisted"
    allowlisted.mkdir()
    (allowlisted / "config.yaml").write_text(
        "approvals:\n  mode: manual\n"
        "command_allowlist:\n"
        "  - recursive delete\n"
        "  - \"git push*\"\n")
    return {"manual": manual, "off": off, "allowlisted": allowlisted}


class TestBuiltinClassSet:
    def test_ships_the_fifteen_audit_classes(self):
        names = [c["name"] for c in BUILTIN_OPERATION_CLASSES]
        assert len(names) == 15
        for expected in [
            "deletion", "recursive deletion", "permission change",
            "ownership change", "move/rename", "package install",
            "git push", "git force-push", "SQL UPDATE", "SQL DROP",
            "service restart", "docker privileged run",
            "credential read (Doppler)", "credential write (Doppler)",
            "remote content to shell",
        ]:
            assert expected in names, expected


class TestManualProfileMatchesIndependentDerivation:
    """Class 1-3 derivations for a bare manual-mode profile.

    Derivation (by hand, from the pattern list):
    - recursive deletion: `rm -rf ./build` and `rm -r workdir` both carry an
      ``-r`` flag → the ``recursive delete`` pattern (`\\brm\\s+-[^\\s]*r`)
      matches both → both PROMPT → class fully gates.
    - move/rename: no pattern in DANGEROUS_PATTERNS matches a bare ``mv``
      between ordinary paths → both pass untouched → class fully ungated.
    - deletion: `rm notes.txt` has no flags and no leading ``/`` → no rm
      pattern matches → passes. `rm /tmp/scratch.txt` matches ``delete in
      root path`` (`\\brm\\s+(-[^\\s]*\\s+)*/`) → prompts. The SQL pair:
      ``DELETE FROM users`` (no WHERE) matches ``SQL DELETE without
      WHERE`` → prompts; the WHERE variant does not → passes. → partial 2/4.
    """

    def test_recursive_deletion_fully_gates(self, profile_homes):
        report = evaluate_profile("manual", profile_homes["manual"],
                                  BUILTIN_OPERATION_CLASSES)
        cls = _class(report, "recursive deletion")
        assert cls["status"] == "full"
        assert all(e["outcome"] == "gated" for e in cls["exemplars"])

    def test_move_rename_fully_ungated(self, profile_homes):
        report = evaluate_profile("manual", profile_homes["manual"],
                                  BUILTIN_OPERATION_CLASSES)
        cls = _class(report, "move/rename")
        assert cls["status"] == "none"
        assert all(e["outcome"] == "ungated" for e in cls["exemplars"])

    def test_deletion_partial_two_of_four(self, profile_homes):
        report = evaluate_profile("manual", profile_homes["manual"],
                                  BUILTIN_OPERATION_CLASSES)
        cls = _class(report, "deletion")
        assert cls["status"] == "partial"
        assert cls["gated_exemplars"] == 2
        assert cls["total_exemplars"] == 4
        by_cmd = {e["command"]: e for e in cls["exemplars"]}
        assert by_cmd["rm notes.txt"]["outcome"] == "ungated"
        assert by_cmd["rm /tmp/scratch.txt"]["outcome"] == "gated"
        assert by_cmd['psql -c "DELETE FROM users"']["outcome"] == "gated"
        assert by_cmd['psql -c "DELETE FROM users WHERE id = 7"']["outcome"] == "ungated"

    def test_doppler_read_fully_gates_after_bui1100(self, profile_homes):
        """Was 0/20 in the audit; the new operation-keyed detectors close it."""
        report = evaluate_profile("manual", profile_homes["manual"],
                                  BUILTIN_OPERATION_CLASSES)
        for name in ("credential read (Doppler)", "credential write (Doppler)"):
            cls = _class(report, name)
            assert cls["status"] == "full", name

    def test_permission_change_fully_gates_after_bui1100(self, profile_homes):
        """chmod 700 / chmod +x were clean pre-change; the class detector
        gates them alongside the historical chmod 777 shape."""
        report = evaluate_profile("manual", profile_homes["manual"],
                                  BUILTIN_OPERATION_CLASSES)
        assert _class(report, "permission change")["status"] == "full"
        assert _class(report, "ownership change")["status"] == "full"


class TestModeOffProfile:
    def test_everything_bypasses_with_mode_off_reason(self, profile_homes):
        report = evaluate_profile("off", profile_homes["off"],
                                  BUILTIN_OPERATION_CLASSES)
        assert report["approvals_mode"] == "off"
        for name in ("recursive deletion", "SQL DROP",
                     "credential read (Doppler)"):
            cls = _class(report, name)
            assert cls["status"] == "none", name
            for exemplar in cls["exemplars"]:
                assert exemplar["outcome"] == "bypass"
                assert exemplar["reason"] == "mode_off"

    def test_yaml_bare_off_is_normalized(self, tmp_path):
        """YAML 1.1 parses bare ``off`` as False — the loader must still
        read it as mode off, mirroring _normalize_approval_mode."""
        home = tmp_path / "yaml-off"
        home.mkdir()
        (home / "config.yaml").write_text("approvals:\n  mode: off\n")
        report = evaluate_profile("yaml-off", home, BUILTIN_OPERATION_CLASSES)
        assert report["approvals_mode"] == "off"


class TestAllowlistedProfile:
    def test_pattern_key_entry_disarms_recursive_deletion(self, profile_homes):
        report = evaluate_profile("allowlisted", profile_homes["allowlisted"],
                                  BUILTIN_OPERATION_CLASSES)
        cls = _class(report, "recursive deletion")
        assert cls["status"] == "none"
        for exemplar in cls["exemplars"]:
            assert exemplar["outcome"] == "bypass"
            assert exemplar["reason"] == "pattern_key_allowlist"

    def test_exact_glob_entry_disarms_git_push_classes(self, profile_homes):
        report = evaluate_profile("allowlisted", profile_homes["allowlisted"],
                                  BUILTIN_OPERATION_CLASSES)
        for name in ("git push", "git force-push"):
            cls = _class(report, name)
            assert cls["status"] == "none", name
            for exemplar in cls["exemplars"]:
                assert exemplar["outcome"] == "bypass"
                assert exemplar["reason"] == "exact_command_allowlist"
                assert exemplar["detail"] == "git push*"

    def test_unrelated_class_still_gates(self, profile_homes):
        report = evaluate_profile("allowlisted", profile_homes["allowlisted"],
                                  BUILTIN_OPERATION_CLASSES)
        assert _class(report, "SQL DROP")["status"] == "full"


class TestEvaluateCommandPrimitives:
    def test_hardline_reported_as_block(self):
        verdict = evaluate_command("rm -rf /", approvals_mode="off")
        assert verdict["outcome"] == "blocked_hardline"
        assert verdict["gates"] is True

    def test_deny_rule_beats_mode_off(self):
        verdict = evaluate_command(
            "doppler secrets get X",
            approvals_mode="off",
            deny_globs=["*doppler*"],
        )
        assert verdict["outcome"] == "blocked_deny_rule"
        assert verdict["gates"] is True

    def test_partial_allowlist_still_gates(self):
        """A command matching TWO keys with only one allowlisted must still
        prompt — the unapproved key keeps the gate armed."""
        verdict = evaluate_command(
            "rm -rf /tmp/scratch",
            approvals_mode="manual",
            allowlist_entries=["recursive delete"],
        )
        assert verdict["outcome"] == "gated"
        assert "delete in root path" in verdict["unapproved_keys"]

    def test_smart_mode_annotated(self):
        verdict = evaluate_command("rm -rf build", approvals_mode="smart")
        assert verdict["outcome"] == "gated"
        assert verdict["smart_mediated"] is True


class TestCliRendering:
    def test_json_output_shape(self, profile_homes, monkeypatch, capsys, tmp_path):
        """CLI end to end against a real profile layout under HERMES_HOME."""
        home = tmp_path / "clihome"
        (home / "profiles" / "ade").mkdir(parents=True)
        (home / "logs").mkdir()
        (home / "config.yaml").write_text("approvals:\n  mode: manual\n")
        (home / "profiles" / "ade" / "config.yaml").write_text(
            "approvals:\n  mode: off\n")
        monkeypatch.setenv("HERMES_HOME", str(home))

        from types import SimpleNamespace
        from hermes_cli.approvals_cmd import cmd_approvals_coverage

        code = cmd_approvals_coverage(SimpleNamespace(
            profile=None, classes_file=None, json=True, verbose=False))
        assert code == 0
        report = json.loads(capsys.readouterr().out)
        assert len(report["operation_classes"]) == 15
        profile_names = {p["profile"] for p in report["profiles"]}
        assert "ade" in profile_names
        ade = next(p for p in report["profiles"] if p["profile"] == "ade")
        assert ade["approvals_mode"] == "off"
        summary_by_class = {s["class"]: s for s in report["summary"]}
        assert summary_by_class["recursive deletion"]["profiles_total"] == len(
            report["profiles"])

    def test_classes_file_extends_builtins(self, monkeypatch, capsys, tmp_path):
        home = tmp_path / "clihome2"
        (home / "logs").mkdir(parents=True)
        (home / "config.yaml").write_text("approvals:\n  mode: manual\n")
        monkeypatch.setenv("HERMES_HOME", str(home))
        extra = tmp_path / "extra.yaml"
        extra.write_text(
            "classes:\n"
            "  - name: kernel module load\n"
            "    commands:\n"
            "      - modprobe some_mod\n")

        from types import SimpleNamespace
        from hermes_cli.approvals_cmd import cmd_approvals_coverage

        code = cmd_approvals_coverage(SimpleNamespace(
            profile=None, classes_file=str(extra), json=True, verbose=False))
        assert code == 0
        report = json.loads(capsys.readouterr().out)
        assert "kernel module load" in report["operation_classes"]
        assert len(report["operation_classes"]) == 16
