#!/usr/bin/env python3
"""Executable allowlist proof for the LibreOffice wrapper.

Runs a sentinel executable for refusal probes, then performs one real XLSX-to-PDF
conversion using an explicitly allowlisted profile. Emits one JSON object per probe.
"""

import argparse
import importlib.util
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path


def load_wrapper(path: Path):
    spec = importlib.util.spec_from_file_location("soffice_probe_wrapper", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def root_mode() -> str:
    return f"{stat.S_IMODE(os.stat('/').st_mode):03o}"


def emit(record: dict) -> None:
    print(json.dumps(record, sort_keys=True), flush=True)


def make_xlsx(path: Path) -> None:
    try:
        from openpyxl import Workbook
    except ImportError as exc:
        raise RuntimeError("openpyxl is required for the real conversion probe") from exc

    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Allowlist Proof"
    worksheet["A1"] = "BUI-1123 LibreOffice profile allowlist"
    worksheet["A2"] = "real XLSX to PDF conversion"
    workbook.save(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()

    wrapper = load_wrapper(args.wrapper.resolve())
    approved_root = wrapper._APPROVED_PROFILE_ROOT
    approved_root.mkdir(parents=True, mode=0o700, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="bui1123_probe_") as scratch_raw:
        scratch = Path(scratch_raw)
        marker = scratch / "sentinel-launched"
        sentinel = scratch / "soffice"
        sentinel.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('launched', encoding='utf-8')\n",
            encoding="utf-8",
        )
        sentinel.chmod(0o755)

        symlink = approved_root / f"bui1123-root-link-{os.getpid()}"
        symlink.symlink_to("/root", target_is_directory=True)

        unsafe_values = [
            ("root", "file:///root"),
            ("filesystem-root", "file:///"),
            ("etc", "file:///etc"),
            ("var", "file:///var"),
            ("home-landon", "file:///home/landon"),
            ("tmp-parent", "file:///tmp"),
            ("approved-root-itself", approved_root.as_uri()),
            ("dotdot-escape", "file:///var/tmp/lo-profiles/../../../root"),
            ("encoded-dotdot-escape", "file:///var/tmp/lo-profiles/%2e%2e/%2e%2e/%2e%2e/root"),
            ("symlink-to-root", symlink.as_uri()),
            ("file-empty-path", "file://"),
            ("bare-relative", "relative-profile"),
        ]

        records = []
        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{scratch}{os.pathsep}{original_path}"
        try:
            for option in ("-env:UserInstallation", "/env:UserInstallation"):
                for case, value in unsafe_values:
                    marker.unlink(missing_ok=True)
                    before = root_mode()
                    refusal = None
                    returncode = None
                    try:
                        result = wrapper.run_soffice([
                            f"{option}={value}",
                            "--headless",
                        ])
                        returncode = result.returncode
                    except ValueError as exc:
                        refusal = str(exc)
                    after = root_mode()
                    launched = marker.exists()
                    record = {
                        "probe": case,
                        "option": option,
                        "value": value,
                        "refused": refusal is not None,
                        "refusal_text": refusal,
                        "sentinel_launched": launched,
                        "returncode": returncode,
                        "root_mode_before": before,
                        "root_mode_after": after,
                    }
                    records.append(record)
                    emit(record)
        finally:
            os.environ["PATH"] = original_path
            symlink.unlink(missing_ok=True)

        conversion_dir = scratch / "conversion"
        conversion_dir.mkdir()
        source = conversion_dir / "allowlist-proof.xlsx"
        output_dir = conversion_dir / "pdf"
        output_dir.mkdir()
        make_xlsx(source)
        profile = approved_root / f"bui1123-approved-{os.getpid()}"
        shutil.rmtree(profile, ignore_errors=True)

        before = root_mode()
        result = wrapper.run_soffice([
            f"-env:UserInstallation={profile.as_uri()}",
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(output_dir),
            str(source),
        ], capture_output=True, text=True)
        after = root_mode()
        output = output_dir / "allowlist-proof.pdf"
        conversion_record = {
            "probe": "approved-real-xlsx-to-pdf",
            "option": "-env:UserInstallation",
            "value": profile.as_uri(),
            "refused": False,
            "refusal_text": None,
            "soffice_launched": True,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "output_exists": output.is_file(),
            "output_bytes": output.stat().st_size if output.is_file() else 0,
            "root_mode_before": before,
            "root_mode_after": after,
        }
        records.append(conversion_record)
        emit(conversion_record)
        shutil.rmtree(profile, ignore_errors=True)

        failures = [
            record
            for record in records[:-1]
            if not record["refused"]
            or record["sentinel_launched"]
            or record["root_mode_before"] != "755"
            or record["root_mode_after"] != "755"
        ]
        if (
            result.returncode != 0
            or not output.is_file()
            or output.stat().st_size == 0
            or before != "755"
            or after != "755"
        ):
            failures.append(conversion_record)

        summary = {
            "probe": "summary",
            "wrapper": str(args.wrapper.resolve()),
            "refusal_probe_count": len(records) - 1,
            "failure_count": len(failures),
            "approved_conversion_output": str(output),
            "approved_conversion_bytes": output.stat().st_size if output.is_file() else 0,
            "root_mode_final": root_mode(),
        }
        emit(summary)

        if args.evidence:
            args.evidence.write_text(
                "\n".join(json.dumps(record, sort_keys=True) for record in [*records, summary]) + "\n",
                encoding="utf-8",
            )

        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
