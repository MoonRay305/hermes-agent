#!/usr/bin/env python3
"""Recalculate an .xlsx file's formulas using LibreOffice headless.

Usage: python recalc.py <path.xlsx> [timeout_seconds]

openpyxl writes formula strings but does not compute them. Downstream scripts
that open the file with data_only=True get None for every formula cell until
something has actually calculated the workbook. Excel does this on open;
headless pipelines need LibreOffice (or similar) to do it explicitly.

LibreOffice is started only through the shared wrapper
(skills/productivity/powerpoint/scripts/office/soffice.py), which gives every
run a private, throwaway user profile. If the wrapper cannot be found this
script refuses to run rather than starting LibreOffice itself.

Exits 0 on success (workbook recomputed and resaved in place), non-zero on
failure. Writes status JSON to stdout either way.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_WRAPPER = Path("productivity", "powerpoint", "scripts", "office", "soffice.py")


def _wrapper_candidates() -> list[Path]:
    # Fixed locations only -- never a walk up into directories other users
    # may be able to write to.
    parents = Path(__file__).resolve().parents
    candidates = []
    if len(parents) > 3:
        # Installed: <skills>/finance/excel-author/scripts/recalc.py
        candidates.append(parents[3] / _WRAPPER)
    if len(parents) > 4:
        # Repository checkout: <repo>/optional-skills/finance/excel-author/scripts/recalc.py
        candidates.append(parents[4] / "skills" / _WRAPPER)
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    home = Path(hermes_home) if hermes_home else Path.home() / ".hermes"
    candidates.append(home / "skills" / _WRAPPER)
    return candidates


def load_soffice_wrapper():
    for candidate in _wrapper_candidates():
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("hermes_office_soffice", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    return None


def recalc(xlsx_path: str, timeout: int = 60) -> dict:
    src = Path(xlsx_path).resolve()
    if not src.exists():
        return {"status": "error", "error": f"File not found: {src}"}

    wrapper = load_soffice_wrapper()
    if wrapper is None:
        return {
            "status": "error",
            "error": "LibreOffice wrapper not found (the bundled powerpoint skill's "
            "scripts/office/soffice.py); refusing to start LibreOffice without it",
        }

    with tempfile.TemporaryDirectory() as td:
        try:
            wrapper.run_soffice(
                ["--headless", "--calc", "--convert-to", "xlsx", str(src), "--outdir", td],
                check=True,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": f"LibreOffice timed out after {timeout}s"}
        except subprocess.CalledProcessError as e:
            return {
                "status": "error",
                "error": f"LibreOffice exited {e.returncode}: {e.stderr.decode(errors='replace')[:500]}",
            }
        except FileNotFoundError as e:
            return {"status": "error", "error": f"{e} — install it or recalc in a real Excel session"}
        except (ValueError, OSError) as e:
            return {"status": "error", "error": f"LibreOffice launch refused: {e}"}

        produced = Path(td) / src.name
        if not produced.exists():
            return {"status": "error", "error": "LibreOffice did not produce output file"}

        shutil.copy(produced, src)

    return {"status": "success", "file": str(src)}


def main():
    if len(sys.argv) < 2:
        print("Usage: python recalc.py <path.xlsx> [timeout_seconds]", file=sys.stderr)
        sys.exit(2)
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    result = recalc(sys.argv[1], timeout=timeout)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)


if __name__ == "__main__":
    main()
