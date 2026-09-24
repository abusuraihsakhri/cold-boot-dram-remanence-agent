import csv
import json
import subprocess
import sys
from pathlib import Path

from cli import format_report_text
from cold_boot_remanence import ColdBootRemanenceEngine

ROOT = Path(__file__).resolve().parents[1]


def test_text_report_uses_corrected_terminology():
    report = ColdBootRemanenceEngine.run_full_assessment(25.0, 1.0)
    text = format_report_text(report)
    assert "Residual uncertainty" in text
    assert "Estimated Search Complexity" not in text


def test_direct_cli_json():
    result = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "--temp", "25", "--time", "0", "--json"],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    assert data["thermal_profile"]["expected_bit_error_rate"] == 0.0


def test_batch_cli(tmp_path):
    output = tmp_path / "out.csv"
    result = subprocess.run(
        [sys.executable, str(ROOT / "cli.py"), "batch", "-i", str(ROOT / "sample.csv"), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "4 records" in result.stdout
    with output.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    assert "residual_uncertainty_bits" in rows[0]
