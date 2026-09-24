#!/usr/bin/env python3
"""Command-line interface for the DRAM remanence risk simulator."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from cold_boot_remanence import ColdBootRemanenceEngine, SimulationReport


def format_report_text(report: SimulationReport) -> str:
    t = report.thermal_profile
    e = report.entropy_metrics
    c = report.countermeasure
    s = report.synthetic_key_decay_results
    lines = [
        "=" * 78,
        "DRAM REMANENCE RISK SIMULATION",
        f"Simulation ID: {report.simulation_id}    Timestamp UTC: {report.timestamp_utc}",
        "=" * 78,
        "[Model]",
        f"  {report.model_assumptions}",
        "",
        "[Thermal decay]",
        f"  Temperature:          {t.temperature_celsius:+.2f} °C ({t.temperature_kelvin:.2f} K)",
        f"  Elapsed time:         {t.time_elapsed_seconds:.2f} s",
        f"  Model time constant:  {t.time_constant_tau_seconds:.3f} s",
        f"  Retention fraction:   {t.retention_fraction * 100:.3f}%",
        f"  Expected BER:         {t.expected_bit_error_rate * 100:.3f}%",
        f"  15% BER model window: {t.reconstruction_window_seconds:.2f} s",
        "",
        "[Information model]",
        f"  Key size:             {e.master_key_bits} bits",
        f"  Binary entropy H(p):  {e.shannon_entropy_per_bit:.4f} bits/bit",
        f"  Retained information: {e.retained_information_bits:.2f} bits",
        f"  Residual uncertainty: {e.residual_uncertainty_bits:.2f} bits",
        f"  Corruption band:      {e.reconstruction_complexity_tier}",
        f"  Note:                 {e.model_warning}",
    ]
    if s:
        lines.extend(
            [
                "",
                "[Synthetic bit decay]",
                f"  Input encoding:       {s['input_encoding']}",
                f"  Total bits:           {s['total_bits']}",
                f"  Flipped bits:         {s['flipped_bits']}",
                f"  Empirical BER:        {s['empirical_ber'] * 100:.2f}%",
            ]
        )
    lines.extend(
        [
            "",
            "[Defensive controls]",
            f"  Heuristic score:      {c.defense_score_percentage:.1f}/100",
            f"  Control band:         {c.threat_level}",
            f"  Note:                 {c.scoring_note}",
        ]
    )
    if c.hardware_features_active:
        lines.append("  Active controls:")
        lines.extend(f"    + {item}" for item in c.hardware_features_active)
    if c.mitigations_recommended:
        lines.append("  Suggested controls:")
        lines.extend(f"    - {item}" for item in c.mitigations_recommended)
    lines.append("=" * 78)
    return "\n".join(lines)


def run_interactive_mode() -> SimulationReport:
    print("\n--- Interactive DRAM Remanence Risk Simulator ---")

    def ask_float(prompt: str, default: float) -> float:
        value = input(f"{prompt} [{default}]: ").strip()
        return float(value) if value else default

    def ask_int(prompt: str, default: int) -> int:
        value = input(f"{prompt} [{default}]: ").strip()
        return int(value) if value else default

    def ask_bool(prompt: str, default: bool = False) -> bool:
        suffix = "Y/n" if default else "y/N"
        value = input(f"{prompt} ({suffix}): ").strip().lower()
        return default if not value else value in {"y", "yes", "true", "1"}

    def ask_str(prompt: str, default: str) -> str:
        value = input(f"{prompt} [{default}]: ").strip()
        return value or default

    temp = ask_float("Temperature in Celsius", 25.0)
    elapsed = ask_float("Elapsed time since power loss in seconds", 10.0)
    key_bits = ask_int("AES key size (128, 192, or 256)", 128)
    sim_test = ask_bool("Run synthetic key decay?", True)
    key = None
    if sim_test:
        key = ask_str("Sample key material (hex preferred)", "2b7e151628aed2a6abf7158809cf4f3c")

    return ColdBootRemanenceEngine.run_full_assessment(
        temperature_celsius=temp,
        time_elapsed_seconds=elapsed,
        master_key_bits=key_bits,
        test_hex_key=key,
        has_tresor=ask_bool("CPU-resident key storage enabled?"),
        has_tme=ask_bool("Hardware memory encryption enabled?"),
        has_mor=ask_bool("Firmware memory overwrite control enabled?"),
        has_tamper=ask_bool("Tamper response enabled?"),
        has_secure_boot=ask_bool("Verified/Secure Boot policy enforced?", True),
        ram_type=ask_str("RAM type", "DDR4"),
    )


def run_batch(input_path: str, output_path: Optional[str] = None, as_json: bool = False) -> None:
    if not os.path.isfile(input_path):
        raise ValueError(f"CSV file not found: {input_path}")
    with open(input_path, "r", encoding="utf-8", newline="") as handle:
        reports = ColdBootRemanenceEngine.evaluate_batch_csv(handle.read())

    if output_path:
        fieldnames = [
            "simulation_id",
            "temperature_celsius",
            "time_elapsed_seconds",
            "time_constant_tau_seconds",
            "half_life_seconds",
            "retention_fraction",
            "expected_bit_error_rate",
            "reconstruction_window_seconds",
            "master_key_bits",
            "shannon_entropy_per_bit",
            "retained_information_bits",
            "residual_uncertainty_bits",
            "effective_security_bits",
            "reconstruction_complexity_tier",
            "defense_score_percentage",
            "threat_level",
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for report in reports:
                t, e, c = report.thermal_profile, report.entropy_metrics, report.countermeasure
                writer.writerow(
                    {
                        "simulation_id": report.simulation_id,
                        "temperature_celsius": t.temperature_celsius,
                        "time_elapsed_seconds": t.time_elapsed_seconds,
                        "time_constant_tau_seconds": t.time_constant_tau_seconds,
                        "half_life_seconds": t.half_life_seconds,
                        "retention_fraction": t.retention_fraction,
                        "expected_bit_error_rate": t.expected_bit_error_rate,
                        "reconstruction_window_seconds": t.reconstruction_window_seconds,
                        "master_key_bits": e.master_key_bits,
                        "shannon_entropy_per_bit": e.shannon_entropy_per_bit,
                        "retained_information_bits": e.retained_information_bits,
                        "residual_uncertainty_bits": e.residual_uncertainty_bits,
                        "effective_security_bits": e.effective_security_bits,
                        "reconstruction_complexity_tier": e.reconstruction_complexity_tier,
                        "defense_score_percentage": c.defense_score_percentage,
                        "threat_level": c.threat_level,
                    }
                )
        print(f"Batch simulation completed for {len(reports)} records. Output: {output_path}")
    elif as_json:
        print(json.dumps([report.to_dict() for report in reports], indent=2, allow_nan=False))
    else:
        for report in reports:
            print(format_report_text(report), "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Illustrative DRAM remanence risk simulator")
    subparsers = parser.add_subparsers(dest="subcommand")

    batch = subparsers.add_parser("batch", help="Run a batch simulation from CSV")
    batch.add_argument("-i", "--input", required=True)
    batch.add_argument("-o", "--output")
    batch.add_argument("--json", action="store_true")

    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--csv", type=str)
    parser.add_argument("-o", "--output", type=str)
    parser.add_argument("--temp", "--temperature", type=float, default=25.0)
    parser.add_argument("--time", "--elapsed", type=float, default=10.0)
    parser.add_argument("--key-bits", type=int, default=128, choices=[128, 192, 256])
    parser.add_argument("--hex-key", type=str, default=None)
    parser.add_argument("--tresor", action="store_true")
    parser.add_argument("--tme", action="store_true")
    parser.add_argument("--mor", action="store_true")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--secure-boot", action="store_true")
    parser.add_argument("--ram-type", type=str, default="DDR4")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.subcommand == "batch":
            run_batch(args.input, args.output, args.json)
            return
        if args.csv:
            run_batch(args.csv, args.output, args.json)
            return
        report = run_interactive_mode() if args.interactive else ColdBootRemanenceEngine.run_full_assessment(
            temperature_celsius=args.temp,
            time_elapsed_seconds=args.time,
            master_key_bits=args.key_bits,
            test_hex_key=args.hex_key,
            has_tresor=args.tresor,
            has_tme=args.tme,
            has_mor=args.mor,
            has_tamper=args.tamper,
            has_secure_boot=args.secure_boot,
            ram_type=args.ram_type,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return
    print(report.to_json() if args.json else format_report_text(report))


if __name__ == "__main__":
    main()
