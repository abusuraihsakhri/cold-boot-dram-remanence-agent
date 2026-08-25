#!/usr/bin/env python3
"""
Command-Line Interface for Cold Boot DRAM Remanence & Key Recovery Defense Engine
Supports interactive execution, CLI parameters, synthetic key decay, CSV batch audits, and JSON output.
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Add parent directory to path if needed
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from cold_boot_remanence import ColdBootRemanenceEngine, SimulationReport


def format_report_text(report: SimulationReport) -> str:
    """Format SimulationReport into a human-readable security assessment summary."""
    t = report.thermal_profile
    e = report.entropy_metrics
    c = report.countermeasure
    s = report.synthetic_key_decay_results

    lines = []
    lines.append("=" * 80)
    lines.append("COLD BOOT ATTACK & DRAM DATA REMANENCE AUDIT REPORT")
    lines.append(f"Simulation ID: {report.simulation_id:<20} Timestamp UTC: {report.timestamp_utc}")
    lines.append("=" * 80)

    # 1. Thermal & Remanence Kinetics
    lines.append("\n[1] THERMAL DECAY KINETICS (Arrhenius Model)")
    lines.append(f"  * Operating Temperature:   {t.temperature_celsius:+.2f} °C ({t.temperature_kelvin:.2f} K)")
    lines.append(f"  * Power-Off Elapsed Time:  {t.time_elapsed_seconds:.2f} seconds")
    lines.append(f"  * Discharge Time Constant: tau = {t.time_constant_tau_seconds:.3f} s (Half-Life = {t.half_life_seconds:.3f} s)")
    lines.append(f"  * Retained Signal/Charge:  {t.retention_fraction * 100:.3f}% of initial state")
    lines.append(f"  * Expected Bit Error Rate: {t.expected_bit_error_rate * 100:.3f}% (BER)")
    lines.append(f"  * Feasible Attack Window:  {t.reconstruction_window_seconds:.2f} seconds (Time to BER > 15%)")

    # 2. Cryptographic Key Reconstructability
    lines.append("\n[2] CRYPTOGRAPHIC KEY DEGRADATION & ENTROPY LOSS")
    lines.append(f"  * Master Key Size:         {e.master_key_bits}-bit AES Key")
    lines.append(f"  * Shannon Entropy per bit: {e.shannon_entropy_per_bit:.4f} bits (H(p))")
    lines.append(f"  * Residual Mutual Info:    {e.residual_mutual_information:.4f} bits/bit")
    lines.append(f"  * Effective Security:      {e.effective_security_bits:.1f} / {e.master_key_bits} bits")
    lines.append(f"  * Reconstruction Tier:     >>> {e.reconstruction_complexity_tier} <<<")
    lines.append(f"  * Est. Search Complexity:  2^{e.estimated_search_complexity_log2:.1f} operations")

    # 3. Synthetic Decay Simulation (if run)
    if s:
        lines.append("\n[3] SYNTHETIC BITSTREAM DECAY SIMULATION")
        lines.append(f"  * Original Key Hex:        {s['original_hex']}")
        lines.append(f"  * Decayed Key Hex:         {s['decayed_hex']}")
        lines.append(f"  * Total Bits:              {s['total_bits']} bits")
        lines.append(f"  * Flipped Bits (Hamming):  {s['flipped_bits']} bits (Empirical BER = {s['empirical_ber'] * 100:.2f}%)")

    # 4. Countermeasures & Defense
    lines.append("\n[4] HARDWARE DEFENSE & COUNTERMEASURE AUDIT")
    lines.append(f"  * Defense Posture Score:   {c.defense_score_percentage:.1f} / 100.0%  (Status: >>> {c.threat_level} <<<)")
    if c.hardware_features_active:
        lines.append("  * Active Countermeasures:")
        for feat in c.hardware_features_active:
            lines.append(f"    [+] {feat}")
    if c.vulnerabilities_identified:
        lines.append("  * Identified Vulnerabilities:")
        for vuln in c.vulnerabilities_identified:
            lines.append(f"    [-] {vuln}")
    if c.mitigations_recommended:
        lines.append("  * Recommended Mitigations:")
        for rec in c.mitigations_recommended:
            lines.append(f"    [*] {rec}")

    lines.append("=" * 80)
    return "\n".join(lines)


def run_interactive_mode() -> SimulationReport:
    """Prompt user interactively for environmental and hardware parameters."""
    print("\n--- Interactive Cold Boot DRAM Remanence Analyzer ---")

    def ask_float(prompt: str, default: float) -> float:
        val = input(f"{prompt} [{default}]: ").strip()
        try:
            return float(val) if val else default
        except ValueError:
            return default

    def ask_int(prompt: str, default: int) -> int:
        val = input(f"{prompt} [{default}]: ").strip()
        try:
            return int(val) if val else default
        except ValueError:
            return default

    def ask_bool(prompt: str, default: bool = False) -> bool:
        def_str = "Y/n" if default else "y/N"
        val = input(f"{prompt} ({def_str}): ").strip().lower()
        if not val:
            return default
        return val in ["y", "yes", "true", "1"]

    def ask_str(prompt: str, default: str) -> str:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default

    temp = ask_float("Ambient / Cooling Temperature in Celsius (e.g. 25 for room, -50 for freeze spray, -196 for LN2)", 25.0)
    elapsed = ask_float("Elapsed time since power-off in seconds", 10.0)
    key_bits = ask_int("Target AES Master Key Size (128 or 256)", 128)
    sim_test = ask_bool("Simulate decay on a sample hex key?", True)
    hex_key = None
    if sim_test:
        default_hex = "2b7e151628aed2a6abf7158809cf4f3c" if key_bits == 128 else "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        hex_key = ask_str("Sample Master Key Hex", default_hex)

    tresor = ask_bool("TRESOR / Loop-Amnesia CPU Register Key Storage active?", False)
    tme = ask_bool("Hardware Total Memory Encryption (TME / SME) active?", False)
    mor = ask_bool("TCG Memory Overwrite Request (MOR) firmware scrubbing?", False)
    tamper = ask_bool("Chassis intrusion tamper detection circuit?", False)
    secboot = ask_bool("UEFI Secure Boot enabled and locked down?", True)
    ram = ask_str("RAM Type (DDR4 / DDR5 / LPDDR5)", "DDR4")

    return ColdBootRemanenceEngine.run_full_assessment(
        temperature_celsius=temp,
        time_elapsed_seconds=elapsed,
        master_key_bits=key_bits,
        test_hex_key=hex_key,
        has_tresor=tresor,
        has_tme=tme,
        has_mor=mor,
        has_tamper=tamper,
        has_secure_boot=secboot,
        ram_type=ram
    )


def main():
    parser = argparse.ArgumentParser(
        description="Cold Boot Attack DRAM Remanence & Key Recovery Defense Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive parameter evaluation mode")
    parser.add_argument("--json", action="store_true", help="Output results in structured JSON format")
    parser.add_argument("--csv", type=str, help="Path to batch CSV file containing simulation parameters")

    # Direct CLI Simulation Arguments
    parser.add_argument("--temp", "--temperature", type=float, default=25.0, help="DRAM temperature in Celsius (+25, -50, -196)")
    parser.add_argument("--time", "--elapsed", type=float, default=10.0, help="Time elapsed since power loss in seconds")
    parser.add_argument("--key-bits", type=int, default=128, choices=[128, 192, 256], help="Target encryption key length (128 or 256 bits)")
    parser.add_argument("--hex-key", type=str, default=None, help="Sample encryption master key in hex format to simulate decay")
    parser.add_argument("--tresor", action="store_true", help="Flag: System uses CPU-register key storage (TRESOR/Loop-Amnesia)")
    parser.add_argument("--tme", action="store_true", help="Flag: System enables Total Memory Encryption (Intel TME / AMD SME)")
    parser.add_argument("--mor", action="store_true", help="Flag: System firmware enforces TCG Memory Overwrite Request (MOR)")
    parser.add_argument("--tamper", action="store_true", help="Flag: Chassis intrusion anti-tamper sensor present")
    parser.add_argument("--secure-boot", action="store_true", help="Flag: UEFI Secure Boot enabled")
    parser.add_argument("--ram-type", type=str, default="DDR4", help="RAM technology type (DDR3, DDR4, DDR5, LPDDR5)")

    args = parser.parse_args()

    if args.csv:
        if not os.path.exists(args.csv):
            print(f"Error: CSV file '{args.csv}' not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.csv, "r", encoding="utf-8") as f:
            csv_text = f.read()
        reports = ColdBootRemanenceEngine.evaluate_batch_csv(csv_text)
        if args.json:
            print(json.dumps([r.to_dict() for r in reports], indent=2))
        else:
            for rep in reports:
                print(format_report_text(rep))
                print("\n")
        return

    if args.interactive:
        report = run_interactive_mode()
    else:
        report = ColdBootRemanenceEngine.run_full_assessment(
            temperature_celsius=args.temp,
            time_elapsed_seconds=args.time,
            master_key_bits=args.key_bits,
            test_hex_key=args.hex_key,
            has_tresor=args.tresor,
            has_tme=args.tme,
            has_mor=args.mor,
            has_tamper=args.tamper,
            has_secure_boot=args.secure_boot,
            ram_type=args.ram_type
        )

    if args.json:
        print(report.to_json())
    else:
        print(format_report_text(report))


if __name__ == "__main__":
    main()
