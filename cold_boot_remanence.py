#!/usr/bin/env python3
"""Illustrative DRAM remanence risk model and defensive posture assessment.

The thermal model is intentionally simple. Its default parameters are calibration
assumptions for demonstration and testing; they are not universal DRAM constants
and must not be interpreted as hardware-specific retention predictions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import csv
import datetime as _datetime
import io
import json
import math
import random
import uuid

BOLTZMANN_CONSTANT_EV = 8.617333262145e-5
SILICON_ACTIVATION_ENERGY_EV = 0.65
ROOM_TEMP_KELVIN = 298.15
ROOM_TEMP_TAU_SECONDS = 2.5
ABSOLUTE_ZERO_CELSIUS = -273.15
MAX_ARRHENIUS_EXPONENT = 60.0
MODEL_ASSUMPTION_NOTE = (
    "Illustrative exponential/Arrhenius-style decay model. The default tau and activation "
    "energy are modeling assumptions, not validated constants for a specific DRAM device."
)


def _finite_float(value: float, name: str) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    return value


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "on"}:
        return True
    if text in {"false", "0", "no", "n", "off", "", "none"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


@dataclass
class ThermalDecayProfile:
    temperature_celsius: float
    temperature_kelvin: float
    time_elapsed_seconds: float
    time_constant_tau_seconds: float
    half_life_seconds: float
    retention_fraction: float
    expected_bit_error_rate: float
    reconstruction_window_seconds: float


@dataclass
class KeyEntropyMetrics:
    master_key_bits: int
    decayed_ber: float
    shannon_entropy_per_bit: float
    residual_mutual_information: float
    effective_security_bits: float
    reconstruction_complexity_tier: str
    estimated_search_complexity_log2: Optional[float]
    retained_information_bits: float = 0.0
    residual_uncertainty_bits: float = 0.0
    model_warning: str = (
        "Recovery tier is a qualitative corruption band; no cryptanalytic operation count is predicted."
    )


@dataclass
class CountermeasureAssessment:
    system_profile_name: str
    defense_score_percentage: float
    threat_level: str
    vulnerabilities_identified: List[str] = field(default_factory=list)
    mitigations_recommended: List[str] = field(default_factory=list)
    hardware_features_active: List[str] = field(default_factory=list)
    scoring_note: str = (
        "Defense score is a transparent heuristic for comparing configurations, not a validated risk probability."
    )


@dataclass
class SimulationReport:
    simulation_id: str
    timestamp_utc: str
    thermal_profile: ThermalDecayProfile
    entropy_metrics: KeyEntropyMetrics
    countermeasure: CountermeasureAssessment
    synthetic_key_decay_results: Optional[Dict[str, Any]] = None
    model_assumptions: str = MODEL_ASSUMPTION_NOTE

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, allow_nan=False)


class ColdBootRemanenceEngine:
    """Educational model for DRAM remanence and defensive configuration review."""

    @staticmethod
    def celsius_to_kelvin(celsius: float) -> float:
        celsius = _finite_float(celsius, "temperature_celsius")
        if celsius <= ABSOLUTE_ZERO_CELSIUS:
            raise ValueError("temperature_celsius must be above absolute zero (-273.15 °C)")
        return celsius + 273.15

    @classmethod
    def calculate_decay_time_constant(cls, temperature_celsius: float) -> float:
        kelvin = cls.celsius_to_kelvin(temperature_celsius)
        inv_diff = (1.0 / kelvin) - (1.0 / ROOM_TEMP_KELVIN)
        exponent = (SILICON_ACTIVATION_ENERGY_EV / BOLTZMANN_CONSTANT_EV) * inv_diff
        exponent = min(max(exponent, -20.0), MAX_ARRHENIUS_EXPONENT)
        return ROOM_TEMP_TAU_SECONDS * math.exp(exponent)

    @classmethod
    def compute_thermal_profile(
        cls, temperature_celsius: float, time_elapsed_seconds: float
    ) -> ThermalDecayProfile:
        temperature_celsius = _finite_float(temperature_celsius, "temperature_celsius")
        time_elapsed_seconds = _finite_float(time_elapsed_seconds, "time_elapsed_seconds")
        if time_elapsed_seconds < 0:
            raise ValueError("time_elapsed_seconds must be >= 0")

        kelvin = cls.celsius_to_kelvin(temperature_celsius)
        tau = cls.calculate_decay_time_constant(temperature_celsius)
        half_life = tau * math.log(2.0)
        decay_ratio = time_elapsed_seconds / tau
        retention = math.exp(-min(decay_ratio, 50.0))
        ber = 0.5 * (1.0 - retention)
        reconstruction_window = -tau * math.log(0.70)

        return ThermalDecayProfile(
            temperature_celsius=round(temperature_celsius, 2),
            temperature_kelvin=round(kelvin, 2),
            time_elapsed_seconds=round(time_elapsed_seconds, 2),
            time_constant_tau_seconds=round(tau, 3),
            half_life_seconds=round(half_life, 3),
            retention_fraction=round(retention, 5),
            expected_bit_error_rate=round(min(max(ber, 0.0), 0.5), 5),
            reconstruction_window_seconds=round(reconstruction_window, 2),
        )

    @staticmethod
    def calculate_shannon_entropy(ber: float) -> float:
        ber = _finite_float(ber, "ber")
        if not 0.0 <= ber <= 0.5:
            raise ValueError("ber must be between 0.0 and 0.5 for this decay model")
        if ber == 0.0:
            return 0.0
        if math.isclose(ber, 0.5, abs_tol=1e-12):
            return 1.0
        return -ber * math.log2(ber) - (1.0 - ber) * math.log2(1.0 - ber)

    @classmethod
    def evaluate_key_reconstruction(cls, master_key_bits: int, ber: float) -> KeyEntropyMetrics:
        if master_key_bits not in {128, 192, 256}:
            raise ValueError("master_key_bits must be one of 128, 192, or 256")
        h_p = cls.calculate_shannon_entropy(ber)
        retained_fraction = 1.0 - h_p
        retained_bits = master_key_bits * retained_fraction
        uncertainty_bits = master_key_bits * h_p

        if ber < 0.02:
            tier = "LOW_CORRUPTION"
        elif ber <= 0.07:
            tier = "MODERATE_CORRUPTION"
        elif ber <= 0.15:
            tier = "HIGH_CORRUPTION"
        else:
            tier = "SEVERE_CORRUPTION"

        return KeyEntropyMetrics(
            master_key_bits=master_key_bits,
            decayed_ber=round(ber, 5),
            shannon_entropy_per_bit=round(h_p, 4),
            residual_mutual_information=round(retained_fraction, 4),
            effective_security_bits=round(uncertainty_bits, 2),
            reconstruction_complexity_tier=tier,
            estimated_search_complexity_log2=None,
            retained_information_bits=round(retained_bits, 2),
            residual_uncertainty_bits=round(uncertainty_bits, 2),
        )

    @classmethod
    def simulate_bitstream_decay(
        cls,
        original_hex_key: str,
        temperature_celsius: float,
        time_elapsed_seconds: float,
        preferred_ground_state: int = 0,
        ground_state_asymmetry: float = 0.95,
        seed: Optional[int] = 42,
    ) -> Dict[str, Any]:
        if preferred_ground_state not in {0, 1}:
            raise ValueError("preferred_ground_state must be 0 or 1")
        ground_state_asymmetry = _finite_float(ground_state_asymmetry, "ground_state_asymmetry")
        if not 0.0 <= ground_state_asymmetry <= 1.0:
            raise ValueError("ground_state_asymmetry must be between 0.0 and 1.0")

        clean = str(original_hex_key).replace(" ", "").removeprefix("0x").strip()
        if not clean:
            raise ValueError("original_hex_key must not be empty")
        try:
            key_bytes = bytes.fromhex(clean)
            input_encoding = "hex"
        except ValueError:
            key_bytes = clean.encode("utf-8")
            input_encoding = "utf-8"

        profile = cls.compute_thermal_profile(temperature_celsius, time_elapsed_seconds)
        decay_prob = 1.0 - profile.retention_fraction
        rng = random.Random(seed)

        bits: List[int] = []
        for byte in key_bytes:
            bits.extend((byte >> i) & 1 for i in range(7, -1, -1))

        decayed: List[int] = []
        flips = 0
        for bit in bits:
            if bit != preferred_ground_state:
                flip_probability = decay_prob * ground_state_asymmetry
            else:
                flip_probability = decay_prob * (1.0 - ground_state_asymmetry) * 0.1
            if rng.random() < flip_probability:
                decayed.append(1 - bit)
                flips += 1
            else:
                decayed.append(bit)

        out = bytearray()
        for i in range(0, len(decayed), 8):
            value = 0
            for bit in decayed[i : i + 8]:
                value = (value << 1) | bit
            out.append(value)

        total_bits = len(bits)
        return {
            "original_hex": clean,
            "input_encoding": input_encoding,
            "decayed_hex": out.hex(),
            "total_bits": total_bits,
            "flipped_bits": flips,
            "hamming_distance": flips,
            "empirical_ber": round(flips / total_bits, 5),
            "expected_theoretical_ber": profile.expected_bit_error_rate,
            "decay_temperature_celsius": profile.temperature_celsius,
            "decay_time_seconds": profile.time_elapsed_seconds,
        }

    @staticmethod
    def evaluate_countermeasures(
        has_tresor_cpu_registers: bool = False,
        has_total_memory_encryption: bool = False,
        has_power_reset_scrubbing: bool = False,
        has_chassis_tamper_sensor: bool = False,
        has_secure_boot_lockdown: bool = False,
        ram_type: str = "DDR4",
    ) -> CountermeasureAssessment:
        controls = [
            (has_tresor_cpu_registers, 30.0, "CPU-resident key storage",
             "Sensitive key material may reside in DRAM.",
             "Use a design that minimizes plaintext key residency in DRAM where supported."),
            (has_total_memory_encryption, 30.0, "Hardware memory encryption",
             "DRAM contents may be readable without a memory-encryption boundary.",
             "Enable and verify platform memory encryption when the hardware and threat model support it."),
            (has_power_reset_scrubbing, 20.0, "Firmware memory overwrite on requested reset paths",
             "A supported reset path may not scrub memory before third-party code runs.",
             "Enable and verify firmware memory-overwrite controls such as TCG MOR where applicable."),
            (has_chassis_tamper_sensor, 10.0, "Tamper response / key invalidation control",
             "Physical enclosure access may not trigger a security response.",
             "Use platform-appropriate tamper detection and key invalidation for high-assurance deployments."),
            (has_secure_boot_lockdown, 10.0, "Verified boot policy",
             "Boot policy may permit untrusted recovery media on the original platform.",
             "Enforce a verified boot policy and restrict unauthorized boot paths."),
        ]

        score = 0.0
        vulnerabilities: List[str] = []
        mitigations: List[str] = []
        active: List[str] = []
        for enabled, weight, label, weakness, mitigation in controls:
            if enabled:
                score += weight
                active.append(label)
            else:
                vulnerabilities.append(weakness)
                mitigations.append(mitigation)

        if score >= 80:
            threat = "STRONG_CONTROLS"
        elif score >= 50:
            threat = "PARTIAL_CONTROLS"
        else:
            threat = "LIMITED_CONTROLS"

        ram_label = str(ram_type).strip() or "Unknown"
        return CountermeasureAssessment(
            system_profile_name=f"{ram_label}-System-Audit",
            defense_score_percentage=round(score, 1),
            threat_level=threat,
            vulnerabilities_identified=vulnerabilities,
            mitigations_recommended=mitigations,
            hardware_features_active=active,
        )

    @classmethod
    def run_full_assessment(
        cls,
        temperature_celsius: float = 25.0,
        time_elapsed_seconds: float = 10.0,
        master_key_bits: int = 128,
        test_hex_key: Optional[str] = None,
        has_tresor: bool = False,
        has_tme: bool = False,
        has_mor: bool = False,
        has_tamper: bool = False,
        has_secure_boot: bool = False,
        ram_type: str = "DDR4",
    ) -> SimulationReport:
        therm = cls.compute_thermal_profile(temperature_celsius, time_elapsed_seconds)
        entropy = cls.evaluate_key_reconstruction(master_key_bits, therm.expected_bit_error_rate)
        cm = cls.evaluate_countermeasures(
            has_tresor_cpu_registers=has_tresor,
            has_total_memory_encryption=has_tme,
            has_power_reset_scrubbing=has_mor,
            has_chassis_tamper_sensor=has_tamper,
            has_secure_boot_lockdown=has_secure_boot,
            ram_type=ram_type,
        )
        simulation = None
        if test_hex_key:
            simulation = cls.simulate_bitstream_decay(
                original_hex_key=test_hex_key,
                temperature_celsius=temperature_celsius,
                time_elapsed_seconds=time_elapsed_seconds,
            )
        return SimulationReport(
            simulation_id=f"COLD-BOOT-{uuid.uuid4().hex[:8].upper()}",
            timestamp_utc=_datetime.datetime.now(_datetime.timezone.utc).isoformat(),
            thermal_profile=therm,
            entropy_metrics=entropy,
            countermeasure=cm,
            synthetic_key_decay_results=simulation,
        )

    @classmethod
    def evaluate_batch_csv(cls, csv_text: str) -> List[SimulationReport]:
        reader = csv.DictReader(io.StringIO(csv_text))
        if not reader.fieldnames:
            raise ValueError("CSV input must include a header row")
        reports: List[SimulationReport] = []
        for row_number, row in enumerate(reader, start=2):
            if not any((value or "").strip() for value in row.values() if isinstance(value, str)):
                continue
            try:
                reports.append(
                    cls.run_full_assessment(
                        temperature_celsius=float(row.get("temperature_celsius") or 25.0),
                        time_elapsed_seconds=float(row.get("time_elapsed_seconds") or 10.0),
                        master_key_bits=int(row.get("master_key_bits") or 128),
                        test_hex_key=(row.get("test_hex_key") or None),
                        has_tresor=_parse_bool(row.get("has_tresor", False)),
                        has_tme=_parse_bool(row.get("has_tme", False)),
                        has_mor=_parse_bool(row.get("has_mor", False)),
                        has_tamper=_parse_bool(row.get("has_tamper", False)),
                        has_secure_boot=_parse_bool(row.get("has_secure_boot", False)),
                        ram_type=row.get("ram_type") or "DDR4",
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid CSV row {row_number}: {exc}") from exc
        return reports
