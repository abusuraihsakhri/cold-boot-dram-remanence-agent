#!/usr/bin/env python3
"""
Cold Boot DRAM Remanence & Key Recovery Defense Engine
------------------------------------------------------
Physics-based modeling of DRAM capacitor charge decay, temperature-dependent
data remanence (Arrhenius model), ground-state decay asymmetry, Shannon entropy
loss, and AES key schedule error correction feasibility (Halderman et al.).

Domain: Hardware Security & Applied Cryptography
Pure Python Standard Library (no external dependencies required).
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Union
import math
import json
import csv
import io
import sys
import random
import binascii


# Physical constants
BOLTZMANN_CONSTANT_EV = 8.617333262145e-5  # eV/K
SILICON_ACTIVATION_ENERGY_EV = 0.65  # eV (DRAM junction/subthreshold leakage activation energy)
ROOM_TEMP_KELVIN = 298.15  # +25 °C
ROOM_TEMP_TAU_SECONDS = 2.5  # Typical room temp retention time constant tau_0


@dataclass
class ThermalDecayProfile:
    """Calculated thermal decay kinetics and remanence parameters."""
    temperature_celsius: float
    temperature_kelvin: float
    time_elapsed_seconds: float
    time_constant_tau_seconds: float
    half_life_seconds: float
    retention_fraction: float  # Fraction of initial charge/signal remaining (0.0 to 1.0)
    expected_bit_error_rate: float  # Expected BER across random data (0.0 to 0.50)
    reconstruction_window_seconds: float  # Time until BER exceeds feasibility threshold (BER > 0.15)


@dataclass
class KeyEntropyMetrics:
    """Information-theoretic and cryptographic metrics for decayed keys."""
    master_key_bits: int  # e.g. 128, 256
    decayed_ber: float
    shannon_entropy_per_bit: float  # H(p)
    residual_mutual_information: float  # 1 - H(p)
    effective_security_bits: float  # master_key_bits * (1 - H(p))
    reconstruction_complexity_tier: str  # 'TRIVIAL', 'EASY', 'FEASIBLE', 'HIGH_INTENSITY', 'INFEASIBLE'
    estimated_search_complexity_log2: float  # Log2 operations required for reconstruction


@dataclass
class CountermeasureAssessment:
    """Security defense evaluation against cold boot extraction."""
    system_profile_name: str
    defense_score_percentage: float  # 0 to 100%
    threat_level: str  # 'CRITICAL_RISK', 'HIGH_RISK', 'MODERATE_RISK', 'PROTECTED', 'IMMUNE'
    vulnerabilities_identified: List[str] = field(default_factory=list)
    mitigations_recommended: List[str] = field(default_factory=list)
    hardware_features_active: List[str] = field(default_factory=list)


@dataclass
class SimulationReport:
    """Unified assessment and simulation output report."""
    simulation_id: str
    timestamp_utc: str
    thermal_profile: ThermalDecayProfile
    entropy_metrics: KeyEntropyMetrics
    countermeasure: CountermeasureAssessment
    synthetic_key_decay_results: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ColdBootRemanenceEngine:
    """
    Algorithmic engine for DRAM data remanence modeling, thermal decay,
    and cold boot attack vulnerability analysis.
    """

    @staticmethod
    def celsius_to_kelvin(celsius: float) -> float:
        """Convert Celsius to Kelvin with absolute zero clamping."""
        kelvin = celsius + 273.15
        if kelvin < 0.001:
            kelvin = 0.001  # Prevent division by zero at absolute zero
        return kelvin

    @classmethod
    def calculate_decay_time_constant(cls, temperature_celsius: float) -> float:
        """
        Calculate the DRAM discharge time constant tau(T) using the Arrhenius equation:
        tau(T) = tau_0 * exp((E_a / k_B) * (1/T - 1/T_0))
        """
        kelvin = cls.celsius_to_kelvin(temperature_celsius)
        
        # Calculate exponent factor: (E_a / k_B) * (1/T - 1/T_0)
        inv_diff = (1.0 / kelvin) - (1.0 / ROOM_TEMP_KELVIN)
        exponent = (SILICON_ACTIVATION_ENERGY_EV / BOLTZMANN_CONSTANT_EV) * inv_diff
        
        # Clamp exponent to prevent floating point overflow in cryogenic temperatures
        if exponent > 60.0:
            exponent = 60.0
        elif exponent < -20.0:
            exponent = -20.0

        tau = ROOM_TEMP_TAU_SECONDS * math.exp(exponent)
        return tau

    @classmethod
    def compute_thermal_profile(cls, temperature_celsius: float, time_elapsed_seconds: float) -> ThermalDecayProfile:
        """
        Compute retention fraction R(t, T) and expected bit error rate over elapsed time.
        """
        t_kelvin = cls.celsius_to_kelvin(temperature_celsius)
        tau = cls.calculate_decay_time_constant(temperature_celsius)
        half_life = tau * math.log(2.0)

        # Fraction of retained charge / uncorrupted signal: R(t) = exp(-t / tau)
        if tau > 0:
            decay_ratio = time_elapsed_seconds / tau
            retention = math.exp(-min(decay_ratio, 50.0))
        else:
            retention = 0.0

        # Unidirectional ground state bit decay:
        # Expected BER for random bits = 0.5 * (1 - exp(-t / tau))
        ber = 0.5 * (1.0 - retention)
        ber = min(max(ber, 0.0), 0.50)

        # Time until BER reaches 0.15 (15% reconstructability threshold):
        # 0.15 = 0.5 * (1 - exp(-t / tau)) => 0.30 = 1 - exp(-t/tau) => exp(-t/tau) = 0.70 => t = -tau * ln(0.70)
        reconstruction_window = -tau * math.log(0.70)

        return ThermalDecayProfile(
            temperature_celsius=round(temperature_celsius, 2),
            temperature_kelvin=round(t_kelvin, 2),
            time_elapsed_seconds=round(time_elapsed_seconds, 2),
            time_constant_tau_seconds=round(tau, 3),
            half_life_seconds=round(half_life, 3),
            retention_fraction=round(retention, 5),
            expected_bit_error_rate=round(ber, 5),
            reconstruction_window_seconds=round(reconstruction_window, 2)
        )

    @staticmethod
    def calculate_shannon_entropy(ber: float) -> float:
        """
        Compute binary Shannon entropy:
        H(p) = -p * log2(p) - (1-p) * log2(1-p)
        """
        if ber <= 0.0 or ber >= 1.0:
            return 0.0
        if math.isclose(ber, 0.5, abs_tol=1e-7):
            return 1.0
        p = min(max(ber, 1e-12), 1.0 - 1e-12)
        return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)

    @classmethod
    def evaluate_key_reconstruction(cls, master_key_bits: int, ber: float) -> KeyEntropyMetrics:
        """
        Evaluate remaining entropy and algorithmic key schedule reconstruction complexity
        based on Halderman-Heninger-Shacham algebraic branch-and-bound benchmarks.
        """
        h_p = cls.calculate_shannon_entropy(ber)
        residual_info = max(0.0, 1.0 - h_p)
        eff_bits = master_key_bits * residual_info

        # AES Key Schedule expansion provides redundancy:
        # AES-128 has 1408 bits in round keys (11 rounds * 128 bits)
        # AES-256 has 1920 bits in round keys (15 rounds * 128 bits)
        # Empirical algorithmic search complexity log2(ops) as a function of BER:
        if ber < 0.02:
            tier = "TRIVIAL"
            log2_ops = 5.0  # Instantaneous (< 1 ms)
        elif ber <= 0.07:
            tier = "EASY"
            log2_ops = 14.0  # < 1 second on single CPU core
        elif ber <= 0.13:
            tier = "FEASIBLE"
            log2_ops = 26.0  # Minutes on modern PC
        elif ber <= 0.20:
            tier = "HIGH_INTENSITY"
            log2_ops = 44.0  # GPU/cluster required (hours to days)
        else:
            tier = "INFEASIBLE"
            log2_ops = min(80.0 + (ber - 0.20) * 200.0, float(master_key_bits))

        return KeyEntropyMetrics(
            master_key_bits=master_key_bits,
            decayed_ber=round(ber, 5),
            shannon_entropy_per_bit=round(h_p, 4),
            residual_mutual_information=round(residual_info, 4),
            effective_security_bits=round(eff_bits, 2),
            reconstruction_complexity_tier=tier,
            estimated_search_complexity_log2=round(log2_ops, 1)
        )

    @classmethod
    def simulate_bitstream_decay(
        cls,
        original_hex_key: str,
        temperature_celsius: float,
        time_elapsed_seconds: float,
        preferred_ground_state: int = 0,
        ground_state_asymmetry: float = 0.95,
        seed: Optional[int] = 42
    ) -> Dict[str, Any]:
        """
        Simulate bitwise DRAM capacitor discharge on a supplied hex key string.
        Flips bits decaying towards preferred ground state (0 or 1) with physical probability.
        """
        if seed is not None:
            random.seed(seed)

        # Convert hex string to binary bit array
        clean_hex = original_hex_key.replace(" ", "").replace("0x", "").strip()
        try:
            key_bytes = bytes.fromhex(clean_hex)
        except ValueError:
            # Fallback to UTF-8 bytes if not valid hex
            key_bytes = clean_hex.encode("utf-8")

        total_bits = len(key_bytes) * 8
        bit_list = []
        for byte in key_bytes:
            for i in range(7, -1, -1):
                bit_list.append((byte >> i) & 1)

        profile = cls.compute_thermal_profile(temperature_celsius, time_elapsed_seconds)
        decay_prob = 1.0 - profile.retention_fraction

        decayed_bits = []
        flipped_count = 0

        for b in bit_list:
            if b != preferred_ground_state:
                # Bit has charge; probabilistically decays towards preferred ground state
                if random.random() < (decay_prob * ground_state_asymmetry):
                    decayed_bits.append(preferred_ground_state)
                    flipped_count += 1
                else:
                    decayed_bits.append(b)
            else:
                # Bit is already in ground state; very low probability of reverse flip (thermal noise)
                reverse_noise_prob = decay_prob * (1.0 - ground_state_asymmetry) * 0.1
                if random.random() < reverse_noise_prob:
                    decayed_bits.append(1 - preferred_ground_state)
                    flipped_count += 1
                else:
                    decayed_bits.append(b)

        # Reconstruct decayed byte string
        decayed_byte_list = bytearray()
        for chunk_idx in range(0, len(decayed_bits), 8):
            chunk = decayed_bits[chunk_idx:chunk_idx + 8]
            byte_val = 0
            for bit in chunk:
                byte_val = (byte_val << 1) | bit
            decayed_byte_list.append(byte_val)

        observed_ber = flipped_count / total_bits if total_bits > 0 else 0.0
        decayed_hex = decayed_byte_list.hex()

        return {
            "original_hex": clean_hex,
            "decayed_hex": decayed_hex,
            "total_bits": total_bits,
            "flipped_bits": flipped_count,
            "hamming_distance": flipped_count,
            "empirical_ber": round(observed_ber, 5),
            "expected_theoretical_ber": profile.expected_bit_error_rate,
            "decay_temperature_celsius": temperature_celsius,
            "decay_time_seconds": time_elapsed_seconds
        }

    @staticmethod
    def evaluate_countermeasures(
        has_tresor_cpu_registers: bool = False,
        has_total_memory_encryption: bool = False,
        has_power_reset_scrubbing: bool = False,
        has_chassis_tamper_sensor: bool = False,
        has_secure_boot_lockdown: bool = False,
        ram_type: str = "DDR4"
    ) -> CountermeasureAssessment:
        """
        Evaluate physical and cryptographic defenses against cold boot attack vectors.
        """
        defense_score = 0.0
        vulnerabilities = []
        mitigations = []
        active_features = []

        if has_tresor_cpu_registers:
            defense_score += 40.0
            active_features.append("TRESOR/Loop-Amnesia CPU Register Key Storage (Keys never touch DRAM)")
        else:
            vulnerabilities.append("Cryptographic keys resides in plaintext in DRAM address space.")
            mitigations.append("Implement CPU-register key storage (e.g. debug/AVX registers) for disk encryption master keys.")

        if has_total_memory_encryption:
            defense_score += 35.0
            active_features.append("Hardware Total Memory Encryption (Intel TME / AMD SME AES-XTS on-the-fly)")
        else:
            vulnerabilities.append("Memory bus traffic and RAM cell contents are unencrypted.")
            mitigations.append("Enable Total Memory Encryption (TME/SME) in BIOS/UEFI firmware.")

        if has_power_reset_scrubbing:
            defense_score += 15.0
            active_features.append("BIOS Memory Overwrite Request (MOR / TCG Platform Reset Attack Mitigation)")
        else:
            vulnerabilities.append("Firmware does not actively zero RAM buffers during reboot transitions.")
            mitigations.append("Enforce TCG MOR bit (Memory Overwrite Request) in firmware.")

        if has_chassis_tamper_sensor:
            defense_score += 10.0
            active_features.append("Anti-tamper chassis sensor with hardware capacitor discharge circuit")
        else:
            vulnerabilities.append("Physical chassis opening does not trigger immediate key erasure.")
            mitigations.append("Integrate chassis intrusion detection with rapid DRAM rail shorting.")

        if has_secure_boot_lockdown:
            defense_score += 5.0
            active_features.append("UEFI Secure Boot (Prevents untrusted USB boot image extraction)")
        else:
            vulnerabilities.append("System allows booting unverified external memory dumping OS images.")
            mitigations.append("Lock down UEFI boot order and enforce Secure Boot with password protection.")

        defense_score = min(defense_score, 100.0)

        if defense_score >= 85.0:
            threat = "PROTECTED"
        elif defense_score >= 60.0:
            threat = "MODERATE_RISK"
        elif defense_score >= 30.0:
            threat = "HIGH_RISK"
        else:
            threat = "CRITICAL_RISK"

        return CountermeasureAssessment(
            system_profile_name=f"{ram_type}-System-Audit",
            defense_score_percentage=round(defense_score, 1),
            threat_level=threat,
            vulnerabilities_identified=vulnerabilities,
            mitigations_recommended=mitigations,
            hardware_features_active=active_features
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
        ram_type: str = "DDR4"
    ) -> SimulationReport:
        """Run unified simulation, entropy calculation, and countermeasure assessment."""
        import datetime
        import uuid

        therm = cls.compute_thermal_profile(temperature_celsius, time_elapsed_seconds)
        entropy = cls.evaluate_key_reconstruction(master_key_bits, therm.expected_bit_error_rate)
        cm = cls.evaluate_countermeasures(
            has_tresor_cpu_registers=has_tresor,
            has_total_memory_encryption=has_tme,
            has_power_reset_scrubbing=has_mor,
            has_chassis_tamper_sensor=has_tamper,
            has_secure_boot_lockdown=has_secure_boot,
            ram_type=ram_type
        )

        sim_key = None
        if test_hex_key:
            sim_key = cls.simulate_bitstream_decay(
                original_hex_key=test_hex_key,
                temperature_celsius=temperature_celsius,
                time_elapsed_seconds=time_elapsed_seconds
            )

        return SimulationReport(
            simulation_id=f"COLD-BOOT-{uuid.uuid4().hex[:8].upper()}",
            timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            thermal_profile=therm,
            entropy_metrics=entropy,
            countermeasure=cm,
            synthetic_key_decay_results=sim_key
        )

    @classmethod
    def evaluate_batch_csv(cls, csv_text: str) -> List[SimulationReport]:
        """Process batch of parameter rows from CSV string."""
        reader = csv.DictReader(io.StringIO(csv_text))
        reports = []
        for row in reader:
            temp = float(row.get("temperature_celsius", 25.0))
            time_s = float(row.get("time_elapsed_seconds", 10.0))
            key_bits = int(row.get("master_key_bits", 128))
            hex_k = row.get("test_hex_key") or None
            tresor = str(row.get("has_tresor", "false")).lower() in ["true", "1", "yes"]
            tme = str(row.get("has_tme", "false")).lower() in ["true", "1", "yes"]
            mor = str(row.get("has_mor", "false")).lower() in ["true", "1", "yes"]
            tamper = str(row.get("has_tamper", "false")).lower() in ["true", "1", "yes"]
            secboot = str(row.get("has_secure_boot", "false")).lower() in ["true", "1", "yes"]
            ram = row.get("ram_type", "DDR4")

            reports.append(cls.run_full_assessment(
                temperature_celsius=temp,
                time_elapsed_seconds=time_s,
                master_key_bits=key_bits,
                test_hex_key=hex_k,
                has_tresor=tresor,
                has_tme=tme,
                has_mor=mor,
                has_tamper=tamper,
                has_secure_boot=secboot,
                ram_type=ram
            ))
        return reports
