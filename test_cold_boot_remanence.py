#!/usr/bin/env python3
"""
Comprehensive Unit Test Suite for Cold Boot DRAM Remanence & Defense Engine
Tests Arrhenius thermal decay kinetics, DRAM capacitor discharge physics,
Shannon entropy calculation, key reconstruction complexity tiers, synthetic decay,
countermeasure defense evaluation, and CSV batch processing.
"""

import unittest
import json
import math
from cold_boot_remanence import (
    ColdBootRemanenceEngine,
    ThermalDecayProfile,
    KeyEntropyMetrics,
    CountermeasureAssessment,
    SimulationReport,
    ROOM_TEMP_KELVIN,
    ROOM_TEMP_TAU_SECONDS,
)


class TestDRAMThermalDecayKinetics(unittest.TestCase):
    """Test Arrhenius temperature-dependent DRAM discharge time constant."""

    def test_room_temperature_baseline(self):
        tau = ColdBootRemanenceEngine.calculate_decay_time_constant(25.0)
        self.assertAlmostEqual(tau, ROOM_TEMP_TAU_SECONDS, delta=0.01)

    def test_cooling_increases_time_constant(self):
        tau_room = ColdBootRemanenceEngine.calculate_decay_time_constant(25.0)
        tau_freeze = ColdBootRemanenceEngine.calculate_decay_time_constant(-50.0)
        tau_ln2 = ColdBootRemanenceEngine.calculate_decay_time_constant(-196.0)

        # Cooling dramatically increases retention time constant
        self.assertGreater(tau_freeze, tau_room * 10)
        self.assertGreater(tau_ln2, tau_freeze * 100)

    def test_refrigeration_decay(self):
        tau_4c = ColdBootRemanenceEngine.calculate_decay_time_constant(4.0)
        self.assertGreater(tau_4c, ROOM_TEMP_TAU_SECONDS)

    def test_thermal_profile_zero_time(self):
        profile = ColdBootRemanenceEngine.compute_thermal_profile(25.0, 0.0)
        self.assertEqual(profile.retention_fraction, 1.0)
        self.assertEqual(profile.expected_bit_error_rate, 0.0)

    def test_thermal_profile_infinite_decay_asymptote(self):
        # After a very long time at room temperature, retention goes to 0 and BER reaches 0.50
        profile = ColdBootRemanenceEngine.compute_thermal_profile(25.0, 300.0)
        self.assertAlmostEqual(profile.retention_fraction, 0.0, delta=0.001)
        self.assertAlmostEqual(profile.expected_bit_error_rate, 0.50, delta=0.001)

    def test_half_life_relationship(self):
        profile = ColdBootRemanenceEngine.compute_thermal_profile(25.0, 10.0)
        expected_half_life = profile.time_constant_tau_seconds * math.log(2.0)
        self.assertAlmostEqual(profile.half_life_seconds, expected_half_life, delta=0.01)

    def test_reconstruction_window_calculation(self):
        profile = ColdBootRemanenceEngine.compute_thermal_profile(-50.0, 10.0)
        self.assertGreater(profile.reconstruction_window_seconds, 0.0)


class TestKeyEntropyAndReconstruction(unittest.TestCase):
    """Test Shannon entropy, effective security bits, and algebraic recovery complexity."""

    def test_shannon_entropy_zero_and_fifty_percent(self):
        # 0% error -> 0 entropy
        h_0 = ColdBootRemanenceEngine.calculate_shannon_entropy(0.0)
        self.assertEqual(h_0, 0.0)

        # 50% error -> maximum 1.0 bit entropy
        h_50 = ColdBootRemanenceEngine.calculate_shannon_entropy(0.50)
        self.assertAlmostEqual(h_50, 1.0, delta=1e-5)

    def test_shannon_entropy_intermediate(self):
        # 10% BER: H(0.1) = -0.1*log2(0.1) - 0.9*log2(0.9) ~ 0.469
        h_10 = ColdBootRemanenceEngine.calculate_shannon_entropy(0.10)
        self.assertAlmostEqual(h_10, 0.469, delta=0.01)

    def test_trivial_reconstruction_tier(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.01)
        self.assertEqual(metrics.reconstruction_complexity_tier, "TRIVIAL")
        self.assertLessEqual(metrics.estimated_search_complexity_log2, 10.0)
        self.assertGreater(metrics.effective_security_bits, 110.0)

    def test_easy_reconstruction_tier(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.05)
        self.assertEqual(metrics.reconstruction_complexity_tier, "EASY")

    def test_feasible_reconstruction_tier(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(256, 0.10)
        self.assertEqual(metrics.reconstruction_complexity_tier, "FEASIBLE")

    def test_high_intensity_reconstruction_tier(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.18)
        self.assertEqual(metrics.reconstruction_complexity_tier, "HIGH_INTENSITY")

    def test_infeasible_reconstruction_tier(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.35)
        self.assertEqual(metrics.reconstruction_complexity_tier, "INFEASIBLE")
        self.assertGreater(metrics.estimated_search_complexity_log2, 80.0)


class TestSyntheticKeyDecaySimulation(unittest.TestCase):
    """Test bit-level simulation of DRAM memory decay."""

    def test_simulate_decay_zero_elapsed_time(self):
        sample_hex = "00112233445566778899aabbccddeeff"
        res = ColdBootRemanenceEngine.simulate_bitstream_decay(
            original_hex_key=sample_hex,
            temperature_celsius=25.0,
            time_elapsed_seconds=0.0,
            seed=42
        )
        self.assertEqual(res["flipped_bits"], 0)
        self.assertEqual(res["empirical_ber"], 0.0)
        self.assertEqual(res["decayed_hex"], sample_hex)

    def test_simulate_decay_long_time_causes_flips(self):
        sample_hex = "ffffffffffffffffffffffffffffffff"
        res = ColdBootRemanenceEngine.simulate_bitstream_decay(
            original_hex_key=sample_hex,
            temperature_celsius=25.0,
            time_elapsed_seconds=60.0,
            preferred_ground_state=0,
            seed=42
        )
        # All-1s key decaying to 0 after 60s at room temp should flip almost all bits
        self.assertGreater(res["flipped_bits"], 100)
        self.assertGreater(res["empirical_ber"], 0.80)

    def test_cryogenic_simulation_preserves_bits(self):
        sample_hex = "2b7e151628aed2a6abf7158809cf4f3c"
        res = ColdBootRemanenceEngine.simulate_bitstream_decay(
            original_hex_key=sample_hex,
            temperature_celsius=-196.0,
            time_elapsed_seconds=30.0,
            seed=42
        )
        # Liquid nitrogen keeps retention near 100%
        self.assertEqual(res["flipped_bits"], 0)
        self.assertEqual(res["decayed_hex"], sample_hex)


class TestCountermeasureEvaluation(unittest.TestCase):
    """Test defense evaluation against cold boot vectors."""

    def test_unmitigated_system_critical_risk(self):
        cm = ColdBootRemanenceEngine.evaluate_countermeasures(
            has_tresor_cpu_registers=False,
            has_total_memory_encryption=False,
            has_power_reset_scrubbing=False,
            has_chassis_tamper_sensor=False,
            has_secure_boot_lockdown=False
        )
        self.assertEqual(cm.threat_level, "CRITICAL_RISK")
        self.assertEqual(cm.defense_score_percentage, 0.0)
        self.assertTrue(len(cm.vulnerabilities_identified) >= 4)

    def test_tresor_plus_tme_protected(self):
        cm = ColdBootRemanenceEngine.evaluate_countermeasures(
            has_tresor_cpu_registers=True,
            has_total_memory_encryption=True,
            has_power_reset_scrubbing=True,
            has_chassis_tamper_sensor=True,
            has_secure_boot_lockdown=True
        )
        self.assertEqual(cm.threat_level, "PROTECTED")
        self.assertEqual(cm.defense_score_percentage, 100.0)
        self.assertEqual(len(cm.hardware_features_active), 5)

    def test_partial_mitigation_moderate_risk(self):
        cm = ColdBootRemanenceEngine.evaluate_countermeasures(
            has_tresor_cpu_registers=False,
            has_total_memory_encryption=True,  # +35
            has_power_reset_scrubbing=True,    # +15
            has_chassis_tamper_sensor=False,
            has_secure_boot_lockdown=True      # +5 -> 55 -> HIGH_RISK or MODERATE
        )
        self.assertTrue(cm.threat_level in ["HIGH_RISK", "MODERATE_RISK"])


class TestSerializationAndBatchCSV(unittest.TestCase):
    """Test report generation, serialization, and batch CSV processing."""

    def test_full_assessment_report_json(self):
        rep = ColdBootRemanenceEngine.run_full_assessment(
            temperature_celsius=-50.0,
            time_elapsed_seconds=15.0,
            master_key_bits=256,
            test_hex_key="0123456789abcdef0123456789abcdef",
            has_tresor=True,
            has_tme=True
        )
        self.assertTrue(rep.simulation_id.startswith("COLD-BOOT-"))
        d = rep.to_dict()
        self.assertIn("thermal_profile", d)
        self.assertIn("entropy_metrics", d)
        self.assertIn("countermeasure", d)
        self.assertIn("synthetic_key_decay_results", d)

        json_str = rep.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["thermal_profile"]["temperature_celsius"], -50.0)

    def test_batch_csv_evaluation(self):
        csv_sample = (
            "temperature_celsius,time_elapsed_seconds,master_key_bits,has_tresor,has_tme\n"
            "25.0,5.0,128,false,false\n"
            "-50.0,60.0,256,true,true\n"
            "-196.0,300.0,128,false,true\n"
        )
        reports = ColdBootRemanenceEngine.evaluate_batch_csv(csv_sample)
        self.assertEqual(len(reports), 3)
        self.assertEqual(reports[0].thermal_profile.temperature_celsius, 25.0)
        self.assertEqual(reports[1].thermal_profile.temperature_celsius, -50.0)
        self.assertEqual(reports[2].thermal_profile.temperature_celsius, -196.0)

    def test_format_report_text_helper(self):
        from cli import format_report_text
        rep = ColdBootRemanenceEngine.run_full_assessment(
            temperature_celsius=25.0,
            time_elapsed_seconds=10.0,
            test_hex_key="00112233445566778899aabbccddeeff"
        )
        txt = format_report_text(rep)
        self.assertIn("COLD BOOT ATTACK & DRAM DATA REMANENCE AUDIT REPORT", txt)
        self.assertIn("THERMAL DECAY KINETICS", txt)
        self.assertIn("SYNTHETIC BITSTREAM DECAY SIMULATION", txt)

    def test_absolute_zero_clamping(self):
        kelvin = ColdBootRemanenceEngine.celsius_to_kelvin(-300.0)
        self.assertGreater(kelvin, 0.0)

    def test_different_ram_types(self):
        cm = ColdBootRemanenceEngine.evaluate_countermeasures(ram_type="LPDDR5")
        self.assertEqual(cm.system_profile_name, "LPDDR5-System-Audit")

    def test_key_length_256_metrics(self):
        metrics = ColdBootRemanenceEngine.evaluate_key_reconstruction(256, 0.05)
        self.assertEqual(metrics.master_key_bits, 256)
        self.assertGreater(metrics.effective_security_bits, 180.0)

    def test_preferred_ground_state_one_simulation(self):
        sample_hex = "0000000000000000"
        res = ColdBootRemanenceEngine.simulate_bitstream_decay(
            original_hex_key=sample_hex,
            temperature_celsius=25.0,
            time_elapsed_seconds=60.0,
            preferred_ground_state=1,
            seed=123
        )
        # All-0s key decaying to 1 should flip bits
        self.assertGreater(res["flipped_bits"], 30)

    def test_non_hex_key_utf8_fallback(self):
        res = ColdBootRemanenceEngine.simulate_bitstream_decay(
            original_hex_key="secret_passphrase!",
            temperature_celsius=25.0,
            time_elapsed_seconds=0.0
        )
        self.assertEqual(res["flipped_bits"], 0)


if __name__ == "__main__":
    unittest.main()
