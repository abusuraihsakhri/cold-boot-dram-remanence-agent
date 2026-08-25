"""
Pytest integration test suite for cold_boot_defense.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from cold_boot_remanence import ColdBootRemanenceEngine


def test_thermal_kinetics_pytest():
    tau_room = ColdBootRemanenceEngine.calculate_decay_time_constant(25.0)
    tau_cold = ColdBootRemanenceEngine.calculate_decay_time_constant(-50.0)
    assert tau_cold > tau_room

    prof = ColdBootRemanenceEngine.compute_thermal_profile(-50.0, 10.0)
    assert prof.retention_fraction > 0.90
    assert prof.expected_bit_error_rate < 0.05


def test_reconstruction_complexity_pytest():
    m1 = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.01)
    assert m1.reconstruction_complexity_tier == "TRIVIAL"

    m2 = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.35)
    assert m2.reconstruction_complexity_tier == "INFEASIBLE"
