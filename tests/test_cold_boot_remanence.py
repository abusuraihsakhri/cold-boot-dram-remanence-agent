import json
import random

import pytest

from cold_boot_remanence import ColdBootRemanenceEngine, ROOM_TEMP_TAU_SECONDS


def test_room_temperature_baseline():
    assert ColdBootRemanenceEngine.calculate_decay_time_constant(25.0) == pytest.approx(ROOM_TEMP_TAU_SECONDS)


def test_cooling_increases_model_time_constant():
    assert ColdBootRemanenceEngine.calculate_decay_time_constant(-50.0) > ColdBootRemanenceEngine.calculate_decay_time_constant(25.0)


def test_invalid_physical_inputs_are_rejected():
    with pytest.raises(ValueError):
        ColdBootRemanenceEngine.celsius_to_kelvin(-273.15)
    with pytest.raises(ValueError):
        ColdBootRemanenceEngine.compute_thermal_profile(25.0, -1.0)
    with pytest.raises(ValueError):
        ColdBootRemanenceEngine.calculate_shannon_entropy(0.7)


def test_zero_time_has_full_retention():
    p = ColdBootRemanenceEngine.compute_thermal_profile(25.0, 0.0)
    assert p.retention_fraction == 1.0
    assert p.expected_bit_error_rate == 0.0


def test_information_metrics_have_correct_direction():
    low = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.0)
    high = ColdBootRemanenceEngine.evaluate_key_reconstruction(128, 0.5)
    assert low.retained_information_bits == pytest.approx(128.0)
    assert low.residual_uncertainty_bits == pytest.approx(0.0)
    assert high.retained_information_bits == pytest.approx(0.0)
    assert high.residual_uncertainty_bits == pytest.approx(128.0)
    assert high.effective_security_bits == high.residual_uncertainty_bits
    assert high.estimated_search_complexity_log2 is None


def test_synthetic_decay_does_not_mutate_global_rng_state():
    random.seed(1234)
    expected = random.random()
    random.seed(1234)
    ColdBootRemanenceEngine.simulate_bitstream_decay("ff" * 16, 25.0, 5.0, seed=42)
    actual = random.random()
    assert actual == expected


def test_synthetic_decay_zero_time():
    key = "00112233445566778899aabbccddeeff"
    result = ColdBootRemanenceEngine.simulate_bitstream_decay(key, 25.0, 0.0)
    assert result["flipped_bits"] == 0
    assert result["decayed_hex"] == key


def test_countermeasure_weights_sum_to_100():
    c = ColdBootRemanenceEngine.evaluate_countermeasures(True, True, True, True, True)
    assert c.defense_score_percentage == 100.0
    assert c.threat_level == "STRONG_CONTROLS"


def test_batch_csv_and_error_context():
    good = (
        "temperature_celsius,time_elapsed_seconds,master_key_bits,has_tme\n"
        "25,5,128,false\n-50,60,256,true\n"
    )
    assert len(ColdBootRemanenceEngine.evaluate_batch_csv(good)) == 2
    bad = "temperature_celsius,time_elapsed_seconds\n25,-2\n"
    with pytest.raises(ValueError, match="row 2"):
        ColdBootRemanenceEngine.evaluate_batch_csv(bad)


def test_json_is_strict_json():
    report = ColdBootRemanenceEngine.run_full_assessment(25.0, 1.0)
    parsed = json.loads(report.to_json())
    assert parsed["model_assumptions"]
