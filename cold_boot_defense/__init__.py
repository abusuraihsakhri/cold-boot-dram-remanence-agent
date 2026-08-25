"""
Cold Boot Attack DRAM Remanence & Key Recovery Defense Package
"""
from cold_boot_remanence import (
    ColdBootRemanenceEngine,
    ThermalDecayProfile,
    KeyEntropyMetrics,
    CountermeasureAssessment,
    SimulationReport,
)

__version__ = "2.0.0"
__all__ = [
    "ColdBootRemanenceEngine",
    "ThermalDecayProfile",
    "KeyEntropyMetrics",
    "CountermeasureAssessment",
    "SimulationReport",
]
