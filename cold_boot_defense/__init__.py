"""Public package interface for the DRAM remanence risk simulator."""
from cold_boot_remanence import (
    ColdBootRemanenceEngine,
    CountermeasureAssessment,
    KeyEntropyMetrics,
    SimulationReport,
    ThermalDecayProfile,
)

__version__ = "2.1.0"
__all__ = [
    "ColdBootRemanenceEngine",
    "ThermalDecayProfile",
    "KeyEntropyMetrics",
    "CountermeasureAssessment",
    "SimulationReport",
]
