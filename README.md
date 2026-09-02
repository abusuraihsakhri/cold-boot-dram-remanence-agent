# Cold Boot Dram Remanence Agent

> **Domain:** Clinical Decision Support & Biomedical Computing  
> **Reference Guidelines & Standards:** `Standard Clinical Formulations & ISO/IEC Quality Frameworks`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

Cold Boot DRAM Remanence & Key Recovery Defense Engine
------------------------------------------------------
Physics-based modeling of DRAM capacitor charge decay, temperature-dependent
data remanence (Arrhenius model), ground-state decay asymmetry, Shannon entropy
loss, and AES key schedule error correction feasibility (Halderman et al.).

Domain: Hardware Security & Applied Cryptography
Pure Python Standard Library (no external dependencies required).

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`ThermalDecayProfile`**: Calculated thermal decay kinetics and remanence parameters.
- **`KeyEntropyMetrics`**: Information-theoretic and cryptographic metrics for decayed keys.
- **`CountermeasureAssessment`**: Security defense evaluation against cold boot extraction.
- **`SimulationReport`**: Unified assessment and simulation output report.
- **`ColdBootRemanenceEngine`**: Algorithmic engine for DRAM data remanence modeling, thermal decay,
and cold boot attack vulnerability analysis.

---

## 📐 Mathematical Formulation & Logic

```text
  """Calculated thermal decay kinetics and remanence parameters."""
  Calculate the DRAM discharge time constant tau(T) using the Arrhenius equation:
  Calculate exponent factor: (E_a / k_B) * (1/T - 1/T_0)
  tau = cls.calculate_decay_time_constant(temperature_celsius)
  h_p = cls.calculate_shannon_entropy(ber)
```

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --- <value> --interactive <value> --json <value> --csv <value>
```

### Parameter Reference
- `---`: Specifies input measurement or parameter value.
- `--interactive`: Specifies input measurement or parameter value.
- `--json`: Specifies input measurement or parameter value.
- `--csv`: Specifies input measurement or parameter value.
- `--temp`: Specifies input measurement or parameter value.
- `--temperature`: Specifies input measurement or parameter value.
- `--time`: Specifies input measurement or parameter value.
- `--elapsed`: Specifies input measurement or parameter value.
- `--key-bits`: Specifies input measurement or parameter value.
- `--hex-key`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `temperature_celsius` | Parameter / observation metric | Required |
| `time_elapsed_seconds` | Parameter / observation metric | Required |
| `master_key_bits` | Parameter / observation metric | Required |
| `test_hex_key` | Parameter / observation metric | Required |
| `has_tresor` | Parameter / observation metric | Required |
| `has_tme` | Parameter / observation metric | Required |
| `has_mor` | Parameter / observation metric | Required |
| `has_tamper` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t cold-boot-dram-remanence-agent .
docker run -p 8000:8000 cold-boot-dram-remanence-agent
```
