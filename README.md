# Cold Boot DRAM Remanence & Key Recovery Defense Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Standard](https://img.shields.io/badge/Security-IEEE%201619%20%7C%20TCG%20MOR-darkgreen.svg)](https://trustedcomputinggroup.org/)
[![Architecture](https://img.shields.io/badge/Zero--Dependency-Standard%20Library-orange.svg)](cold_boot_remanence.py)

Physics-grounded simulation, information-theoretic degradation modeling, and hardware countermeasure auditor for Dynamic Random-Access Memory (DRAM) data remanence and cold boot attacks.

Based on the seminal hardware security research by **Halderman et al. (USENIX Security 2008)**, this engine models temperature-dependent capacitor charge leakage, asymmetric bit decay kinetics, Shannon entropy decay of retained bitstreams, and computational search complexity for partial AES key schedule reconstruction.

---

## 1. Theoretical Background & Physical Models

DRAM cells store digital information as electric charges within microscopic trench or stacked capacitors ($C_s \approx 20\text{--}30\text{ fF}$). When power is severed, leakage current ($I_{\text{leak}}$) discharges the cell capacitors through subthreshold MOSFET leakage, reverse-biased p-n junction diffusion, and dielectric trap tunneling.

### 1.1 Arrhenius Temperature-Dependent Discharge Kinetics

The leakage rate in silicon semiconductors is strongly dictated by thermal activation. The discharge time constant $\tau(T)$ at absolute temperature $T$ (Kelvin) follows the Arrhenius equation:

$$\tau(T) = \tau_0 \cdot \exp\left( \frac{E_a}{k_B} \cdot \left( \frac{1}{T} - \frac{1}{T_0} \right) \right)$$

Where:
- $\tau_0 \approx 2.5\text{ s}$: Baseline discharge time constant at nominal room temperature ($T_0 = 298.15\text{ K} / +25^\circ\text{C}$).
- $E_a \approx 0.65\text{ eV}$: Effective activation energy for subthreshold and silicon junction leakage.
- $k_B \approx 8.61733 \times 10^{-5}\text{ eV/K}$: Boltzmann constant.
- $T$: Operating temperature in Kelvin ($T_K = T_{^\circ\text{C}} + 273.15$).

The capacitor discharge half-life $t_{1/2}$ is given by:

$$t_{1/2} = \tau(T) \cdot \ln(2) \approx 0.69315 \cdot \tau(T)$$

Charge retention follows exponential decay:

$$Q(t) = Q_0 \cdot e^{-t / \tau(T)}$$

### 1.2 Bit Error Rate (BER) & Ground-State Asymmetry

DRAM cells typically decay towards an asymmetric physical ground state (unenergized capacitor voltage $V_{\text{cell}} \to 0\text{ V}$):
- Cells representing logical `0` as discharged capacitors retain their state indefinitely ($0 \to 0$).
- Cells representing logical `1` as charged capacitors decay over time to `0` ($1 \to 0$).
- Across uniformly balanced cryptographic material (e.g., AES keys where $P(1) = P(0) = 0.5$), the expected macroscopic Bit Error Rate (BER) across all bits is:

$$\text{BER}(t, T) = \frac{1}{2} \cdot \left(1 - e^{-t / \tau(T)}\right)$$

As $t \to \infty$, the expected BER asymptotically approaches $0.50$ (complete randomness or saturation into the ground state).

### 1.3 Shannon Entropy Loss & Key Recovery Feasibility

Given a symmetric channel error probability $p = \text{BER}$, the binary Shannon entropy per bit $H(p)$ is:

$$H(p) = -p \log_2(p) - (1-p) \log_2(1-p)$$

Residual mutual information remaining in the decayed memory is $I(X; Y) = 1 - H(p)$. The effective security strength $S_{\text{eff}}$ of an $n$-bit master key degrades to:

$$S_{\text{eff}} = n \cdot (1 - H(p))$$

| Bit Error Rate (BER) | Shannon Entropy $H(p)$ | Effective Security (128-bit) | Reconstruction Complexity Tier | Estimated Brute-Force Ops |
|:--------------------:|:----------------------:|:----------------------------:|:------------------------------:|:-------------------------:|
| $\le 1.0\%$          | $\le 0.0808\text{ bits}$| $117.7\text{--}128.0\text{ bits}$ | **TRIVIAL** | $\le 2^{10}$ |
| $1.0\% < \text{BER} \le 5.0\%$ | $0.0808\text{--}0.2864\text{ bits}$ | $91.3\text{--}117.7\text{ bits}$ | **EASY** | $\approx 2^{10}\text{--}2^{20}$ |
| $5.0\% < \text{BER} \le 15.0\%$ | $0.2864\text{--}0.6098\text{ bits}$ | $49.9\text{--}91.3\text{ bits}$ | **FEASIBLE** | $\approx 2^{20}\text{--}2^{45}$ |
| $15.0\% < \text{BER} \le 30.0\%$ | $0.6098\text{--}0.8813\text{ bits}$ | $15.2\text{--}49.9\text{ bits}$ | **HIGH_INTENSITY** | $\approx 2^{45}\text{--}2^{85}$ |
| $> 30.0\%$           | $> 0.8813\text{ bits}$ | $< 15.2\text{ bits}$         | **INFEASIBLE** | $> 2^{85}$ |

When key schedule expansion states (e.g., 10 round keys for AES-128 or 14 for AES-256) are present in memory, redundancy allows branch-and-bound pruning algorithms to reconstruct corrupted master keys even at BERs up to 10–15%.

---

## 2. Thermal Decay Reference Table

Calculated decay dynamics for standard cooling regimes:

| Regime | Temp ($^\circ\text{C}$) | Temp (K) | Time Constant $\tau$ | Half-Life $t_{1/2}$ | BER after 60s | Reconstruction Window (BER $\le 15\%$) |
|:-------|:-----------------------:|:--------:|:--------------------:|:-------------------:|:-------------:|:--------------------------------------:|
| Room Ambient | $+25^\circ\text{C}$ | $298.15\text{ K}$ | $2.50\text{ s}$ | $1.73\text{ s}$ | $50.00\%$ | $0.89\text{ seconds}$ |
| Refrigeration | $+4^\circ\text{C}$ | $277.15\text{ K}$ | $17.00\text{ s}$ | $11.78\text{ s}$ | $48.54\%$ | $6.06\text{ seconds}$ |
| Commercial Freeze Spray | $-50^\circ\text{C}$ | $223.15\text{ K}$ | $12,323\text{ s}$ | $8,542\text{ s}$ | $0.24\%$ | $4,395\text{ s}$ (~1.2 hours) |
| Liquid Nitrogen ($\text{LN}_2$) | $-196^\circ\text{C}$ | $77.15\text{ K}$ | $2.85 \times 10^{26}\text{ s}$ | $1.98 \times 10^{26}\text{ s}$ | $0.00\%$ | $> 10^{18}\text{ years}$ |

---

## 3. Hardware Countermeasures & Defenses

Modern hardware and firmware implement multi-layered defenses against physical cold boot and memory bus interposition attacks:

```
+-----------------------------------------------------------------------------+
|                          DEFENSE-IN-DEPTH MATRIX                            |
+------------------------------------+--------+-------------------------------+
| Countermeasure Mechanism           | Weight | Protection Profile            |
+------------------------------------+--------+-------------------------------+
| TRESOR / CPU Register Key Storage  | +40%   | Keys never leave CPU cache/reg|
| Total Memory Encryption (TME/SME)  | +35%   | AES-XTS memory bus scrambling |
| TCG Platform Reset (MOR bit)       | +15%   | Firmware memory zeroing       |
| UEFI Secure Boot Lockdown          | +5%    | Prevents untrusted bootloader |
| Chassis Tamper Intrusion Loop      | +5%    | Hardware DRAM rail discharge  |
+------------------------------------+--------+-------------------------------+
| Total Defense Posture Score        | 100%   | PROTECTED Status              |
+------------------------------------+--------+-------------------------------+
```

1. **CPU Register Storage (TRESOR, Loop-Amnesia)**: Master disk encryption keys reside exclusively inside CPU debug registers (DR0–DR7) or AVX registers; plaintext key bytes are never written to DRAM chips.
2. **Total Memory Encryption (Intel TME, AMD SME)**: Memory controllers automatically encrypt all data crossing the bus with ephemeral AES-XTS keys generated per power cycle.
3. **TCG Memory Overwrite Request (MOR)**: Firmware zeros all DRAM address spaces during non-clean reboot sequences before handing execution to external media.
4. **Active Chassis Tamper Loops**: Micro-switches detect physical enclosure opening and immediately trip high-speed crowbar circuits to short DRAM supply rails to ground.

---

## 4. Installation & Requirements

The engine requires **Python 3.10+** and uses **only standard library modules** for core calculations.

```bash
# Clone repository
git clone https://github.com/abusuraihsakhri/cold-boot-dram-remanence-engine.git
cd cold-boot-dram-remanence-engine

# Verify test suite
python -m pytest -p no:zarr
```

---

## 5. CLI Usage & Quickstart

The CLI supports interactive analysis, single-shot simulation, and batch CSV execution.

### 5.1 Batch CSV Execution (Recommended)

Audit multiple physical scenarios and export structured security metrics:

```bash
# Process batch CSV and output results to a CSV file
python cli.py batch -i sample.csv -o results.csv

# Process batch CSV and stream formatted audit reports to stdout
python cli.py batch -i sample.csv

# Output structured JSON
python cli.py batch -i sample.csv --json
```

### 5.2 Direct Parameter Execution

Analyze an individual cold boot attack configuration:

```bash
# Simulation of freeze-spray attack (-50 °C, 60s delay, 128-bit AES)
python cli.py --temp -50.0 --time 60.0 --key-bits 128 --hex-key 2b7e151628aed2a6abf7158809cf4f3c

# Simulation with hardware defenses enabled (TME and MOR)
python cli.py --temp -50.0 --time 60.0 --tme --mor --secure-boot
```

### 5.3 Interactive Mode

Launch guided diagnostic interview:

```bash
python cli.py -i
```

---

## 6. Batch CSV Format

Input CSV files accept the following schema (`sample.csv`):

```csv
temperature_celsius,time_elapsed_seconds,master_key_bits,test_hex_key,has_tresor,has_tme,has_mor,has_tamper,has_secure_boot,ram_type
25.0,5.0,128,2b7e151628aed2a6abf7158809cf4f3c,false,false,false,false,true,DDR4
-50.0,60.0,128,2b7e151628aed2a6abf7158809cf4f3c,false,false,true,false,true,DDR4
-196.0,300.0,256,603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4,true,true,true,true,true,DDR5
4.0,15.0,128,00112233445566778899aabbccddeeff,false,true,false,false,true,LPDDR5
```

---

## 7. Verification & Testing

Execute the test suite covering Arrhenius kinetics, entropy equations, countermeasure scoring, bitstream decay, and CLI subcommands:

```bash
python -m pytest -v -p no:zarr
```

---

## 8. References

- **Halderman, J. A., et al. (2008).** *"Lest We Remember: Cold Boot Attacks on Encryption Keys."* Proceedings of the 17th USENIX Security Symposium.
- **Müller, T., & Freiling, F. C. (2011).** *"TRESOR: Runs Encryption Securely Outside RAM."* Proceedings of the 20th USENIX Security Symposium.
- **TCG Platform Reset Attack Mitigation Specification.** Trusted Computing Group (TCG) PC Client Work Group.
- **Intel Total Memory Encryption (TME) Architecture Specification.** Intel Corporation.

---

## 9. License

This project is licensed under the [MIT License](LICENSE).
