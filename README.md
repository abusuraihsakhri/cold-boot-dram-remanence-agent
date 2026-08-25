# Cold Boot DRAM Remanence & Key Recovery Defense Engine

A physics-based security modeling and cryptographic defense engine for analyzing DRAM data remanence, cold boot attack feasibility, and hardware mitigation strategies. The system models temperature-dependent capacitor discharge kinetics via the **Arrhenius semiconductor leakage relation**, evaluates bit error rate (BER) progression and Shannon entropy loss, and assesses algebraic AES key schedule reconstruction complexity based on the landmark **Halderman-Heninger-Shacham algorithm**.

---

## 1. Physics of Cold Boot Attacks & DRAM Remanence

Dynamic Random-Access Memory (DRAM) cells store digital state ($0$ or $1$) as electrical charge on tiny microscopic capacitors (typically $20\text{--}30\text{ fF}$). In standard operation, internal refresh cycles periodically recharge these capacitors. When power is severed:
1. **Capacitor Discharge:** Leakage current across the access transistor's junction and dielectric causes stored charge to decay toward the cell's natural ground state.
2. **Temperature Dependence:** Lowering DRAM temperature dramatically suppresses subthreshold conduction and junction leakage, extending retention times from seconds at room temperature to minutes (with freeze spray, $-50^\circ\text{C}$) or hours/days (with liquid nitrogen, $-196^\circ\text{C}$).
3. **Exploitation Vector:** An attacker with physical access chills the memory modules, cuts power, reboots into an untrusted memory dumping kernel or transplants the physical DIMM into an analysis system, and extracts residual encryption keys from the decayed memory image.

---

## 2. Mathematical Models & Computational Formulation

### A. Arrhenius Temperature-Dependent Retention Model
The discharge time constant $\tau(T)$ is modeled using the semiconductor Arrhenius equation:
$$\tau(T) = \tau_0 \cdot \exp\left( \frac{E_a}{k_B} \left( \frac{1}{T} - \frac{1}{T_0} \right) \right)$$
where:
- $k_B = 8.617333 \times 10^{-5}\text{ eV/K}$ (Boltzmann constant)
- $E_a \approx 0.65\text{ eV}$ (Silicon subthreshold and p-n junction leakage activation energy)
- $T_0 = 298.15\text{ K}$ ($+25^\circ\text{C}$ room temperature reference)
- $\tau_0 \approx 2.5\text{ seconds}$ (Reference unrefreshed DRAM retention time constant)

### B. Signal Retention and Bit Error Rate (BER)
At elapsed time $t$ after power loss, the fraction of retained charge/signal is:
$$R(t, T) = \exp\left( -\frac{t}{\tau(T)} \right)$$

Due to physical sensing amplifier layout, bits decay asymmetrically toward preferred ground states (predominantly $0$). The expected Bit Error Rate (BER) across randomized memory payload is:
$$\text{BER}(t, T) = \frac{1}{2} \cdot \left( 1 - \exp\left(-\frac{t}{\tau(T)}\right) \right)$$
- At $t=0$: $\text{BER} = 0.0\%$ (perfect retention)
- As $t \to \infty$: $\text{BER} \to 50.0\%$ (complete ground state noise)

### C. Shannon Entropy & Residual Security
The binary Shannon entropy per bit $H(p)$ for a decayed channel with $\text{BER} = p$ is:
$$H(p) = -p \log_2(p) - (1-p) \log_2(1-p)$$
The effective remaining cryptographic security of an $N$-bit key is:
$$\text{EffectiveSecurityBits} = N \cdot (1 - H(p))$$

### D. Key Schedule Reconstruction Complexity Tiers
AES master keys (128 or 256 bits) are expanded into redundant round key schedules (11 or 15 round keys). The Halderman-Heninger-Shacham algebraic reconstruction algorithm exploits this redundancy:

| BER Range | Classification Tier | Search Complexity ($\log_2 \text{ ops}$) | Feasibility Benchmark |
| :---: | :---: | :---: | :--- |
| $\text{BER} < 2\%$ | **TRIVIAL** | $\le 2^{5}$ | Instantaneous ($< 1\text{ ms}$) |
| $2\% \le \text{BER} \le 7\%$ | **EASY** | $\approx 2^{14}$ | $< 1\text{ second}$ on single CPU core |
| $7\% < \text{BER} \le 13\%$ | **FEASIBLE** | $\approx 2^{26}$ | Minutes on a standard workstation |
| $13\% < \text{BER} \le 20\%$ | **HIGH_INTENSITY** | $\approx 2^{44}$ | GPU cluster required ($< 1\text{ week}$) |
| $\text{BER} > 20\%$ | **INFEASIBLE** | $> 2^{80}$ | Computationally intractable |

---

## 3. Hardware Countermeasures & Defenses

1. **CPU Register Key Storage (TRESOR / Loop-Amnesia):** Disk encryption master keys are stored exclusively in CPU debug registers (DR0–DR7) or AVX vector registers and never written to DRAM ($+40\%$ Defense).
2. **Total Memory Encryption (Intel TME / AMD SME):** Hardware memory controller encrypts all DRAM traffic on-the-fly using ephemeral AES-XTS keys ($+35\%$ Defense).
3. **TCG Memory Overwrite Request (MOR):** BIOS/UEFI firmware scrubs and overwrites all RAM banks during boot sequence before booting any external media ($+15\%$ Defense).
4. **Chassis Tamper Detection:** Physical chassis switches trigger instant hardware capacitor discharge across DRAM power rails ($+10\%$ Defense).
5. **UEFI Secure Boot Lockdown:** Prevents loading unauthorized Linux kernels used to dump residual memory ($+5\%$ Defense).

---

## 4. Installation & Quick Start

Requires Python 3.9+ (Pure Python standard library; no external dependencies).

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/cold-boot-dram-remanence-agent.git
cd cold-boot-dram-remanence-agent

# Execute test suite
python -m unittest test_cold_boot_remanence.py
```

---

## 5. Command-Line Interface (CLI)

### Single Scenario Evaluation
```bash
python cli.py --temp -50 --time 45 --key-bits 128 --hex-key 2b7e151628aed2a6abf7158809cf4f3c --tme
```

### Interactive Simulation Mode
```bash
python cli.py -i
```

### Batch CSV Audit & JSON Output
```bash
python cli.py --csv sample.csv --json
```

---

## 6. Test Suite & Verification

The unit test suite in [`test_cold_boot_remanence.py`](file:///C:/Users/abusu/Desktop/Apps-Developed/507-Projects_25Aug/cold-boot-dram-remanence-agent/test_cold_boot_remanence.py) contains 28 tests verifying:
- Arrhenius rate constant scaling across cryogenic ($-196^\circ\text{C}$), sub-zero ($-50^\circ\text{C}$), and ambient ($+25^\circ\text{C}$) regimes.
- Retention fraction and asymptotic BER convergence.
- Binary Shannon entropy and effective security bit calculations.
- Reconstruction complexity tier categorizations (TRIVIAL through INFEASIBLE).
- Bitstream decay simulation with Hamming distance and bit-flip tracking.
- Defense scoring and countermeasure threat level determinations.
- Batch CSV parsing and JSON roundtrips.

```bash
python -m unittest test_cold_boot_remanence.py
# Ran 28 tests in 0.011s -> OK
```

---

## 7. License

MIT License. Authored by Dr. Abu Suraih Sakhri.
