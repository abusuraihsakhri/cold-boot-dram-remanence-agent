# DRAM Remanence Risk Simulator

### [Open the Live Application →](https://abusuraihsakhri.github.io/cold-boot-dram-remanence-agent/)

A small educational simulator for exploring DRAM data-remanence assumptions after power loss and reviewing common defensive controls relevant to cold-boot threat models.

The repository contains a zero-runtime-dependency Python engine and CLI plus a dependency-free browser interface for GitHub Pages. The thermal model is illustrative: its default time constant and activation-energy parameters are modeling assumptions, not universal DRAM characteristics or hardware-specific predictions.

## Features

- Temperature/time decay simulation with an explicit exponential/Arrhenius-style model.
- Shannon binary-entropy, retained-information, and residual-uncertainty calculations.
- Synthetic asymmetric bit-decay simulation for supplied test material.
- Heuristic comparison of CPU-resident key storage, memory encryption, firmware memory overwrite, tamper response, and verified boot controls.
- Single-scenario CLI, interactive mode, JSON output, and batch CSV processing.
- Responsive light/dark browser UI that runs locally without uploading inputs.

## Important interpretation notes

The simulator does **not** estimate a universal cryptanalytic work factor. Earlier versions labeled retained mutual information as “effective security bits”; v2.1 corrects that interpretation by reporting retained information and residual uncertainty separately. The compatibility field `effective_security_bits` now maps to residual uncertainty.

The default decay parameters are intended for reproducible demonstrations. Real remanence varies by DRAM device, platform, refresh history, temperature, power-off sequence, and acquisition method. Defensive-control scores are transparent heuristic weights, not probabilities or certification results.

## Install and run

```bash
git clone https://github.com/abusuraihsakhri/cold-boot-dram-remanence-agent.git
cd cold-boot-dram-remanence-agent
python -m pip install -e .
cold-boot-remanence --temp -50 --time 60 --key-bits 128 --json
```

Batch processing:

```bash
cold-boot-remanence batch -i sample.csv -o results.csv
```

Run tests:

```bash
python -m pip install -e ".[test]"
python -m pytest -q
```

## Browser application

The Pages application mirrors the small deterministic calculation model in plain JavaScript rather than loading a Python WebAssembly runtime. This keeps the page lightweight and removes a network/runtime dependency. No scenario data is sent to a server.

## References

- Halderman JA, et al. *Lest We Remember: Cold Boot Attacks on Encryption Keys.* USENIX Security 2008.
- Trusted Computing Group. *PC Client Platform Reset Attack Mitigation Specification* (Memory Overwrite Request).
- Intel documentation for Total Memory Encryption (TME/TME-MK).
- AMD documentation for Secure Memory Encryption (SME).

## Browser compatibility

Current versions of Chrome, Edge, Firefox, and Safari are supported. The CLI requires Python 3.10 or newer.

## License

MIT. See [LICENSE](LICENSE).
