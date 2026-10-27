# 9R0JE6T-R10T (`R3V3R53//F0RG3` v26.0.0)

[![Forensic Verification CI](https://github.com/M-Inc-lab/9R0JE6T-R10T/actions/workflows/ci.yml/badge.svg)](https://github.com/M-Inc-lab/9R0JE6T-R10T/actions/workflows/ci.yml)

A forensic-grade, evidence-driven reverse engineering and binary vulnerability analysis suite.

---

## 1. Authoritative Versioning & Supported Platform Matrix

- **Authoritative Version**: `26.0.0` (Moniker: `rust-bicentennial`).
  - Python Package: `pyproject.toml` (`26.0.0`) & `reverse_forge/__init__.py` (`__version__ = "26.0.0"`, `__release_tag__ = "26.0.0-rust-bicentennial"`)
  - Rust Core Engine: `rust_core/Cargo.toml` (`26.0.0`)
- **Verified Platform**: **Linux x86-64 (AMD64)**
  - Native Rust acceleration, C fallback bridge, and micro-visor execution are formally tested and verified on Linux AMD64.
  - Windows/macOS execution paths are experimental; cross-platform claims are limited to pure-Python parsing layers unless compiled in dedicated native host environments.

---

## 2. Core Architecture & Subsystems

| Subsystem | File Reference | Functionality & Guarantees |
| :--- | :--- | :--- |
| **Fail-Closed Security & HIL** | `reverse_forge/pipeline.py` | 12-stage pipeline state machine. Strict HIL approval gates for dynamic execution, network access, and artifact mutation. ScopeLedger enforces canonical realpath containment. Autonomy levels cannot bypass security policy. |
| **Cryptographic Authentication & Cloud Sync** | `reverse_forge/firebase_sync.py` | PyJWT token verification with signature, expiry (`exp`), and audience/issuer validation. Strict separation of `LocalSimulationPersistenceAdapter` (tenant-isolated memory) and `ProductionFirestoreStorageAdapter`. |
| **Native Multi-Backend Core** | `reverse_forge/native_rust_bridge.py` | Explicit backend identity (`RUST_NATIVE`, `C_FALLBACK`, `PURE_PYTHON`). Cryptographic source fingerprinting, visible compiler diagnostics, ABI verification vectors, and multi-iteration warm-up benchmarks. |
| **Binary Analyzers** | `reverse_forge/pe_analyzer.py`, `elf_analyzer.py` | Deep static inspection of PE32+ (mitigations, sections, Authenticode) and ELF64 (segments, symbols, dynamic linkages). Fail-closed error handling on corrupt or truncated inputs. |
| **Differential Validation** | `tests/test_differential_analysis_validation.py` | Ground-truth concordance against Capstone v5.0.7 (x86-64 instruction lengths and trap handling) and standard FLIRT CRC16 vectors. |
| **Provenance & Audit** | `reverse_forge/provenance.py` | SHA-256 cryptographic hashing, immutable read-only working copy creation (`0444`), and action ledgers. |

---

## 3. Quick Start & CLI Workflows

### Environment Setup
```bash
# Clone repository
git clone https://github.com/M-Inc-lab/9R0JE6T-R10T.git
cd 9R0JE6T-R10T

# Install dependencies and package in editable mode
pip install -e .[all]
```

### Running Analysis
```bash
# Run pipeline with explicit scope authorization
python3 -m reverse_forge.cli pipeline -i /bin/ls --autonomy 2 --output-md report.md --output-json report.json

# Tool discovery and dependency matrix inspection
python3 -m reverse_forge.cli detect-tools

# Static format inspection
python3 -m reverse_forge.cli elf-audit -i /bin/ls
python3 -m reverse_forge.cli win-audit -i /path/to/binary.exe
```

---

## 4. Verification & Testing

The repository maintains strict regression and differential verification test suites:

```bash
# 1. Run security regression tests (Fail-closed HIL, ScopeLedger realpaths, JWT verification)
pytest tests/test_security_regressions.py -v

# 2. Run differential ground-truth analysis tests (Capstone, ELF headers, PE32+ spec)
pytest tests/test_differential_analysis_validation.py -v

# 3. Run multi-tenant Firebase persistence isolation tests
pytest tests/test_firebase_sync.py -v

# 4. Run native Rust/C bridge selection and ABI verification
pytest tests/test_phase86_90_rust_native_core.py -v

# 5. Run native Rust cargo test suite
cargo test --manifest-path rust_core/Cargo.toml

# 6. Run full Python test suite
pytest -v
```

---

## 5. Security Model & Documentation
For detailed architecture, threat modeling, and formal capability bounds, consult:
- `docs/SECOND_PASS_AUDIT.md`: Forensic audit report and baseline findings.
- `docs/SECURITY_MODEL.md`: Fail-closed security architecture, RBAC, and boundary enforcement.
- `docs/CAPABILITY_MATRIX.md`: Verified, heuristic, and simulated capability ledger.
- `docs/ANALYSIS_VALIDATION.md`: Differential verification results against ground truth.
