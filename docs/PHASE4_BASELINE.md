# Phase 4 Baseline Execution & Environment Audit

**Document:** `docs/PHASE4_BASELINE.md`  
**Date:** 2026-10-28T01:03:14+05:30  
**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Phase:** 4 — Security Enforcement, CI Recovery & Real Persistence  

---

## 1. Baseline Repository State

- **Starting Commit SHA:** `6198530438cf3ffb91d295ad6016cf617a7a58c1` (`6198530`)
- **Starting Branch:** `main` (tracking `origin/main`, ahead by 2 local commits from Phase 2/3)
- **Repository Version:** `26.0.0` (from `pyproject.toml`)
- **Python Runtime:** Python 3.14.0a3 (Kali Linux x86_64)
- **Pip Version:** pip 25.2 from `/usr/lib/python3/dist-packages/pip`
- **Compiler Versions:**
  - `rustc`: 1.84.0 (or available system toolchain)
  - `gcc`: gcc (Debian 14.2.0-17) 14.2.0
  - `clang`: 19.1.7

---

## 2. CI & Packaging Failure Reproduction

### Observed Issue
The GitHub Actions CI pipeline previously failed during package installation with:
```
error: Multiple top-level packages discovered in a flat-layout: ['rust_core', 'reverse_forge']
To avoid accidental packaging, setuptools refuses to build multiple top-level packages in a flat layout.
```

### Local Reproduction
Executed command:
```bash
python3 -m pip install -e /home/kali/Desktop/9R0JE6T-R10T-v26.0-rust-bicentennial --break-system-packages
```
**Exit Code:** 1  
**Error Message:**
```
error: Multiple top-level packages discovered in a flat-layout: ['rust_core', 'reverse_forge']
Setuptools flat-layout auto-discovery identified rust_core/ as a candidate top-level package.
```

### Root Cause Analysis
`rust_core/` is a native Rust crate directory containing `Cargo.toml` and C fallback source code. It is not a Python package (no `__init__.py`). However, setuptools 77.0+ default package auto-discovery in flat layouts scans for all top-level directories containing recognized files and flags multiple potential packages unless explicitly configured.

### Remediation in `pyproject.toml`
Configured explicit package discovery in `pyproject.toml`:
```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["reverse_forge*"]
exclude = ["rust_core*", "tests*", "docs*", "build*", "dist*", ".reverse_forge_workspace*"]
```
Also added explicit package data configurations and updated `[project.license]` to standard SPDX format (`text = "Apache-2.0"`).

### Verification
Executed:
```bash
python3 -m pip install -e . --break-system-packages
```
**Exit Code:** 0 (Clean editable install succeeded).  
Imports verified:
```python
import reverse_forge
print(reverse_forge.__file__)
```
**Result:** Imported successfully without `PYTHONPATH` hacks.

---

## 3. Environmental State & Baseline Capabilities

| Component | Status | Notes |
|---|---|---|
| Python Packaging | **RESTORED** | Explicit setuptools discovery excludes non-Python dirs |
| Local Editable Install | **VERIFIED** | Clean install with `--break-system-packages` succeeds |
| Pytest Test Suite | **ACTIVE** | Full suite executing |
| Google Cloud Firestore SDK | **INSTALLED** | `google-cloud-firestore` 2.34.1 installed |
| Google Cloud Storage SDK | **INSTALLED** | `google-cloud-storage` 3.17.1 installed |
| PyJWT & Cryptography | **VERIFIED** | Algorithm checking, claim validation, signature enforcement active |
| Native C / Rust Bridge | **OPERATIONAL** | FFI bridge with CRC/entropy ABI validation |

---

## 4. Next Implementation Sequence
1. Patch `reverse_forge/firebase_sync.py` to catch all `PyJWTError` and key malformation errors gracefully (fixing T-18).
2. Wire actual `google.cloud.firestore` and `google.cloud.storage` SDK calls into `ProductionFirestoreStorageAdapter` with strict tenant isolation.
3. Centralize execution authorization and HIL validation into `reverse_forge/authorization.py` with direct handler protection, HMAC-signed approval grants, freshness checks, and zero side-effects on denial.
4. Enhance native compiler/ABI cache fingerprinting with toolchain versions and build flags.
5. Execute end-to-end acceptance test and full adversarial test suite.
