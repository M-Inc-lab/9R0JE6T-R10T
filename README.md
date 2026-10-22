# 9R0JE6T-R10T (`R3V3R53//F0RG3` v1.0.0)

Cross-platform static binary reconnaissance, mitigation auditing, multi-tool correlation (Native + Radare2 + Ghidra Headless + Capstone), and isolated sandbox profile generation engine.

## Features

- **Cross-Platform Format Reconnaissance (`triage`):** Pure-Python structural parsers for Windows `PE32`/`PE32+`, Linux `ELF32`/`ELF64`, Apple `Mach-O` (`32-bit`, `64-bit`, and `Universal/Fat`), and `JVM Class` bytecode (`0xCAFEBABE` disambiguation), plus SHA-256/MD5 hashing and section entropy calculation.
- **Multi-Engine Correlation (`correlate` & `ghidra-audit`):** Combines native structural parsers with `radare2` (`aa; iIj; aflj`), headless `Ghidra` (`analyzeHeadless` exporting functions, dangerous sink cross-references, and decompiled C pseudocode), and `Capstone` entry-point disassembly using exact virtual-to-file offset mapping.
- **Windows PE Security & IAT/EAT Audit (`win-checksec`, `win-iat`, `win-audit`):** Inspects `ASLR`, `HighEntropyVA`, `DEP/NX`, `CFG`, `SafeSEH`, and `Authenticode` signatures (`pefile` with built-in pure-Python fallback) and maps imported APIs against dangerous capability categories.
- **Linux ELF Security & Dynamic Linking Audit (`elf-audit`):** Parses `PT_DYNAMIC` (`DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`), `.dynsym`/`.symtab` imports and exports, and `NX`, `PIE`, `RELRO` (Full/Partial), `Stack Canary`, and `FORTIFY_SOURCE` mitigations.
- **Apple Mach-O Security, Symbol & Entitlements Audit (`macho-audit`):** Parses `MH_PIE`/stack/heap flags, `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_SYMTAB` imports/exports/canaries, and `LC_CODE_SIGNATURE` (`CS_SuperBlob` + embedded XML entitlements).
- **Hardened Windows Sandbox Profile Generator (`win-sandbox`):** Generates XML-escaped `.wsb` profiles mapping target directories read-only into `C:\Analysis`.
- **Authenticated Colab T4 GPU Bridge (`colab_t4_server.ipynb`, `connect_colab.py`, `gpu_client.py`):** Binds Uvicorn to `127.0.0.1`, enforces Bearer token authentication (`COLAB_BRIDGE_TOKEN`), and restricts remote execution to allowlisted binaries with `shell=False`.

## Quick Start

```bash
# Discover installed reverse-engineering tools
python3 -m reverse_forge.cli detect-tools

# Triage any PE, ELF, Mach-O, or JVM .class binary
python3 -m reverse_forge.cli triage -i /path/to/binary

# Run multi-tool correlation (Native + Radare2 + Ghidra + Capstone)
python3 -m reverse_forge.cli correlate -i /path/to/binary

# Run platform-specific security & capability audits
python3 -m reverse_forge.cli win-audit -i /path/to/binary.exe
python3 -m reverse_forge.cli elf-audit -i /bin/ls
python3 -m reverse_forge.cli macho-audit -i /path/to/macos_binary
python3 -m reverse_forge.cli ghidra-audit -i /path/to/binary

# Run automated security & parser regression test suite
python3 -m unittest discover -s tests -v
```