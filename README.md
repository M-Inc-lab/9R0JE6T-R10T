# 9R0JE6T-R10T (`R3V3R53//F0RG3` v1.0.0)

Autonomous, multi-tool cross-platform reverse engineering, static/dynamic correlation, and vulnerability research engine implementing the **R3V3RSE//F0RG3 v1.0** specification.

## Architecture & Module Inventory (Phases 1–9)

| Module | Spec Mapping | Capabilities |
| :--- | :--- | :--- |
| `reverse_forge/cli.py` | §00, §15 | Unified CLI orchestrating 18 subcommands across static, dynamic, taint, crypto, and pipeline workflows. |
| `reverse_forge/provenance.py` | §01, §03.1, §04 | Cryptographic provenance (`SHA-256`, `SHA-1`, `MD5`), `ScopeLedger` authorization checks, and read-only working-copy isolation (`0444`). |
| `reverse_forge/layer_unpacker.py` | §01.4, §04.2 | Multi-layer container signature scanner (`ZIP`, `GZIP`, `SquashFS`, `U-Boot`), `.NET CLR` metadata inspector, `JAR`/`WAR` manifest/class analyzer, and Universal Mach-O slice parser. |
| `reverse_forge/pe_analyzer.py` & `windows_engine.py` | §01.1, §05, §13.1 | Pure-Python + `pefile` PE32/PE32+ header, section, mitigation (`ASLR`, `DEP`, `CFG`, `SafeSEH`), Authenticode (`$env:RF_TARGET_PATH`), and IAT/EAT capability auditor. |
| `reverse_forge/elf_analyzer.py` | §01.2, §05, §13.5 | ELF32/ELF64 segment, section, `PT_DYNAMIC` (`DT_NEEDED`, `RPATH`, `RUNPATH`), `.dynsym`/`.symtab` symbol, and mitigation (`NX`, `PIE`, `Full/Partial RELRO`, `Canary`, `FORTIFY_SOURCE`) auditor. |
| `reverse_forge/macho_analyzer.py` | §01.3, §05, §13.6 | Mach-O 32/64/Fat parser with `JVM .class` (`0xCAFEBABE`) disambiguation, `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_SYMTAB`, and `LC_CODE_SIGNATURE` (`CS_SuperBlob` + XML entitlements) auditor. |
| `reverse_forge/ghidra_analyzer.py` & `correlation_engine.py` | §02.1–§02.4 | Multi-tool orchestrator combining Native Parsers, `Radare2` (`aa; iIj; aflj`), headless `Ghidra` (`analyzeHeadless` exporting functions, sink xrefs, and decompiled C pseudocode), and `Capstone` entry-point disassembly. |
| `reverse_forge/dataflow_engine.py` | §05.3, §09, §10 | Directed call-graph builder and BFS source-to-sink taint reachability engine (`recv`/`fread`/`getenv` to `strcpy`/`sprintf`/`system`/`free`). |
| `reverse_forge/crypto_engine.py` | §14 | Binary constant scanner (`MD5`, `SHA-1`, `SHA-256`, `AES Rcon/S-Box`) and masked hardcoded secret detector (`RSA/PEM`, `AWS AKIA`, `JWT`, generic API keys). |
| `reverse_forge/windows_sandbox.py` & `behavioral_engine.py` | §07, §08 | Hardened `.wsb` XML generator, PowerShell telemetry collector script generator, and runtime trace (`process`, `file`, `registry`, `network`, `crash`) to static indicator correlator. |
| `reverse_forge/pipeline.py` & `reporter.py` | §03.2, §16–§19 | 12-stage state machine (`Stage 0`–`Stage 11`) with `AutonomyLevel` (`0`–`4`) HIL gates, `AntiLoopGuard`, and dual Executive Summary + Technical 5WH report generator (JSON & Markdown). |
| `reverse_forge/remediation_engine.py` | §20–§22 | Automated C/C++ unified diff patch synthesizer, compiler hardening flag recommender, and standalone C regression test harness generator mapped by CWE. |

## Quick Start

```bash
# Run the full 12-stage autonomous pipeline (outputs Executive + Technical Markdown/JSON reports)
python3 -m reverse_forge.cli pipeline -i /path/to/binary --autonomy 3 --output-md report.md --output-json report.json

# Platform-specific deep static audits
python3 -m reverse_forge.cli win-audit -i /path/to/binary.exe
python3 -m reverse_forge.cli elf-audit -i /bin/ls
python3 -m reverse_forge.cli macho-audit -i /path/to/macos_binary
python3 -m reverse_forge.cli ghidra-audit -i /path/to/binary

# Specialized analysis engines
python3 -m reverse_forge.cli unpack -i /path/to/container_or_dotnet.exe
python3 -m reverse_forge.cli dataflow -i /path/to/binary
python3 -m reverse_forge.cli crypto-audit -i /path/to/binary
python3 -m reverse_forge.cli behavioral-correlate -t telemetry_trace.json -b /path/to/binary
python3 -m reverse_forge.cli remediate --cwe CWE-120 --symbol parse_packet

# Run the 31-test automated security & functional regression suite
python3 -m unittest discover -s tests -v
```
