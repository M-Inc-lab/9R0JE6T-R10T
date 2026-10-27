# 9R0JE6T-R10T Machine-Readable Evidence Report Schema
**Schema Version:** 1.0.0-draft  
**Standard:** JSON Schema (Draft 2020-12) / SARIF-compatible Forensic Provenance  

---

## 1. Schema Overview

Every analysis result emitted by `9R0JE6T-R10T` must conform to this schema to ensure:
- Every finding is mathematically anchored to a binary SHA-256 hash and byte offset.
- The exact tool, version, and execution parameters are permanently recorded.
- Findings distinguish between directly observed facts, tool outputs, heuristics, and hypotheses.

---

## 2. JSON Schema Definition

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ReverseForgeForensicReport",
  "type": "object",
  "required": [
    "schema_version",
    "report_id",
    "generated_at_utc",
    "artifact_provenance",
    "execution_metadata",
    "findings",
    "stages"
  ],
  "properties": {
    "schema_version": {
      "type": "string",
      "const": "1.0.0-forensic"
    },
    "report_id": {
      "type": "string",
      "format": "uuid"
    },
    "generated_at_utc": {
      "type": "string",
      "format": "date-time"
    },
    "artifact_provenance": {
      "type": "object",
      "required": ["artifact_name", "sha256", "md5", "file_size_bytes", "format", "architecture"],
      "properties": {
        "artifact_name": { "type": "string" },
        "original_path": { "type": "string" },
        "working_copy_path": { "type": "string" },
        "file_size_bytes": { "type": "integer", "minimum": 0 },
        "sha256": { "type": "string", "pattern": "^[a-f0-9]{64}$" },
        "md5": { "type": "string", "pattern": "^[a-f0-9]{32}$" },
        "sha1": { "type": "string", "pattern": "^[a-f0-9]{40}$" },
        "format": { "type": "string" },
        "architecture": { "type": "string" },
        "entropy": { "type": "number", "minimum": 0.0, "maximum": 8.0 },
        "in_scope": { "type": "boolean" }
      }
    },
    "execution_metadata": {
      "type": "object",
      "required": ["platform_version", "backend_engine", "total_wall_clock_ms"],
      "properties": {
        "platform_version": { "type": "string" },
        "backend_engine": { "type": "string" },
        "native_acceleration_active": { "type": "boolean" },
        "total_wall_clock_ms": { "type": "number" },
        "operator_id": { "type": "string" }
      }
    },
    "stages": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["stage_index", "stage_name", "status", "wall_clock_ms"],
        "properties": {
          "stage_index": { "type": "integer" },
          "stage_name": { "type": "string" },
          "status": { "type": "string", "enum": ["COMPLETED", "FAILED", "SKIPPED"] },
          "wall_clock_ms": { "type": "number" },
          "evidence_count": { "type": "integer" },
          "error": { "type": ["string", "null"] }
        }
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "finding_id",
          "title",
          "severity",
          "provenance_class",
          "evidence_offset",
          "confidence_score"
        ],
        "properties": {
          "finding_id": { "type": "string" },
          "cwe_id": { "type": ["string", "null"] },
          "title": { "type": "string" },
          "severity": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] },
          "provenance_class": {
            "type": "string",
            "enum": ["DIRECT_FACT", "TOOL_DERIVED", "HEURISTIC_INFERENCE", "MODEL_HYPOTHESIS"]
          },
          "evidence_offset": { "type": "string", "description": "Virtual address or raw file offset" },
          "confidence_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
          "description": { "type": "string" },
          "remediation_hint": { "type": ["string", "null"] }
        }
      }
    }
  }
}
```
