# Schema Freeze v2.0.0
## Immutable Evidence Format

**Version:** 2.0.0  
**Date:** 2026-07-18  
**Status:** FROZEN

---

## Freeze Declaration

This document certifies that the **RawrXD Validation Evidence Schema v2.0.0** is now **frozen**.

### What This Means

- ✅ Schema is stable and production-ready
- ✅ All evidence produced with this schema is valid
- ✅ Future changes require new schema version
- ❌ No modifications to v2.0.0 schema definition

### Versioning Rules

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| New optional field | Patch (2.0.1) | Add `timing.gpu_ms` |
| New required field | Minor (2.1.0) | Add `hardware.gpu_driver` |
| Breaking change | Major (3.0.0) | Remove `invariants` object |
| Schema restructuring | Major (3.0.0) | Rename `observations` to `raw_data` |

---

## Schema Definition (Frozen)

### Root Object

```json
{
  "schema_version": {
    "type": "string",
    "pattern": "^\\d+\\.\\d+\\.\\d+$",
    "const": "2.0.0",
    "description": "Schema version, must be 2.0.0"
  },
  "evidence_format": {
    "type": "string",
    "const": "rawrxd-val-019-v2",
    "description": "Evidence format identifier"
  }
}
```

### Required Fields

```json
{
  "run_metadata": { "$ref": "#/definitions/RunMetadata" },
  "environment": { "$ref": "#/definitions/Environment" },
  "git_provenance": { "$ref": "#/definitions/GitProvenance" },
  "artifact_under_test": { "$ref": "#/definitions/ArtifactUnderTest" },
  "validators": { "$ref": "#/definitions/Validators" },
  "stages": { "$ref": "#/definitions/Stages" },
  "summary": { "$ref": "#/definitions/Summary" },
  "integrity": { "$ref": "#/definitions/Integrity" }
}
```

### Field Definitions

#### RunMetadata

```json
{
  "type": "object",
  "required": ["id", "timestamp", "state"],
  "properties": {
    "id": { "type": "string", "pattern": "^run-\\d{6}$" },
    "timestamp": { "type": "string", "format": "date-time" },
    "state": {
      "enum": ["DESIGNED", "IMPLEMENTED", "BUILT", "EXECUTED", "VALIDATED", "VERIFIED", "ARCHIVED"]
    },
    "previous_run": { "type": ["string", "null"] },
    "next_run": { "type": ["string", "null"] }
  }
}
```

#### Environment

```json
{
  "type": "object",
  "required": ["os", "cpu", "compiler"],
  "properties": {
    "os": {
      "type": "object",
      "required": ["name", "version"],
      "properties": {
        "name": { "type": "string" },
        "version": { "type": "string" },
        "build": { "type": "string" },
        "architecture": { "type": "string" }
      }
    },
    "cpu": {
      "type": "object",
      "required": ["vendor", "model"],
      "properties": {
        "vendor": { "type": "string" },
        "model": { "type": "string" },
        "cores": { "type": "integer" },
        "logical_processors": { "type": "integer" },
        "features": { "type": "array", "items": { "type": "string" } }
      }
    },
    "compiler": {
      "type": "object",
      "required": ["name", "version"],
      "properties": {
        "name": { "type": "string" },
        "version": { "type": "string" },
        "flags": { "type": "string" },
        "optimization": { "type": "string" },
        "build_type": { "type": "string" }
      }
    }
  }
}
```

#### GitProvenance

```json
{
  "type": "object",
  "required": ["commit", "dirty"],
  "properties": {
    "commit": { "type": "string", "pattern": "^[a-f0-9]{40}$" },
    "abbrev": { "type": "string", "pattern": "^[a-f0-9]{7,}$" },
    "branch": { "type": "string" },
    "remote": { "type": "string" },
    "remote_url": { "type": "string", "format": "uri" },
    "dirty": { "type": "boolean" },
    "dirty_files": { "type": "array", "items": { "type": "string" } },
    "submodules": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "path": { "type": "string" },
          "commit": { "type": "string" },
          "dirty": { "type": "boolean" }
        }
      }
    },
    "describe": { "type": "string" },
    "tags": { "type": "array", "items": { "type": "string" } },
    "author": { "type": "string" },
    "timestamp": { "type": "string", "format": "date-time" },
    "message": { "type": "string" }
  }
}
```

#### ArtifactUnderTest

```json
{
  "type": "object",
  "required": ["path"],
  "properties": {
    "path": { "type": ["string", "null"] },
    "filename": { "type": ["string", "null"] },
    "size_bytes": { "type": ["integer", "null"] },
    "sha256": { "type": ["string", "null"], "pattern": "^sha256:[a-f0-9]{64}$" },
    "modified_utc": { "type": ["string", "null"], "format": "date-time" },
    "source": { "type": ["string", "null"] },
    "quantization": { "type": ["string", "null"] },
    "parameters": { "type": ["string", "null"] },
    "context_length": { "type": ["integer", "null"] },
    "vocab_size": { "type": ["integer", "null"] },
    "embedding_length": { "type": ["integer", "null"] },
    "attention_heads": { "type": ["integer", "null"] },
    "layer_count": { "type": ["integer", "null"] }
  }
}
```

#### Stage

```json
{
  "type": "object",
  "required": ["name", "state"],
  "properties": {
    "name": { "type": "string" },
    "state": {
      "enum": ["DESIGNED", "IMPLEMENTED", "BUILT", "EXECUTED", "VALIDATED", "VERIFIED", "ARCHIVED"]
    },
    "kernel_version": { "type": "string" },
    "tolerance": { "type": "number" },
    "acceptance_criteria": { "type": "object" },
    "observations": { "type": ["object", "null"] },
    "conclusions": { "type": ["object", "null"] }
  }
}
```

#### Observations

```json
{
  "type": "object",
  "properties": {
    "timestamp_start": { "type": "string", "format": "date-time" },
    "timestamp_end": { "type": "string", "format": "date-time" },
    "timing": {
      "type": "object",
      "properties": {
        "parse_ms": { "type": "number" },
        "tensor_load_ms": { "type": "number" },
        "kernel_execution_ms": { "type": "number" },
        "comparison_ms": { "type": "number" },
        "total_ms": { "type": "number" }
      }
    },
    "tensor_metrics": {
      "type": "object",
      "properties": {
        "input_shape": { "type": "array", "items": { "type": "integer" } },
        "output_shape": { "type": "array", "items": { "type": "integer" } },
        "input_element_count": { "type": "integer" },
        "output_element_count": { "type": "integer" },
        "input_min": { "type": "number" },
        "input_max": { "type": "number" },
        "output_min": { "type": "number" },
        "output_max": { "type": "number" },
        "nan_count": { "type": "integer" },
        "inf_count": { "type": "integer" },
        "zero_count": { "type": "integer" }
      }
    },
    "error_metrics": {
      "type": "object",
      "properties": {
        "max_absolute_error": { "type": "number" },
        "mean_absolute_error": { "type": "number" },
        "min_absolute_error": { "type": "number" },
        "error_distribution": { "type": "object" }
      }
    }
  }
}
```

#### Conclusions

```json
{
  "type": "object",
  "properties": {
    "status": { "enum": ["PASS", "FAIL", "INCONCLUSIVE"] },
    "overall_passed": { "type": "boolean" },
    "gate_evaluations": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "criterion": { "type": "string" },
          "observed": {},
          "threshold": {},
          "passed": { "type": "boolean" },
          "confidence": { "enum": ["certain", "high", "medium", "low"] }
        }
      }
    },
    "requires_independent_validation": { "type": "boolean" },
    "notes": { "type": "array", "items": { "type": "string" } }
  }
}
```

#### Integrity

```json
{
  "type": "object",
  "required": ["sealed"],
  "properties": {
    "manifest_sha256": { "type": ["string", "null"], "pattern": "^sha256:[a-f0-9]{64}$" },
    "sealed": { "type": "boolean" },
    "sealed_at": { "type": ["string", "null"], "format": "date-time" }
  }
}
```

---

## Validation

### Schema Validation

All evidence files must validate against this schema:

```python
import json
from jsonschema import validate

with open("schema-v2.0.0.json") as f:
    schema = json.load(f)

with open("evidence.json") as f:
    evidence = json.load(f)

validate(instance=evidence, schema=schema)  # Raises ValidationError if invalid
```

### Version Check

```python
def check_version(evidence):
    version = evidence.get("schema_version")
    if version != "2.0.0":
        raise ValueError(f"Expected schema 2.0.0, got {version}")
```

---

## Migration Path

### From v1.0 to v2.0

| v1.0 Field | v2.0 Field | Action |
|------------|-----------|--------|
| `status` | `run_metadata.state` | Rename |
| `git.commit` | `git_provenance.commit` | Rename |
| `binary_sha256` | `validators[].sha256` | Restructure |
| `timing_ms` | `observations.timing.total_ms` | Nest |
| `max_error` | `observations.error_metrics.max_absolute_error` | Nest |
| N/A | `conclusions` | Add |
| N/A | `integrity` | Add |

### To v3.0 (Future)

When v3.0 is released:
1. Maintain v2.0 evidence reader for backward compatibility
2. Provide migration tool: `migrate-v2-to-v3.py`
3. Archive v2.0 evidence with v2.0 schema reference

---

## Certification

This schema is certified for production use.

**Frozen by:** Validation System Architect  
**Date:** 2026-07-18  
**Commit:** `c2f0eb6aa`  
**Signature:** [Cryptographic signature would go here]

---

## References

- Full specification: `AUDITABLE-SYSTEM-V2.md`
- Golden validation suite: `GOLDEN-VALIDATION-SUITE.md`
- Example evidence: `runs/run-000001-IMPLEMENTED/manifest.json`
