# VAL-019.1: GGUF Model Loading Specification

**Phase:** 019.1  
**Objective:** Load GGUF model and validate metadata + tensor inventory  
**Status:** IN PROGRESS  
**Evidence:** `val_019_1_evidence.json`

---

## Success Criteria

| Requirement | Method | Pass Condition |
|-------------|--------|----------------|
| Load GGUF header | File I/O | Magic number matches `GGUF` |
| Parse metadata | GGUF spec v3 | All key-value pairs readable |
| Inventory tensors | Tensor info array | Count matches header |
| Access tensor data | Memory mapping | SHA-256 checksum matches |
| Validate alignment | Offset calculation | All tensors aligned to 32 bytes |

---

## Evidence Format

```json
{
  "schema_version": "VAL-019.1",
  "timestamp": "2026-07-17T...",
  "simulation": false,
  "input": {
    "model_path": "models/TinyLlama-1.1B-v1.0.Q4_K_M.gguf",
    "model_sha256": "..."
  },
  "metadata": {
    "gguf_version": 3,
    "tensor_count": 201,
    "metadata_kv_count": 24,
    "architecture": "llama",
    "vocab_size": 32000,
    "embedding_length": 2048,
    "block_count": 22
  },
  "tensors": [
    {
      "name": "token_embd.weight",
      "shape": [32000, 2048],
      "type": "Q4_K",
      "offset": 512,
      "size": 32800000,
      "checksum_sha256": "..."
    }
  ],
  "validation": {
    "header_valid": true,
    "metadata_complete": true,
    "tensor_count_match": true,
    "alignment_valid": true,
    "all_checksums_match": true
  },
  "execution_time_ms": 45.2,
  "status": "PASS"
}
```

---

## Implementation Plan

### Step 1: Extend Existing GGUF Loader

Build on `VAL-017` GGUF loading to add:
- Tensor data access (not just metadata)
- SHA-256 checksum computation
- Evidence JSON output

### Step 2: Create Validation Executable

```cpp
// tests/val_019_1_gguf_loader.cpp
int main(int argc, char** argv) {
    // 1. Load model from argv[1]
    // 2. Parse header and metadata
    // 3. Inventory all tensors
    // 4. Compute checksums for each tensor
    // 5. Write evidence to val_019_1_evidence.json
    // 6. Return 0 on PASS, 1 on FAIL
}
```

### Step 3: Test Model

Use **TinyLlama-1.1B** (Q4_K_M quantized):
- Small enough for fast testing
- Real GGUF format
- Known architecture

---

## Validation Checklist

- [ ] Load GGUF header (magic, version, counts)
- [ ] Parse all metadata key-value pairs
- [ ] Read tensor info array
- [ ] Access each tensor's raw data
- [ ] Compute SHA-256 for each tensor
- [ ] Verify alignment constraints
- [ ] Generate evidence JSON
- [ ] Return PASS/FAIL exit code

---

## Dependencies

- Existing `gguf_loader.cpp` (VAL-017)
- SHA-256 implementation (or OpenSSL)
- nlohmann/json for evidence output
- Test model file

---

## Next Phase

After VAL-019.1 PASS → **VAL-019.2: Tensor Access Validation**
