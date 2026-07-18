# Golden Validation Suite
## Production-Grade Regression Testing

**Schema Version:** 2.0.0  
**Date:** 2026-07-18  
**Status:** Specification Complete

---

## Test Corpus

### 1. Minimal Valid GGUF
**Purpose:** Baseline validation - smallest possible valid file

```json
{
  "test_id": "GGUF-001",
  "name": "minimal_valid",
  "description": "Smallest possible valid GGUF file",
  "size_bytes": 256,
  "expected_result": "PASS",
  "validation_gates": {
    "magic_number": "GGUF",
    "version": 3,
    "tensor_count": 0,
    "metadata_kv_count": 1
  }
}
```

**Generation:**
```python
# Create minimal GGUF with just header and one metadata entry
header = b'GGUF' + struct.pack('<I', 3)  # magic + version
tensor_count = 0
metadata_kv_count = 1
# ... minimal metadata
```

---

### 2. Valid Production GGUF
**Purpose:** Real-world validation - Phi-3-mini

```json
{
  "test_id": "GGUF-002",
  "name": "phi3_mini_production",
  "description": "Actual production model (Phi-3-mini-4k-instruct-q8_0.gguf)",
  "source": "huggingface:microsoft/Phi-3-mini-4k-instruct",
  "size_bytes": 2176177120,
  "sha256": "sha256:a1b2c3d4...",
  "expected_result": "PASS",
  "validation_gates": {
    "magic_number": "GGUF",
    "version": 3,
    "tensor_count": 195,
    "metadata_kv_count": 23,
    "architecture": "phi3",
    "quantization": "Q8_0"
  }
}
```

---

### 3. Truncated GGUF
**Purpose:** Error handling - file cut short

```json
{
  "test_id": "GGUF-003",
  "name": "truncated_file",
  "description": "Valid header but truncated tensor data",
  "size_bytes": 1024,
  "expected_result": "FAIL",
  "expected_error": "Unexpected end of file",
  "validation_gates": {
    "magic_number": "PASS",
    "version": "PASS",
    "tensor_read": "FAIL - truncated"
  }
}
```

**Generation:**
```python
# Take first 1024 bytes of valid GGUF
truncated = valid_gguf[:1024]
```

---

### 4. Corrupted Metadata
**Purpose:** Error handling - invalid metadata structure

```json
{
  "test_id": "GGUF-004",
  "name": "corrupted_metadata",
  "description": "Valid header but corrupted metadata section",
  "size_bytes": 512,
  "expected_result": "FAIL",
  "expected_error": "Invalid metadata key-value pair",
  "corruption": "Random bytes in metadata section",
  "validation_gates": {
    "magic_number": "PASS",
    "version": "PASS",
    "metadata_parse": "FAIL - corruption detected"
  }
}
```

**Generation:**
```python
# Corrupt metadata section
corrupted = bytearray(valid_gguf)
corrupted[128:256] = os.urandom(128)
```

---

### 5. Invalid Tensor Table
**Purpose:** Error handling - tensor count mismatch

```json
{
  "test_id": "GGUF-005",
  "name": "invalid_tensor_table",
  "description": "Tensor count in header doesn't match actual tensors",
  "size_bytes": 2048,
  "expected_result": "FAIL",
  "expected_error": "Tensor count mismatch",
  "modification": "Header claims 100 tensors, file has 10",
  "validation_gates": {
    "magic_number": "PASS",
    "version": "PASS",
    "tensor_count_integrity": "FAIL - mismatch"
  }
}
```

---

### 6. Alignment Edge Case
**Purpose:** Boundary testing - unusual alignment requirements

```json
{
  "test_id": "GGUF-006",
  "name": "alignment_edge_case",
  "description": "Tensors with unusual alignment requirements",
  "size_bytes": 4096,
  "expected_result": "PASS",
  "alignment_tests": {
    "1_byte_aligned": true,
    "2_byte_aligned": true,
    "4_byte_aligned": true,
    "8_byte_aligned": true,
    "16_byte_aligned": true,
    "32_byte_aligned": true
  }
}
```

---

### 7. Integer Overflow Case
**Purpose:** Security - large values that could overflow

```json
{
  "test_id": "GGUF-007",
  "name": "integer_overflow",
  "description": "Tensor dimensions that could cause integer overflow",
  "size_bytes": 256,
  "expected_result": "FAIL",
  "expected_error": "Tensor dimension overflow",
  "attack_vector": "Dimension set to 0xFFFFFFFF",
  "validation_gates": {
    "magic_number": "PASS",
    "version": "PASS",
    "dimension_sanity": "FAIL - overflow detected"
  }
}
```

---

## Regression Test Suite

### Automated Test Execution

```yaml
# .github/workflows/golden-validation.yml
name: Golden Validation Suite

on:
  push:
    branches: [main, release/*]
  pull_request:
    branches: [main]

jobs:
  golden-tests:
    runs-on: windows-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Validator
        run: |
          cmake -B build -DCMAKE_BUILD_TYPE=Release
          cmake --build build --config Release
          
      - name: Download Golden Corpus
        run: |
          # Download from secure storage
          aws s3 sync s3://rawrxd-golden-corpus/ validation/golden-corpus/
          
      - name: Execute Golden Tests
        run: |
          $results = @()
          
          foreach ($test in Get-ChildItem validation/golden-corpus/*.gguf) {
            $result = & .\build\src\RawrXD_Validator.exe $test.FullName
            $results += @{
              test_id = $test.BaseName
              result = $result.ExitCode -eq 0 ? "PASS" : "FAIL"
              evidence = $result.Output
            }
          }
          
          $results | ConvertTo-Json | Out-File golden-results.json
          
      - name: Compare Against Baseline
        run: |
          $current = Get-Content golden-results.json | ConvertFrom-Json
          $baseline = Get-Content validation/golden-baseline.json | ConvertFrom-Json
          
          # Compare each test result
          foreach ($test in $current) {
            $expected = $baseline | Where-Object { $_.test_id -eq $test.test_id }
            if ($test.result -ne $expected.expected_result) {
              Write-Error "Regression detected: $($test.test_id)"
              exit 1
            }
          }
          
      - name: Archive Evidence
        uses: actions/upload-artifact@v4
        with:
          name: golden-validation-evidence
          path: golden-results.json
```

---

## Evidence Comparison

### Baseline Format

```json
{
  "schema_version": "2.0.0",
  "baseline_date": "2026-07-18",
  "tests": [
    {
      "test_id": "GGUF-001",
      "name": "minimal_valid",
      "expected_result": "PASS",
      "expected_evidence": {
        "magic": "GGUF",
        "version": 3,
        "tensor_count": 0
      }
    },
    {
      "test_id": "GGUF-002",
      "name": "phi3_mini_production",
      "expected_result": "PASS",
      "expected_evidence": {
        "magic": "GGUF",
        "version": 3,
        "tensor_count": 195,
        "architecture": "phi3"
      }
    },
    {
      "test_id": "GGUF-003",
      "name": "truncated_file",
      "expected_result": "FAIL",
      "expected_error": "Unexpected end of file"
    }
  ]
}
```

### Comparison Rules

1. **PASS tests** must produce identical evidence
2. **FAIL tests** must produce expected error
3. **New failures** in previously PASS tests = regression
4. **Unexpected PASS** in FAIL tests = improvement (update baseline)

---

## Independent Parser Parity

### Comparison Targets

| Implementation | Repository | Status |
|---------------|------------|--------|
| llama.cpp | ggml-org/llama.cpp | Reference |
| gguf-py | ggml-org/gguf | Python reference |
| RawrXD | ItsMehRAWRXD/RawrXD | Under test |

### Parity Test

```python
# compare_parity.py
import json
import subprocess

def get_llamacpp_output(gguf_path):
    """Get tensor inventory from llama.cpp"""
    result = subprocess.run(
        ["llama-gguf-dump", gguf_path, "--json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def get_rawrxd_output(gguf_path):
    """Get tensor inventory from RawrXD"""
    result = subprocess.run(
        ["RawrXD_Validator.exe", gguf_path, "--json"],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def compare_outputs(llamacpp, rawrxd):
    """Compare tensor inventories"""
    differences = []
    
    # Compare tensor count
    if len(llamacpp["tensors"]) != len(rawrxd["tensors"]):
        differences.append(f"Tensor count mismatch: {len(llamacpp['tensors'])} vs {len(rawrxd['tensors'])}")
    
    # Compare each tensor
    for i, (l_tensor, r_tensor) in enumerate(zip(llamacpp["tensors"], rawrxd["tensors"])):
        if l_tensor["name"] != r_tensor["name"]:
            differences.append(f"Tensor {i}: name mismatch")
        if l_tensor["shape"] != r_tensor["shape"]:
            differences.append(f"Tensor {i}: shape mismatch")
        if l_tensor["offset"] != r_tensor["offset"]:
            differences.append(f"Tensor {i}: offset mismatch - CRITICAL")
    
    return differences

# Test on multiple models
models = [
    "golden-corpus/phi3-mini.gguf",
    "golden-corpus/llama2-7b.gguf",
    "golden-corpus/mistral-7b.gguf"
]

for model in models:
    print(f"Testing parity for: {model}")
    llama_out = get_llamacpp_output(model)
    rawrxd_out = get_rawrxd_output(model)
    diffs = compare_outputs(llama_out, rawrxd_out)
    
    if diffs:
        print(f"  PARITY FAIL: {len(diffs)} differences")
        for d in diffs[:5]:
            print(f"    - {d}")
    else:
        print(f"  PARITY PASS: Outputs match")
```

---

## CI Integration

### Pre-Commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: golden-validation
        name: Golden Validation Suite
        entry: python validation/run_golden_tests.py --quick
        language: system
        pass_filenames: false
        always_run: true
```

### Release Gates

```yaml
# release-gates.yml
name: Release Validation Gates

on:
  release:
    types: [created]

jobs:
  full-validation:
    runs-on: [windows-latest, ubuntu-latest, macos-latest]
    
    steps:
      - name: Full Golden Suite
        run: python validation/run_golden_tests.py --full
        
      - name: Parser Parity Check
        run: python validation/compare_parity.py --all-models
        
      - name: Evidence Archival
        run: |
          # Archive to permanent storage
          aws s3 cp evidence/ s3://rawrxd-evidence-archive/releases/${{ github.ref }}/
```

---

## Summary

### Test Coverage

| Test ID | Name | Type | Expected | Priority |
|---------|------|------|----------|----------|
| GGUF-001 | minimal_valid | Positive | PASS | Critical |
| GGUF-002 | phi3_mini_production | Positive | PASS | Critical |
| GGUF-003 | truncated_file | Negative | FAIL | High |
| GGUF-004 | corrupted_metadata | Negative | FAIL | High |
| GGUF-005 | invalid_tensor_table | Negative | FAIL | High |
| GGUF-006 | alignment_edge_case | Boundary | PASS | Medium |
| GGUF-007 | integer_overflow | Security | FAIL | Critical |

### Next Steps

1. **Generate golden corpus** - Create all 7 test files
2. **Establish baseline** - Record expected evidence
3. **Integrate into CI** - Automated regression testing
4. **Parser parity** - Compare against llama.cpp
5. **Evidence archival** - S3 storage for immutability

### Success Criteria

- [ ] All 7 golden tests pass
- [ ] CI runs golden suite on every commit
- [ ] Parser parity matches llama.cpp on 3+ models
- [ ] Evidence archived to permanent storage
- [ ] Regression detected automatically
