# RawrXD Tokenizer - Milestone 4: Determinism and Reference Comparison

**Date:** July 14, 2026  
**Status:** 🔄 **IN PROGRESS**

---

## Objective

Validate that RawrXD's tokenizer + inference pipeline produces **deterministic, reproducible results** that match `llama.cpp` reference implementation within acceptable tolerances.

---

## Success Criteria

| Criterion | Target | Method |
|-----------|--------|--------|
| Determinism | 100% | Same prompt → same tokens (3 runs) |
| Token Match | ≥ 99.9% | RawrXD tokens == llama.cpp tokens |
| Proof Validity | 100% | All checkpoints have valid Merkle roots |
| Hash Consistency | 100% | Vocab hash matches across runs |

---

## Test Plan

### Phase 1: Internal Determinism

```batch
REM Run 3 times with same prompt
for /l %%i in (1,1,3) do (
    test_e2e_inference.exe models\tinyllama.gguf "Hello world" 10
)

REM Verify token sequences match
```

### Phase 2: Reference Comparison

```batch
REM Run llama.cpp
llama-cli -m models\tinyllama.gguf -p "Hello world" -n 10 --seed 42

REM Run RawrXD
test_e2e_inference.exe models\tinyllama.gguf "Hello world" 10

REM Compare token sequences
```

### Phase 3: Proof Validation

```batch
REM Generate with proof export
test_e2e_inference.exe models\tinyllama.gguf "Hello world" 10 --export-proof proof.rawrproof

REM Validate proof
rawrxd-validate-proof.exe proof.rawrproof
```

---

## Comparison Script

Create `scripts/compare_llamacpp_rawrxd.ps1`:

```powershell
param(
    [string]$ModelPath,
    [string]$Prompt,
    [int]$Tokens = 10,
    [int]$Seed = 42
)

# Run llama.cpp
$llamaOutput = & llama-cli -m $ModelPath -p $Prompt -n $Tokens --seed $Seed --temp 0.8 2>$null

# Run RawrXD
$rawrOutput = & test_e2e_inference.exe $ModelPath $Prompt $Tokens

# Compare
Write-Host "=== Comparison ==="
Write-Host "llama.cpp: $llamaOutput"
Write-Host "RawrXD:    $rawrOutput"
```

---

## Expected Results

### Determinism Test

```
Run 1: [1, 22172, 318, ...]
Run 2: [1, 22172, 318, ...]
Run 3: [1, 22172, 318, ...]

✓ Token sequences identical
```

### Reference Comparison

```
llama.cpp tokens: [1, 22172, 318, 281, 1183, 13, ...]
RawrXD tokens:    [1, 22172, 318, 281, 1183, 13, ...]

Match: 10/10 (100%)
✓ Reference match
```

### Proof Validation

```
Proof file: proof.rawrproof
- Merkle root: 0xabc123...
- Checkpoints: 10
- Valid: ✓

✓ Proof validation passed
```

---

## Tolerance Guidelines

| Model Type | Token Match | Numeric Tolerance |
|------------|-------------|-------------------|
| F32 | 100% | ±0.0001% |
| F16 | ≥ 99.9% | ±0.001% |
| Q8_0 | ≥ 99.9% | ±0.01% |
| Q4_0 | ≥ 99.5% | ±0.1% |
| Q4_1 | ≥ 99.5% | ±0.1% |

---

## Commands to Execute

```batch
REM Phase 1: Build and test determinism
build_e2e.bat

REM Run determinism test
test_e2e_inference.exe models\tinyllama.gguf "Hello world" 10

REM Phase 2: Compare with llama.cpp
powershell -File scripts\compare_llamacpp_rawrxd.ps1 -ModelPath models\tinyllama.gguf -Prompt "Hello world" -Tokens 10

REM Phase 3: Validate proof
test_e2e_inference.exe models\tinyllama.gguf "Hello world" 10 --export-proof proof.rawrproof
rawrxd-validate-proof.exe proof.rawrproof
```

---

## Deliverables

- [ ] Determinism test results (3 runs)
- [ ] Reference comparison report
- [ ] Proof validation results
- [ ] Tolerance documentation
- [ ] Comparison script

---

**Milestone 4 - Determinism Validation**
