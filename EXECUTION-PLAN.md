# VAL-019 Execution Plan
## From Infrastructure to First PASS

## Current State

```
Artifact validation       ██████████ 100%
Tensor access             ███████░░░ 70%
Embedding execution       ███████░░░ 70%
RMSNorm execution         ███████░░░ 70%
Transformer validation    ██░░░░░░░░ 20%
Generation validation     ░░░░░░░░░░ 0%
```

## Phase 1: Synthetic Vector PASS (Immediate)

### Goal
Get first kernel-backed validation stage to PASS with synthetic data.

### Steps

1. **Compile embedding_stage.cpp**
   ```batch
   cl.exe /EHsc /O2 /W4 embedding_stage.cpp /Fe:embedding_stage.exe
   ```

2. **Run embedding validation**
   ```batch
   embedding_stage.exe ^
       val-019/vectors/embedding_input.bin ^
       val-019/vectors/embedding_expected.bin ^
       val-019/evidence/embedding_actual.bin
   ```

3. **Expected output:**
   ```
   ========================================
     VAL-019: Embedding Stage Validation
   ========================================
   
   [CONFIG] Input:  val-019/vectors/embedding_input.bin
   [CONFIG] Expected: val-019/vectors/embedding_expected.bin
   [CONFIG] Output:   val-019/evidence/embedding_actual.bin
   [CONFIG] Tolerance: 1e-05
   
   ----------------------------------------
   RESULT: PASS
   ----------------------------------------
   Input checksum:  sha256:4f6addc9...
   Output checksum: sha256:51246bdd...
   Max error:       0.000000e+00
   Runtime:         0.500 ms
   Backend:         native
   Kernel:          embedding_lookup_v1.0_native
   
   Evidence JSON:
   ----------------------------------------
   {
     "stage": "embedding",
     "status": "PASS",
     ...
   }
   ```

### Success Criteria
- [ ] embedding_stage.exe builds without errors
- [ ] Execution completes without crashes
- [ ] Max error ≤ 1e-5
- [ ] Evidence JSON generated
- [ ] Exit code 0

---

## Phase 2: RMSNorm with Invariants (Next)

### Goal
Validate numerical reduction operation with comprehensive invariant checks.

### Steps

1. **Compile rmsnorm_stage_v2.cpp**
   ```batch
   cl.exe /EHsc /O2 /W4 rmsnorm_stage_v2.cpp /Fe:rmsnorm_stage.exe
   ```

2. **Run RMSNorm validation**
   ```batch
   rmsnorm_stage.exe ^
       val-019/vectors/rmsnorm_input.bin ^
       val-019/vectors/rmsnorm_expected.bin ^
       val-019/evidence/rmsnorm_actual.bin
   ```

3. **Expected invariant checks:**
   ```
   INVARIANT CHECKS:
     has_nan:              PASS
     has_inf:              PASS
     output_shape_matches: PASS
     rms_range_valid:      PASS
   ```

### Success Criteria
- [ ] rmsnorm_stage.exe builds
- [ ] All invariant checks PASS
- [ ] RMS statistics in valid range
- [ ] Evidence JSON includes invariants section

---

## Phase 3: Unified Pipeline (Short Term)

### Goal
Execute multiple stages in sequence with unified reporting.

### Steps

1. **Compile unified_runner.cpp**
   ```batch
   cl.exe /EHsc /O2 /W4 unified_runner.cpp /Fe:unified_runner.exe
   ```

2. **Run unified validation**
   ```batch
   unified_runner.exe val-019/evidence/unified_report.json
   ```

3. **Expected output:**
   ```
   Executing VAL-019 Validation Pipeline
   =====================================
   
   [PASS] embedding   error=0.00e+00 time=0.50ms
   [PASS] rmsnorm     error=1.00e-07 time=0.80ms
   [SKIP] qkv         - Not implemented
   [SKIP] rope        - Not implemented
   ...
   
   ========================================
     Pipeline Complete: 2/10 stages passed
     Execution Path: 20.0%
   ========================================
   ```

### Success Criteria
- [ ] unified_runner.exe builds
- [ ] Pipeline executes all stages
- [ ] Report JSON generated
- [ ] Execution percentage calculated

---

## Phase 4: GGUF-Backed Validation (Medium Term)

### Goal
Replace synthetic vectors with actual model weights.

### Steps

1. **Generate GGUF-backed vectors**
   ```python
   python generate_golden_from_gguf.py \
       --model /path/to/phi-3.gguf \
       --output val-019/vectors/
   ```

2. **Update metadata**
   - Point to `*_gguf.bin` files
   - Update checksums
   - Record model hash

3. **Run validation with real weights**
   ```batch
   embedding_stage.exe ^
       val-019/vectors/embedding_input_gguf.bin ^
       val-019/vectors/embedding_expected_gguf.bin ^
       val-019/evidence/embedding_actual_gguf.bin
   ```

### Success Criteria
- [ ] Vectors extracted from GGUF
- [ ] SHA256 of model recorded
- [ ] Validation PASS with real weights
- [ ] Evidence shows model provenance

---

## Phase 5: Complete Transformer Chain (Long Term)

### Goal
Validate full transformer execution path.

### Stages to Implement

| Stage | Priority | Complexity |
|-------|----------|------------|
| QKV | High | Medium |
| RoPE | High | High |
| Attention | High | High |
| FFN | High | Medium |
| KV Cache | Medium | Low |
| Logits | Medium | Low |
| Sampling | Low | Low |
| Streaming | Low | Low |

### Success Criteria
- [ ] All 10 stages implemented
- [ ] Each stage produces PASS evidence
- [ ] Execution path ≥ 80%
- [ ] End-to-end inference validated

---

## Evidence Locking

After each successful phase, record:

```json
{
  "phase": "synthetic_embedding",
  "timestamp": "2026-07-17T22:00:00Z",
  "binary_hash": "sha256:...",
  "input_hash": "sha256:4f6addc9...",
  "output_hash": "sha256:51246bdd...",
  "evidence_hash": "sha256:...",
  "result": "PASS"
}
```

This creates an immutable validation chain.

---

## CI Integration

Final CI gate:

```yaml
- name: Validate Embedding
  run: embedding_stage.exe ...
  
- name: Validate RMSNorm
  run: rmsnorm_stage.exe ...
  
- name: Unified Pipeline
  run: unified_runner.exe ...
  
- name: Check Execution Path
  run: |
    $report = Get-Content val-019/evidence/unified_report.json | ConvertFrom-Json
    if ($report.summary.execution_percent -lt 80) {
      throw "Execution path below 80%"
    }
```

---

## Summary

| Phase | Goal | Timeline |
|-------|------|----------|
| 1 | Synthetic Embedding PASS | Immediate |
| 2 | RMSNorm with Invariants | Next |
| 3 | Unified Pipeline | Short term |
| 4 | GGUF-Backed Validation | Medium term |
| 5 | Full Transformer Chain | Long term |

**Next action:** Compile `embedding_stage.cpp` when compiler is available.
