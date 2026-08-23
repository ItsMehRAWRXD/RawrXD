# VAL-051.7 — Gate 19: Final Certification Harness

## Document Identity
- **Gate:** 19
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Certification Checklist

### Fixture Integrity
- [ ] Git HEAD matches freeze
- [ ] Executable SHA-256 verified
- [ ] Model SHA-256 verified
- [ ] Prompt fixture unchanged

### GGUF Tensor Integrity
- [ ] All tensors parse correctly
- [ ] Offsets within file bounds
- [ ] Sizes match metadata
- [ ] Quantization block sizes valid

### Residency Acquire
- [ ] Acquire succeeds for all layer weights
- [ ] Generation assigned correctly
- [ ] Data pointer non-null

### Residency Release
- [ ] Release succeeds for all acquired tensors
- [ ] Lease count reaches zero
- [ ] No double-release

### Lease Validation
- [ ] Valid lease passes
- [ ] Released lease fails
- [ ] Old generation fails
- [ ] Wrong tensor fails

### Stale Lease Rejection
- [ ] Use-after-eviction detected
- [ ] Generation mismatch caught
- [ ] Counter incremented

### Remap Correctness
- [ ] Byte-identical after remap
- [ ] Generation incremented
- [ ] Old leases invalidated

### Eviction Correctness
- [ ] LRU selects oldest evictable
- [ ] Active leases protected
- [ ] Capacity respected

### Layer Accounting
- [ ] Every acquisition has release
- [ ] No active leases at EndLayer
- [ ] Layer count exact

### Forward Accounting
- [ ] Forward count exact
- [ ] Layer count = forwards × layers
- [ ] No active leases at EndForward

### Position Accounting
- [ ] Position monotonic
- [ ] Position count = token count
- [ ] KV position matches
- [ ] RoPE position matches

### KV Integrity
- [ ] KV cache position correct
- [ ] Sequence length correct
- [ ] No corruption across forwards

### 15-Token Autoregression
- [ ] 15 tokens generated
- [ ] No repetition (except valid)
- [ ] No early termination

### Hidden-State Finiteness
- [ ] All hidden states finite
- [ ] Norm within expected range
- [ ] No NaN/Inf

### Attention Sanity
- [ ] Attention outputs finite
- [ ] No overflow in softmax
- [ ] Scores within reasonable range

### FFN Sanity
- [ ] FFN outputs finite
- [ ] SwiGLU produces non-zero
- [ ] No overflow in projections

### Logits Finiteness
- [ ] All logits finite
- [ ] No NaN/Inf in vocab

### Tokenizer Correctness
- [ ] Prompt tokenized correctly
- [ ] Output tokens decode correctly
- [ ] Special tokens handled

### Sampler Correctness
- [ ] Same seed → same token
- [ ] EOS handled correctly
- [ ] Bounds checked

### Output Token Validity
- [ ] All token IDs in vocab range
- [ ] No invalid tokens
- [ ] Text decodes correctly

### Teardown
- [ ] All leases released
- [ ] All mappings unmapped
- [ ] Resident bytes = 0
- [ ] No crashes on destruction

### Leak Detection
- [ ] mapCount == unmapCount
- [ ] activeLeaseCount == 0
- [ ] currentResidentBytes == 0

### A/B Equivalence
- [ ] OFF and ON produce same tokens
- [ ] Counters match within tolerance
- [ ] Numerical output equivalent

### Stress Matrix
- [ ] All stress cases pass
- [ ] No counter drift
- [ ] No leaks across repeated sessions

---

## Final Certification Artifact

```
evidence/VAL-051.7/certification/
├── gate_results.json       # Machine-readable PASS/FAIL per gate
├── failures.json           # Any failures with full context
├── checksums.txt           # SHA-256 of all artifacts
└── VAL-051.7-CERTIFICATION.md  # Human-readable summary
```

## Definition of Done

- [ ] All 19 gates pass
- [ ] All A-G extras pass
- [ ] Evidence package complete
- [ ] Git commit recorded
- [ ] Final certification artifact reproducible
