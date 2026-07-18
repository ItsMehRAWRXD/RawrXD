# RawrXD Validation Architecture (VAL-019)

## Overview

Complete validation framework transitioning from **format verification** to **numerical execution verification**.

```
┌─────────────────────────────────────────────────────────────┐
│                    VALIDATION PIPELINE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Golden Vectors          Validation Runner         Evidence  │
│       │                         │                    │      │
│       ▼                         ▼                    ▼      │
│  ┌─────────┐              ┌──────────┐          ┌─────────┐  │
│  │ GGUF    │─────────────▶│ Stage    │─────────▶│ Report  │  │
│  │ Weights │              │ Executor │          │ JSON    │  │
│  └─────────┘              └──────────┘          └─────────┘  │
│       │                         │                           │
│       ▼                         ▼                           │
│  ┌─────────┐              ┌──────────┐                        │
│  │ Input   │              │ Kernel   │                        │
│  │ Tensor  │              │ Native   │                        │
│  └─────────┘              └──────────┘                        │
│       │                         │                           │
│       ▼                         ▼                           │
│  ┌─────────┐              ┌──────────┐                        │
│  │ Expected│◀────────────│ Output   │                        │
│  │ Output  │   Compare   │ Tensor   │                        │
│  └─────────┘              └──────────┘                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Validation Gates

### E1: Token Bounds Validation
- Verify token IDs within vocabulary range
- Check for negative indices
- Validate batch dimensions

### E2: Deterministic Lookup
- Fixed seed (42) for reproducibility
- Same input → same output across runs
- Cross-platform consistency

### E3: Shape Validation
- Input: [batch, seq_len]
- Output: [batch, seq_len, hidden_dim]
- Dimension consistency checks

### E4: Numerical Comparison
- Max absolute error ≤ tolerance
- Per-element difference tracking
- Statistical metrics (mean, min, max error)

### E5: Model-Backed Tensor Lookup ⭐
- Extract weights from actual GGUF
- Use `token_embd.weight` tensor
- Prove RawrXD tensor access + kernel compatibility

## Stage Implementation Status

| Stage | E1 | E2 | E3 | E4 | E5 | Status |
|-------|----|----|----|----|----|--------|
| **Embedding** | ✅ | ✅ | ✅ | ✅ | ⬜ | Ready |
| **RMSNorm** | ✅ | ✅ | ✅ | ✅ | ⬜ | Ready |
| QKV | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| RoPE | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Attention | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| FFN | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| KV Cache | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Logits | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Sampling | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Streaming | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | Planned |

## Evidence Chain

```
source
  │
  ▼
GGUF artifact
  │
  ▼
token_embd.weight
  │
  ▼
┌─────────────────┐
│  Golden Vector  │
│  - input.bin    │
│  - expected.bin │
│  - SHA256       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Stage Executor │
│  - load input   │
│  - execute      │
│  - compare      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Evidence JSON  │
│  - status       │
│  - checksums    │
│  - max_error    │
│  - runtime_ms   │
└─────────────────┘
```

## File Structure

```
validation/
├── embedding_stage.cpp          # E1-E4 implementation
├── rmsnorm_stage.cpp            # Numerical reduction op
├── unified_runner.cpp           # Pipeline orchestration
├── generate_embedding_golden.py # Seeded vector gen
├── generate_golden_from_gguf.py # E5 model-backed gen
├── val-019/
│   ├── vectors/
│   │   ├── embedding_input.bin
│   │   ├── embedding_expected.bin
│   │   ├── rmsnorm_input.bin
│   │   ├── rmsnorm_expected.bin
│   │   └── manifest.json
│   └── evidence/
│       ├── embedding_actual.bin
│       ├── rmsnorm_actual.bin
│       └── unified_report.json
└── [other validation files]
```

## Evidence Format

```json
{
  "stage": "embedding",
  "status": "PASS",
  "input_checksum": "sha256:4f6addc9659d6fb90fe94b6688a79f2a1fa8d36ec43f8f3e1d9b6528c448a384",
  "output_checksum": "sha256:51246bdd5446d14aa906f60bd996cb2e85d4e3f3f226aa1f33ee0c6a7ad9ec7b",
  "max_error": 0.0,
  "runtime_ms": 0.5,
  "tolerance": 1e-5,
  "telemetry": {
    "mean_rms": 1.0,
    "min_rms": 0.99,
    "max_rms": 1.01
  },
  "implementation": {
    "backend": "native",
    "kernel": "embedding_lookup_v1.0_native",
    "commit": "8473df6ea611e082ace66b9876fb17bccebf259d"
  },
  "reference": {
    "source": "llama.cpp",
    "version": "b1559"
  }
}
```

## Key Design Decisions

### 1. Separation of Concerns
- **Vector Generation**: Python (flexibility)
- **Stage Execution**: C++ (performance)
- **Orchestration**: C++ runner (unified)

### 2. Determinism
- Fixed seed (42) for synthetic data
- Reproducible across runs and platforms
- Enables regression detection

### 3. Extensibility
- Stage executor function pointer pattern
- Easy to add new stages
- Consistent interface

### 4. Evidence Quality
- SHA256 checksums for all tensors
- Runtime telemetry
- Error metrics
- Implementation provenance

## Next Steps

### Immediate
1. Compile `embedding_stage.cpp` → `embedding_stage.exe`
2. Verify PASS with golden vectors
3. Compile `rmsnorm_stage.cpp` → `rmsnorm_stage.exe`
4. Chain stages in `unified_runner.exe`

### Short Term
5. Implement QKV projection stage
6. Implement RoPE stage
7. Implement Attention stage
8. Implement FFN stage

### Medium Term
9. Implement E5 (GGUF-backed) validation
10. Extract actual model weights
11. Compare against llama.cpp reference

### Long Term
12. Full transformer chain validation
13. End-to-end inference validation
14. CI gate enforcement
15. Release certification

## Success Metrics

- [ ] Embedding stage produces PASS evidence
- [ ] RMSNorm stage produces PASS evidence
- [ ] Unified runner executes full pipeline
- [ ] Execution path ≥ 80%
- [ ] E5 validation with actual GGUF model
- [ ] CI gate passes on every commit
- [ ] Release artifacts include validation evidence
