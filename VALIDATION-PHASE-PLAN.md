# Validation Phase Plan
## From Push to Reproducible Runtime

**Date:** 2026-07-17  
**Baseline:** VAL-019-preflight  
**Commit:** `8473df6ea611e082ace66b9876fb17bccebf259d`

---

## Current State

✅ **Repository synchronized**
- cloud-hosting: `copilot/courageous-rodent` up-to-date
- RawrXD: `copilot/vscode-mlyextom-3zgo-phase7a` pushed with 2 commits

✅ **Baseline frozen**
- See `VAL-019-preflight-baseline.yml` for complete system snapshot
- Hardware: AMD Ryzen 7 7800X3D + RX 7800 XT
- Compiler: MSVC 14.50.35717

---

## Phase 1: Complete VAL-018 Execution Chain (Next)

**Goal:** Execute through all transformer stages with telemetry

```
Status:
  GGUF        ✅ Complete
  Tokenizer   ✅ Complete
  Embedding   ⬜ Next
  RMSNorm     ⬜
  QKV         ⬜
  RoPE        ⬜
  Attention   ⬜
  FFN         ⬜
  KV Cache    ⬜
  Logits      ⬜
  Sampling    ⬜
  Streaming   ⬜
```

**Deliverable:** Each stage produces:
- Input tensor checksum
- Output tensor checksum
- Runtime telemetry JSON
- PASS/FAIL evidence artifact

---

## Phase 2: VAL-019 Golden Vector Validation

**Goal:** Automated comparison against reference outputs

**Components Created:**
1. `validation_runner.cpp` - Executable harness
2. `.github/workflows/validation-gate.yml` - CI pipeline
3. `val-019/metadata.json` - Test vectors (to be populated)

**CI Flow:**
```
Build → Hash → VAL-018 Tests → VAL-019 Vectors → Report → Publish
```

---

## Phase 3: Security Triage (Parallel)

**745 Dependabot alerts** tracked separately:
- See `security/dependabot-triage-plan.md`
- P0 Critical: 8 (7-day fix target)
- P1 High Runtime: ~50 (14-day fix target)
- P2-P4: Batched monthly

**Isolation:** Security branches use `security/` prefix, never mixed with validation commits

---

## Immediate Next Steps

1. **Populate golden vectors**
   - Create `validation/val-019/metadata.json`
   - Define input/output tensor paths
   - Generate reference checksums

2. **Implement Embedding stage**
   - Hook into validation_runner
   - Produce first new evidence artifact

3. **Build validation_runner**
   - Compile with existing codebase
   - Test against VAL-018-3 baseline

4. **Run first CI validation**
   - Trigger workflow manually
   - Verify artifact upload
   - Check report generation

---

## Success Criteria

- [ ] All 12 execution stages produce evidence
- [ ] CI gate passes before any release
- [ ] Binary hashes recorded per build
- [ ] Security P0/P1 cleared
- [ ] Repository tagged as `v1.0.0-validated`

---

## Files Created

| File | Purpose |
|------|---------|
| `VAL-019-preflight-baseline.yml` | Frozen system state |
| `validation_runner.cpp` | Executable harness |
| `.github/workflows/validation-gate.yml` | CI pipeline |
| `security/dependabot-triage-plan.md` | Security roadmap |
| `VALIDATION-PHASE-PLAN.md` | This document |

---

## Notes

- Validation work stays in `validation/` directory
- CI gates prevent unvalidated releases
- Security fixes are independent but required for release
- Next checkpoint: VAL-019-complete (all stages green)
