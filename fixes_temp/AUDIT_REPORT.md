# SOVEREIGN PLATINUM — CRITICAL AUDIT REPORT
## Date: 2026-05-24 | Modules Audited: 14 | Critical Bugs: 7 | Severity: PRODUCTION-BLOCKING

---

### 1. TITAN_VECTOR_HADAMARD_BIAS.ASM — FMA Opcode Bug (SEV-1)
**Issue:** `vfmadd213ps ymm2, ymm0, ymm1` computes `ymm2 = ymm0 * ymm2 + ymm1`, but the comment and intent require `ymm2 = ymm0 * ymm1 + ymm2` (fused multiply-add-accumulate).
**Impact:** Expert merge produces `dest = dest * src + bias` instead of `dest = dest + src * bias`, causing accumulator corruption on every MoE layer.
**Fix:** Change to `vfmadd231ps ymm2, ymm0, ymm1`.

---

### 2. TITAN_RMS_NORM.ASM — AVX Syntax Fault (SEV-1)
**Issue:** `vrsqrtss xmm5, xmm5` uses legacy SSE encoding in an AVX context. MASM may assemble it as `rsqrtss` which zeros the upper XMM bits and breaks the broadcast chain.
**Impact:** RMSNorm produces NaN or zero scale factors, collapsing the transformer signal.
**Fix:** Use explicit 3-operand AVX form: `vrsqrtss xmm5, xmm5, xmm5`.

---

### 3. TITAN_SOFTMAX_PHASE.ASM — Divergent Taylor Exp (SEV-1)
**Issue:** The 3rd-order Taylor series `1 + x + x^2/2 + x^3/6` diverges catastrophically for x < -3. After `x -= max(x)`, values routinely hit -5 to -10. The series yields negative probabilities.
**Impact:** Softmax outputs garbage / negative values. Routing gate becomes non-deterministic.
**Fix:** Replaced with the Schraudolph bit-hack `fast_exp2` (2 instructions, ~3 cycle latency, valid for x <= 0 after max-subtraction).

---

### 4. TITAN_GEMV_FMA_CORE.ASM — Missing Horizontal Reduction (SEV-1)
**Issue:** The kernel accumulates 8 partial sums in `ymm0` but stores all 8 lanes with `vmovaps [r8], ymm0`. It never reduces to a scalar dot-product result.
**Impact:** The "output" is 8 unreduced partial sums. The orchestrator treats index 0 as the real result, silently discarding 87.5% of the compute.
**Fix:** Added `vperm2f128` -> `vshufps` -> `vaddps` horizontal tree to collapse to scalar, then `vmovss`.

---

### 5. TITAN_TENSOR_TRANSPOSE.ASM — ABI Corruption (SEV-1)
**Issue:** The transpose clobbers `ymm6` through `ymm15` without save/restore. Under the Windows x64 ABI, `ymm6-ymm15` (and their XMM halves) are **non-volatile**.
**Impact:** Caller state corruption. The Win32 UI thread or inference bridge will experience register poisoning and likely crash inside Qt or WinAPI callbacks.
**Fix:** Added 320-byte stack spill and restore for all 10 non-volatile YMM registers. Line count exceeds 99; ABI compliance is non-negotiable.

---

### 6. TITAN_MoE_ORCHESTRATOR.H — Buffer Overflow + Wrong Math (SEV-1)
**Issues:**
- `dequantized_weights[32]` in `TitanScratchWorkspace` is sized for **one** Q4_1 block. The orchestrator loops `dimension_k / 32` and writes to `&dequantized_weights[b * 32]`. For K=1024, this overflows by 31x.
- `route_scale_vector[8]` is computed but **never consumed**.
- `Titan_Vector_Merge_AVX2` computes `dest = dest * expert_out + bias`. With `dest=merged_output` (zeroed), this yields `bias` only, ignoring the expert computation entirely.
**Impact:** Stack-smashing buffer overflow + mathematically null forward pass.
**Fix:** Rewrote orchestrator with correct loop structure, dynamic scratch sizing, and a new `Titan_Vector_Scale_Add_AVX2` kernel that does `dest += (src * scale) + bias`.

---

### 7. TITAN_EXPERT_ROUTER.ASM — Label Mismatch (SEV-2)
**Issue:** `PUBLIC Titan_Route_Experts_Top2` but `Titan_Expert_Router_Top2 ENDP`. Linker will fail or resolve the wrong symbol.
**Fix:** Synchronized labels.

---

### ARCHITECTURAL MISMATCH — Weight Layout vs GEMV
The current `Titan_GEMV_Interleaved_AVX2` is fixed to output a **scalar** (1 dot product). Your orchestrator expects **32 outputs** per expert (`expert_accumulator[32]`). 

You have two options:
**A.** Keep scalar GEMV and call it 32 times per expert (simpler, correct, still AVX2-inner-loop fast).
**B.** Re-layout weights as 8-row-interleaved and provide a batched GEMV kernel (faster, requires weight re-packing).

The corrected orchestrator uses **Option A** (scalar GEMV in a loop) to guarantee correctness today. You can upgrade to batched later without changing the ASM ABI.

---

### BUILD SCRIPT — Truncated Link Command
The pasted document cuts off mid-link. The completed command is provided in `build_sovereign_platinum_complete.bat`.
