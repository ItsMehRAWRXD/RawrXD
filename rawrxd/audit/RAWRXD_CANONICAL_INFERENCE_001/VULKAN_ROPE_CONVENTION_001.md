# RAWRXD_VULKAN_ROPE_CONVENTION_001 — the Vulkan attention defect, root-caused and fixed

```
GATE            = RAWRXD_VULKAN_ROPE_CONVENTION_001
DATE            = 2026-10-02
GIT_HEAD        = b81d3f1312727eb6ab1b7f2dd7ef7798fd5c9223  (worktree modified)
DRIVER          = server_generation_parity.exe (links the InferenceEngine TARGET)
PRIMITIVE       = Deep2Engine::generateStream() -- production
MODEL           = tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf  (arch=llama)
PROMPT          = "What is the capital of France? Answer in one word."  (13 tokens)
SAMPLING        = temperature 0, topK 1
SHADER          = src/deep2/shaders/deep2_ops.comp -> deep2_ops.spv
                  before  SHA256 2D47B9FCDDE175FE...
                  after   SHA256 E74919423BEB914C...
```

Supersedes the `FIRST_DIVERGENT_BOUNDARY = DispatchAttnDecode` claim in
`ATTN_VISIBILITY_TRACE_001.md`. That attribution was wrong, and the reason it
was wrong is the most useful thing in this record.

---

## 1. Root cause

```cpp
// src/deep2/shaders/deep2_ops.comp  OP_ROPE   (BEFORE)
uint i0 = h * headDim + pair * 2u;      // adjacent pair (i, i+1)
uint i1 = i0 + 1u;
float exponent = -float(pair * 2u) / float(headDim);
```

```cpp
// src/deep2/Deep2Engine.cpp:3732  applyRoPE
if (modelWeights.ropeNeoxStyle) {          // llama, qwen, mistral, gemma, ...
    rotateHeadNeox:  pair (i, i + rotaryDim/2)      // ROTATED HALF
                    invFreq = theta^(-i/(rotaryDim/2))
} else {
    rotateHead:      pair (i, i+1)                  // GPT-J adjacent
                    invFreq = theta^(-2i/rotaryDim)
}
```

`ropeNeoxStyle` is `true` for `arch == "llama"`
(`Deep2Engine.cpp:1691`). The shader implemented **only** the GPT-J branch.
For a llama-family model the two are different rotations of the same vector.

**The defect is invisible at position 0.** There `angle = 0`, so `cos = 1`,
`sin = 0`, and *both* conventions are the identity. That single fact explains
every symptom that delayed this:

- every position-0 gate passed;
- the parity grid's only visible step was 0, and it agreed;
- the `CTX=1` control agreed;
- the K/V split agreed, because it compares post-projection K, which is
  identical — only the *rotation* differs;
- attention at one visible slot returns `V[0]` regardless of the score, so the
  wrong K was not yet observable.

From position 1 on, the GPU rotates K and Q one way and the CPU rotates them
another, and every downstream number differs.

## 2. How it was actually found

The CTX=2 capture (`RAWRXD_ATTN_CTX2_PROBE_001`) emitted `SCORE_RAW`,
`SCORE_SCALED`, `SOFTMAX_PROB` and `ATTN_VALUE` per head from three sources:
the CPU production attention, the Vulkan kernel's *algorithm* re-evaluated on
the host in float32 from the exact device bytes, and the device arena.

The pivot settled the kernel's own faithfulness first:

```ini
CONTROL_POS0_GPU_MODEL_VS_ARENA_COMPARED=96  MISMATCH=0
CONTROL=POS0_AGREES
STEP1_GPU_MODEL_VS_ARENA = FAITHFUL (20 heads) / DIVERGES (12), worst rel 2.4e-5
```

The model reproduces the arena to float32 reduction-order noise. The kernel
does what its source says. It was therefore exonerated, and the search moved
upstream.

The first wrong scalar was then in `SCORE_RAW` at position 0 of the context —
and the input-byte hashes pinned it immediately:

```ini
STEP1_HEADS_WITH_DIFFERING_INPUT_BYTES=32 / 32
VERDICT=INPUT_BYTES_DIFFER
```

`Q_F8` and `K_F8` for head 0 at position 1 were not last-bit differences; they
were different numbers entirely.

## 3. The retraction, and why the L2 comparison caused it

The previous record asserted, from an L2 comparison:

```ini
VULKAN_LAYER0_Q_ROPE = PARITY
VULKAN_LAYER0_K_ROPE = PARITY
VULKAN_LAYER0_V      = PARITY
```

Those three are **retracted**. At layer 0, position 1:

| stage | side | MIN | MAX | MEAN | L2 | FIRST8 |
|---|---|---|---|---|---|---|
| ATTN_NORM | CPU | -1.26793122 | 2.05834889 | 0.000258307392 | 3.03900923 | — |
| ATTN_NORM | GPU | -1.26793158 | 2.05834961 | 0.000258307536 | 3.03901027 | — |
| Q_PRE_ROPE | CPU | -5.04938316 | 4.27178955 | -0.00613438149 | 19.948757 | — |
| Q_PRE_ROPE | GPU | -5.04938459 | 4.27179146 | -0.00613438359 | 19.948764 | — |
| K_PRE_ROPE | CPU | -9.50698757 | 3.34584546 | -0.153660558 | 17.8532648 | — |
| K_PRE_ROPE | GPU | -9.50699234 | 3.3458457 | -0.153660634 | 17.8532715 | — |
| **Q_ROPE** | CPU | -5.05490685 | 4.26459408 | -0.00703408971 | 19.9487568 | -0.0973646343,-0.0374812186,… |
| **Q_ROPE** | GPU | -5.04894352 | 4.27112246 | -0.00577833549 | 19.9487633 | -0.13950415,-0.0608576313,… |
| **K_ROPE** | CPU | -9.52082825 | 3.34485316 | -0.149923337 | 17.8532648 | -0.532934666,-0.620994747,… |
| **K_ROPE** | GPU | -9.50698566 | 3.32241917 | -0.151182263 | 17.853271 | 0.459393293,-0.358776867,… |

The **input** agrees to 1e-7. The **post-RoPE** output does not agree at all:
MIN, MAX, MEAN, HASH and all eight leading elements differ.

And L2 agrees to **3.5e-7** on both. K reaches −9.5, so two or three outliers
dominate the norm of 256 elements and conceal O(0.1) differences across the
rest. A magnitude-only comparison is not a weaker form of an element-wise
comparison; it is a different measurement that is structurally incapable of
seeing this class of defect. This is the fourth recorded instance of that
pattern in this project, and the first one where the instrument was *newly
written* and still made the error.

`vulkan_grid_layer_bisect.ps1` now classifies on the relative difference of
`FIRST8` element-wise, and reports `HASH_EQ` separately. Re-running it after
the fix, over the same valid prefill window:

```ini
STEP_STAGE_PAIRS_TOTAL        = 169
STEP_STAGE_PAIRS_ALL_MATCH    = 162     (was 13)
STEP_STAGE_PAIRS_WITH_DIVERGENCE = 7     (was 156)
```

The 7 residuals are at relative 0.0010–0.0030, straddling the 1e-3 threshold,
in `SWIGLU` (6) and one `ATTN_VALUE`, touching 1–2 of 22 layers each.

## 4. The fix

`OP_ROPE` now implements both conventions, and `DispatchRope` takes the
convention and the rotary dimension from the same model fields `applyRoPE`
uses. `OpsPush` has no spare integer field — `p0..p5` and `n` are all live and
`f0` is theta — so `f1` carries `rotaryDim` in its integral part and the NeoX
flag in its fractional part.

```cpp
p.f1 = static_cast<float>(rotaryDim) + (neoxStyle ? 0.5f : 0.0f);
```

```glsl
uint rotaryDim = uint(pc.f1);
bool neox = (pc.f1 - float(rotaryDim)) > 0.25;
```

The threshold is `0.25`, not `0.5`. The first attempt used `> 0.5`; with
`f1 == 64.5`, `pc.f1 - float(64)` is exactly `0.5f`, the test is false, the
NeoX branch never activates, and the output is **bit-identical to the unfixed
shader**. That attempt was caught only because the output was compared rather
than the exit code — a fix that cannot be distinguished from no fix is not a
fix.

Both `DispatchRope` call sites pass `modelWeights.ropeNeoxStyle` and
`modelWeights.ropeDimensionCount`. `deep2_ops.spv` was regenerated with
`glslangValidator -V --target-env vulkan1.1` and validated with `spirv-val`.
The previous module is preserved at `deep2_ops.spv.bak_preshader`.

## 5. Verification

Element-wise, layer 0, position 1, `K_ROPE` first eight:

```ini
CPU  cache   K8 = -0.532935  -0.620995  -0.0783299 -0.106779  -0.134186  -0.365004  -0.00215312 -0.453598
GPU  arena   F8 = -0.532934964 -0.620994985 -0.0783298835 -0.106779434 -0.134186476 -0.36500445 -0.00215319311 -0.453598648
```

(before the fix: `0.459393293, -0.358776867, 0.240323484, …`)

End-to-end, production `generateStream()`, 24 greedy tokens, same prompt:

```ini
BEFORE  cpu     = 13,1576,7483,310,278,3303,3900,29973,13,29896,29889,13,29906,29889,13,13,29896,29889,13,13,13,29896,29929,29889
BEFORE  vulkan  = 13,22550,29901,450,7483,310,3444,338, ...          diverged from token 1

AFTER   cpu     = 13,1576,7483,310,278,3303,3900,29973,13,29896,29889,13,29906,29889,13,13,29896,29889,13,13,13,29896,29929,29889
AFTER   vulkan  = 13,1576,7483,310,278,3303,3900,29973,13,29896,29889,13,29906,29889,13,13,29896,29889,13,13,13,29896,29929,29889
```

**Token-for-token identical over 24 tokens.** Before the fix the two routes
parted company at token 1.

The grid's own self-certification, same run:

```ini
SUMMARY VALID_RECORDS=13464 UNSTABLE_RECORDS=0 PREMATURE_RECORDS=0
        READBACK_AUTHORITY=CERTIFIED
        ANCHOR_CALLS=792 MAX_POS=35 STEP_IDENTITY=AUTHORITATIVE_KV_POS
```

## 6. Ledger

```ini
RAWRXD_VULKAN_ROPE_CONVENTION_001          = ROOT_CAUSED_FIXED_VERIFIED
VULKAN_ROPE_CONVENTION                     = MATCHES_CPU (element-wise)
VULKAN_LAYER_BODY_POS0                     = PASS
VULKAN_LAYER_BODY_POS1_PLUS                = PASS   (162/169 pairs; 7 at 1e-3 noise)
VULKAN_FIRST_GENERATED_TOKEN               = PASS   (agrees with CPU)
VULKAN_24_TOKEN_SEQUENCE                   = IDENTICAL_TO_CPU
DISPATCH_ATTN_DECODE                       = EXONERATED (faithful to its source)

# retracted from ATTN_VISIBILITY_TRACE_001.md
VULKAN_LAYER0_Q_ROPE = PARITY              = RETRACTED (L2-only; MIN/MAX/MEAN/HASH differ)
VULKAN_LAYER0_K_ROPE = PARITY              = RETRACTED (L2-only; MIN/MAX/MEAN/HASH differ)
VULKAN_LAYER0_V      = PARITY              = RETRACTED (L2-only; element-wise differs)
FIRST_DIVERGENT_BOUNDARY = DispatchAttnDecode = RETRACTED  -> RoPE

# unchanged
CPU_NEWEST_KV_VISIBILITY                   = CORRECT
CPU_PREFILL_LENGTH                         = CORRECT
NEWEST_SLOT_KV_NOT_VISIBLE                 = FALSIFIED
VULKAN_KV_PROJECTED_TO_WRITTEN             = PASS
VULKAN_KV_WRITTEN_TO_READBACK              = PASS
VULKAN_SLOT0_SURVIVAL                      = PASS
VULKAN_GRID_STEP_IDENTITY                  = FIXED_AND_VERIFIED (MAX_POS=35)
RAWRXD_CPU_ARGMAX_LOCK_REPRODUCTION        = INDETERMINATE
  REASON = historical executable/input provenance absent; not merged into
           "fixed" or "still broken"
CPU_EXTERNAL_REFERENCE_PARITY              = OPEN  (the CPU route still answers
           "the capital of the United States"; agreement between two routes is
           not correctness against a reference)
GPU_QUANT_EXECUTION_CERT                   = INVALID/OPEN
SAFE_TO_SHIP                               = 0
```

`SAFE_TO_SHIP` stays 0. The two routes now agree, which removes a divergence;
it does not establish that either is numerically correct. The CPU route still
answers the France question wrongly, and a shared defect in a common weight or
quant path would be invisible to a CPU-vs-GPU comparison.

## 7. The fourth instrument defect, in a newly written instrument

| # | Defect | Caught by |
|---|---|---|
| 8 | `vulkan_grid_layer_bisect.ps1` classified on L2 and reported 13/169 pairs matching; the step-0 PASS was read as a general PASS | element-wise `FIRST8` + `MIN/MAX/MEAN/HASH` from the CTX=2 probe |
| 9 | `attn_ctx2_classify.ps1` read only the GPU file, so every `cpu vs gpu_model` comparison had a null counterpart and printed `ALL_FOUR_AGREE=32` for a comparison never made | `HEADS_PAIRED_CPP_ALL_THREE` / `HEADS_UNPAIRED` counters, `EVIDENCE_COUNT=0 => INVALID` |
| 10 | `attn_ctx2_classify.ps1` compared model-vs-arena by hash; both are float32 and differ in the last bits, so all 32 heads read `DIVERGES` on a pair agreeing to 7 significant figures | relative-L2 test for float pairs; hash equality kept only for byte-identity claims |
| 11 | RoPE fix used `> 0.5` on a flag encoded as exactly `0.5`; the branch never activated and the output was bit-identical to the unfixed shader | comparing the output, not the exit code |

Defect 9 is the one the proposed `RAWRXD_MEASUREMENT_HARNESS_AUTHORITY_001`
rule `EVIDENCE_COUNT == 0 => VERDICT=INVALID` exists to prevent, and it
committed inside the tool written to detect exactly that class. Rule 1
("nonempty input must produce nonzero parsed records") plus an explicit
`UNPAIRED` counter is what is needed; a record count alone is not sufficient,
because a run can parse records and still compare none of them.

## 8. Artifacts

```text
ctx2_cpu.txt / ctx2_vulkan.txt        three-source CTX=2 capture
cpu_kv_probe.txt / vulkan_parity_grid.txt        pre-fix captures (evidence for the retraction)
cpu_probe_final.txt / vulkan_grid_final.txt      post-fix captures
vulkan_grid_ropefix.txt               intermediate capture, single-stage proof
kvar_cpu.log / kvar_cpu2.log          CPU projection-vs-cache dumps (RAWRXD_KV_PARITY_DUMP)
deep2_ops.spv.bak_preshader           pre-fix SPIR-V
```

## 9. Files changed

```text
src/deep2/shaders/deep2_ops.comp           OP_ROPE implements both conventions
src/deep2/shaders/deep2_ops.spv            regenerated, spirv-val clean
src/deep2/shaders/deep2_ops.spv.bak_preshader  preserved
src/deep2/vulkan_compute.cpp                DispatchRope takes convention + rotaryDim
src/deep2/vulkan_compute.h                  signature
src/deep2/vulkan_compute_patched.h          signature
src/deep2/Deep2Engine_GpuForward.cpp        both call sites pass the model fields
src/deep2/AttnCtx2Probe.h                   NEW  (three-source CTX capture)
src/deep2/Deep2Engine.cpp                   CPU-side CTX capture
tools/attn_ctx2_classify.ps1                NEW
tools/vulkan_grid_layer_bisect.ps1          verdict moved off L2 onto FIRST8
```

No behaviour changes outside the RoPE convention, which is now driven by the
same model fields the CPU path already used. The three opt-in gates
(`RAWRXD_ATTN_CTX2_PROBE`, `RAWRXD_ATTN_VISIBILITY_TRACE`,
`RAWRXD_VULKAN_PARITY_GRID`) still default to off.
