# DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002 — harness introduction

Base: `ef97b24938f81692cd5aaf305284ebd3150a6822` (`fix/deep2-multimodel-safety-20261025`). This work deliberately does not touch `K2NativeMoEFfn_Place.cpp`, `K2WeightResolve.cpp`, runtime dispatch, model weights, or release controls.

## Scope

`tools/k2_gpu_moe_vector_parity.py` compares complete **CPU, GPU0, and independently generated oracle** vectors. Inputs are text files containing one finite floating-point element per line, with optional blank lines and `#` comments. Every input is hashed in the resulting JSON receipt. Mismatched lengths, missing files, malformed values, and nonfinite values fail closed. The tool reports max/mean absolute difference, RMS, normalized RMS, max relative difference, cosine similarity, and worst-element index and values, for each of CPU/oracle, GPU/oracle, and GPU/CPU.

It **does not implement an independent GGUF dequantization/GEMV oracle** or capture the live tensor buffers. Those are follow-up source integration tasks and must not be counted as passed. The oracle file must be independently generated and its implementation/provenance reviewed. An identical final token is not parity proof.

## Run

```powershell
python tools/test_k2_gpu_moe_vector_parity.py
python tools/k2_gpu_moe_vector_parity.py --cpu cpu_vector.txt --gpu gpu_vector.txt --oracle scalar_oracle_vector.txt --oracle-provenance "independent scalar dequant/GEMV implementation + version" --max-abs 0.01 --max-rms 0.003 --min-cosine 0.999 --output parity_receipt.json
```

Thresholds in the example are **illustrative, not approved certification tolerances**. Choose and freeze tolerances using the independent reference and representative model inputs before issuing a production certificate.

Exit codes: 0 = threshold checks pass **diagnostically**; 2 = numerical threshold failure; 3 = invalid input or evaluation error. All JSON receipts set `certified=false` because vector capture, oracle independence, tensor identity, and quantization tolerances require separate audits.

## Next work

1. Add bounded opt-in CPU/GPU capture at the same layer/expert, before weighted accumulation, with dimensions and tensor hashes.
2. Implement independent scalar GGUF Q4_K/Q6_K dequant and GEMV reference (without using optimized CPU or GPU GEMV dispatch).
3. Validate exact quant block geometry, strides, endianness, weights, input identity, and H2D/D2H byte counts.
4. Run hardware receipts, freeze tolerances, and certify gates 02–10 only after evidence.

```ini
GPU0_DISPATCH=DEMONSTRATED_PREVIOUS_RECEIPT
VECTOR_COMPARISON_HARNESS=SOURCE_ADDED
LIVE_VECTOR_CAPTURE=NOT_IMPLEMENTED
INDEPENDENT_ORACLE=NOT_IMPLEMENTED
NUMERICAL_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Independent Q6_K scalar down-GEMV reference (increment 2)

The repository now includes `tools/k2_q6k_scalar_oracle.py`, which independently
unpacks GGML Q6_K blocks (256 elements / 210 packed bytes), including
signed group scales, 6-bit signed quantized values, and the F16 block scale.
It evaluates matrix-vector products with a scalar Python implementation,
not `QuantKernelRegistry::GetGEMV()` or a Vulkan compute shader.

```powershell
python tools/test_k2_q6k_scalar_oracle.py
python tools/k2_q6k_scalar_oracle.py --weights down_expert_q6k.bin --input post_swiglu.txt --rows 7168 --columns 2048 --output down_oracle.txt --receipt down_oracle_receipt.json
```

The dimensions above are **examples**, not an assertion about the running
model: use the validated physical expert-slice geometry and post-SwiGLU
activation length from the same real execution. The script rejects a
mismatched packed byte count, nonfinite inputs, and invalid dimensions.

Local synthetic suite: **9/9 PASS** on the author's test runner. No Kimi
model bytes, Vulkan device, or native Windows binary were exercised by this
suite. The GPU/CPU/oracle comparison remains blocked on *actual* same-expert
vector capture and independent cross-validation of the packed Q6_K layout
against authoritative GGML fixtures. Q4_K gate/up are **not yet** modeled by
this oracle; that requires a separate extension.

For a real MoE down-projection parity experiment, capture the **post-SwiGLU
vector passed into Q6_K down-GEMV**, the exact packed expert's down weights,
and the CPU/GPU down output vectors. Raw normalized hidden states are not a
valid substitute for the down-projection input. Keep all captures bounded
and explicitly opt-in. The scalar oracle uses high-precision summation, so
an F32 GPU kernel can differ slightly without being incorrect; freeze
tolerances only after reference and accumulation-order analysis.

```ini
Q6K_SCALAR_SOURCE=ADDED
Q6K_SYNTHETIC_TESTS=9/9_LOCAL_PASS
Q6K_LAYOUT_CROSS_REFERENCE=REQUIRES_INDEPENDENT_FIXTURE
Q4K_GATE_UP_ORACLE=NOT_IMPLEMENTED
LIVE_KIMI_VECTOR_CAPTURE=NOT_IMPLEMENTED
REAL_KIMI_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Same-expert capture wiring (increment 3)

The opt-in diagnostic code at `K2NativeMoEFfn_ExpertGpu.cpp` now
calls `K2MoEParityCapture.hpp` after the *existing* CPU/GPU parity
vectors are available. It does not change any inference output or the
GPU/CPU backend selector. Capture is intentionally scoped to the
existing `DEEP2_MOE_GPU_PARITY=1` path, and requires a **preexisting,
private, empty directory** in `DEEP2_MOE_PARITY_CAPTURE_DIR`. Never
use a shared evidence directory; file writes are non-atomic and do not
support concurrent runs. A diagnostic returns `WRITTEN` or
`SKIPPED`, and a skipped capture does not constitute evidence.

The capture contains `k2_l<layer>_e<expert>_s<stick>` files:

- `.down_q6k.bin`: exact packed expert down matrix from the cold
  slice (`ggmlType=14`), not a transformed dequant tensor
- `.post_swiglu.txt`: actual activation sent to the down projection
- `.cpu_down.txt`: full output from the existing native CPU kernel
- `.gpu_down.txt`: full output downloaded by existing parity probe
- `.manifest.txt`: layer, expert, stick, rows, columns, byte count,
  and `certified=0`

Capture skips cached experts without a host-accessible packed weight
pointer. To obtain a complete reference bundle, run one cold expert in
an isolated test. No tensor values are printed into logs by default.

```powershell
# Run in an already configured Windows MSVC environment:
cl /std:c++17 /EHsc /I src\deep2 tools\test_k2_moe_parity_capture.cpp
.\test_k2_moe_parity_capture.exe

# Create a fresh private folder before a bounded real Kimi replay:
New-Item -ItemType Directory -Path F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001
$env:DEEP2_MOE_GPU_PARITY='1'
$env:DEEP2_MOE_GPU_PARITY_LIMIT='1'
$env:DEEP2_MOE_PARITY_CAPTURE_DIR='F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001'
# Run the established, single-layer, GPU0 Kimi replay from the GPU0 receipt.
# Inspect status=WRITTEN; do NOT infer successful capture from exit=0.

python tools/k2_q6k_scalar_oracle.py --weights F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001\k2_l1_e0_s0.down_q6k.bin --input F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001\k2_l1_e0_s0.post_swiglu.txt --rows 7168 --columns 2048 --output F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001\oracle.txt --receipt F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001\oracle_receipt.json
```

The example layer/expert/dimensions are **placeholders**; use the values
recorded by the actual manifest, not an assumed shape. Run
`tools/k2_gpu_moe_vector_parity.py` with the capture's CPU/GPU
down vector files and the generated oracle file, and with frozen,
independently justified tolerances.

This captures only the **down-GEMV** numerical comparison, not the
independent Q4_K gate/up/SwiGLU pipeline, weighted multi-expert
accumulation, or full-model logits. It is not a certification PASS.
Standalone C++ capture smoke source is present, but an MSVC compile
and live GPU run have not been executed in this environment.

```ini
CAPTURE_HELPER=SOURCE_WIRED
CAPTURE_DEFAULT=OFF
CAPTURE_CPP_SMOKE=NOT_RUN
REAL_KIMI_CAPTURE=NOT_RUN
REAL_KIMI_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Manifest-driven audit (increment 4)

A new `tools/k2_moe_capture_audit.py` consumes an existing
`k2_l<layer>_e<expert>_s<stick>.manifest.txt` and derives all
dimensions from that manifest. It checks manifest identity, Q6_K block
geometry, byte counts, input/output lengths, finiteness, and hashes
before applying the independent scalar Q6_K down-GEMV oracle. It emits
CPU/oracle, GPU/oracle, and GPU/CPU numerical comparisons and remains
`certified=false` even if thresholds pass.

```powershell
python tools/test_k2_moe_capture_audit.py
python tools/k2_moe_capture_audit.py --manifest "F:\rawrxd\evidence\KIMI_PARITY_CAPTURE_001\k2_l1_e0_s0.manifest.txt" --max-abs 0.01 --max-rms 0.003 --min-cosine 0.999 --receipt parity_audit.json
```

The tolerance values above are illustrative, not an acceptance contract.
**Do not classify a GPU-versus-oracle mismatch as solely down-GEMV
error:** the existing CPU post-SwiGLU vector is NOT proof that the GPU
used the same post-SwiGLU input. Exact GPU activation identity must be
captured and checked separately. The output also requires an
authoritative, externally validated Q6_K layout fixture.

Seven synthetic audit test cases are supplied. The new tests and the
C++ capture integration are **not yet executed on the Windows/Vulkan
machine**. GitHub source commit alone cannot certify them.

```ini
MANIFEST_AUDIT=SOURCE_ADDED
MANIFEST_AUDIT_TESTS=NOT_RUN
GPU_POST_SWIGLU_IDENTITY=NOT_PROVEN
FULL_KIMI_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## GPU submission-order certification blocker (increment 5 audit)

Source review of `K2NativeMoEFfn_ExpertGpu.cpp` shows that
`emitParity(r)` is invoked inside the expert loop, after
`K2MoEStickExpertDevice(...)` but before the outer
`K2MoEStickEndFused(...)`. Thus the diagnostic may ask
`DownloadBuf(ArenaDown())` for an expert result before a fused
submission/completion boundary. A successful transfer API call
**by itself does not prove that the corresponding expert result
was finished and owned by that same expert**. The GPU vector
capture must be treated as suspect until the Vulkan command
lifetime is inspected and a per-expert, completion-ordered GPU
witness is implemented. This matters especially if the same
arena slot is reused between experts.

The standalone manifest and scalar oracle compare the bytes
they receive; they cannot repair an incorrect capture boundary.
An analyst must check command recording, submission, completion
and per-expert buffer identity before certifying parity.

The new `.github/workflows/deep2-kimi-parity-offline.yml`
runs all three Python test files explicitly (so zero discovered
tests cannot be mistaken for a pass), plus standalone C++
capture checks with Linux GCC and Windows MSVC. No Vulkan
device is required for these offline tests. Workflow commit
is **not** a green CI receipt; inspect actual job conclusion.

```ini
GPU_CAPTURE_SUBMISSION_ORDER=AUDIT_BLOCKER
OFFLINE_CI_WORKFLOW=SOURCE_ADDED
OFFLINE_CI_RESULT=PENDING
REAL_GPU_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 6: fail closed on unsynchronized fused output capture

This section **supersedes the earlier live-capture instructions above**.
The prior call to `emitParity(r)` was inside the fused recording
loop, before `K2MoEStickEndFused`. At that point neither GPU
completion nor per-expert `ArenaDown` ownership had been
established. This could produce a misleading numerical witness.

The unsafe in-loop `DownloadBuf(ArenaDown())` and its
`k2_parity_capture::Capture(...)` call have been removed.
When either diagnostic parity or a capture directory is
requested, runtime now emits:

```text
GPU_EXPERT_PARITY status=BLOCKED reason=FUSED_OUTPUT_NOT_SYNCHRONIZED
```

The normal fused GPU worklist remains enabled. Standalone
capture helpers and offline scalar oracle code remain available
but **are not wired to a reliable live GPU expert witness**.
Existing capture datasets produced by the earlier implementation
must be treated as **untrusted diagnostic data** until the
ordering and provenance can be independently established.

`tools/test_k2_fused_parity_safety.py` guards against reintroducing
the unsafe in-loop read. The GitHub offline workflow includes this
test. Future restoration requires a per-expert, completion-ordered
GPU output buffer and a separately witnessed GPU post-SwiGLU
activation, with fresh evidence from actual hardware. No old
`GPU_EXPERT_PARITY status=OK` line alone satisfies the gate.

```ini
UNSAFE_FUSED_READ=REMOVED
LIVE_PARITY_CAPTURE=BLOCKED_FAIL_CLOSED
OFFLINE_REGRESSION_TEST=SOURCE_ADDED
MSVC_RUNTIME_BUILD=NOT_VERIFIED
GPU_NUMERICAL_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 7: completed aggregate GPU partial witness (not expert parity)

The diagnostic path now permits a **post-`K2MoEStickEndDevice`**
capture of the complete fused **stick aggregate** partial vector,
rather than downloading `ArenaDown()` inside the expert-recording
loop. The normal fused execution path remains unchanged.
When `DEEP2_MOE_PARITY_CAPTURE_DIR` points to a private existing
directory, a successful diagnostic writes:

- `k2_l<L>_s<S>_aggregate.gpu_partial.txt`: finite aggregate vector.
- `k2_l<L>_s<S>_aggregate.manifest.txt`: dimensions, layer, stick,
  ordered expert IDs and routing weights; `certified=0`.

It emits `GPU_STICK_PARTIAL_CAPTURE ... status=WRITTEN
scope=AGGREGATE_ONLY` on success. A missing/skipped capture is not
a PASS. Existing files are refused, not overwritten.

**These files are deliberately incompatible with the per-expert Q6_K
oracle manifest.** They describe the final sum of routed contributions,
not one expert's unweighted down-GEMV. The previous
`GPU_EXPERT_PARITY status=BLOCKED` is still emitted. Do not infer
per-expert output, activation identity, or scalar Q6_K parity from this
aggregate.

A source regression test checks that the aggregate capture occurs after
the fused completion and device partial boundary, stays uncertified,
and does not re-enable the in-loop `ArenaDown` read.

```ini
POST_DEVICE_STICK_PARTIAL_CAPTURE=SOURCE_WIRED
PER_EXPERT_GPU_WITNESS=BLOCKED
MSVC_BUILD_AND_RUNTIME=NOT_RUN
KIMI_GPU_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```
