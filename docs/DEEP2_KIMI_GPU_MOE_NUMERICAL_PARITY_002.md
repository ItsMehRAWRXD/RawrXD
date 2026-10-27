# DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002 — implementation slice

Base: `ef97b24938f81692cd5aaf305284ebd3150a6822` on
`fix/deep2-multimodel-safety-20261025`.

This PR adds an **isolated comparison harness**, not a certified numerical
oracle or a GPU runtime change. It does not modify K2 execution, REAP sizing,
GPU1, existing diagnostic edits, or the release promotion gate.

## Inputs

Export three **complete**, equally sized raw little-endian float32 vectors
for the same layer, token step, routed expert, weights, and input:
- `cpu.f32le`: existing host CPU path
- `gpu.f32le`: device-output path after D2H
- `oracle.f32le`: **independently implemented** scalar dequantization/GEMV

The caller must verify and supply the shared input and weight SHA256 values.
This script cannot prove those hashes refer to the same tensors; that is a
separate capture/integrity gate. It also cannot prove that the oracle implementation
is independent merely from its description.

Example (PowerShell):

```powershell
python tools/deep2_moe_vector_parity.py `
  --cpu evidence/cpu.f32le --gpu evidence/gpu.f32le `
  --oracle evidence/oracle.f32le `
  --layer 2 --expert-id 358 --token-step 0 `
  --input-sha256 <64-hex-input-digest> `
  --weights-sha256 <64-hex-weight-digest> `
  --oracle-method "independent scalar dequant f32 GEMV" `
  --max-abs-tol 0.01 --rms-tol 0.005 --cos-min 0.999 `
  --output evidence/DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002.json
```

**Illustrative thresholds only.** Freeze tolerance values using independently
reviewed reference data before certification. The sample expert ID is also
illustrative; use the actual captured expert ID.

Exit codes: `0` diagnostic comparison within supplied tolerances;
`2` comparison outside tolerances; `3` invalid inputs or I/O failure.
Even an exit-0 receipt is explicitly `PASS_DIAGNOSTIC` and
`certified=false`; no production promotion.

Run tests:

```powershell
python -m unittest discover -s tools -p test_deep2_moe_vector_parity.py -v
```

## Remaining prerequisites for certification

1. Capture matched CPU/GPU expert inputs and quantized weights with verifiable hashes.
2. Implement and review the independent scalar GGUF dequantization/GEMV oracle.
3. Capture all eight complete expert vectors and the weighted MoE accumulation.
4. Freeze tolerances before running certification; test adversarial/near-zero outputs.
5. Verify actual GPU submissions, H2D/D2H identity and bounded residency.
6. Run on the Windows/Vulkan host and attach real receipts.

`PROMOTE=0`; `TIP_CLIMB=HOLD`.
