# RawrXD ModelGenie: TopK/MoE dispatcher evaluation-order repair

## Root cause

The last measured run (commit `b2331ec070`) had `IR_OPS_EXECUTED=248`, `IR_OPS_SKIPPED=52`, with exactly 26 TopK failures (primitive 7) and 26 MoE failures (primitive 8). Router op 19 produced 64 finite elements. The corresponding `Dispatch` calls query `arena.Size(op.output.id)` in the same C++ function call that invokes `getOutput(op)` to allocate its storage. C++ does not specify the order in which these function arguments are evaluated. The size can therefore be queried before allocation, yielding zero and causing both operations to return false.

**This is an execution-order defect, not a Q6_K LM-head defect.** The measured Q6_K logit audit passed independently, with RMSE 1.32e-7 and argmax 2901. This does not establish target token parity.

## Install and run (Windows 11 / VS2022 BuildTools)

Extract `tools/parity_frontier/` from the ZIP into `F:\rawrxd\tools\parity_frontier\`. From PowerShell 7:

```powershell
# Preview the surgical source replacement, without mutation or build
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\verify_dispatch_order.ps1

# Apply and recompile with the existing Windows build batch; run real GGUF
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\verify_dispatch_order.ps1 -Apply

# Also commit/push precisely whitelisted source + measured evidence
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\verify_dispatch_order.ps1 -Apply -Push
```

The `-Apply -Push` command intentionally publishes **measured FAIL evidence** if full parity is still broken. It never declares an artificial PASS. The `SaaSEncryptionSecurity` submodule is neither staged nor modified.

The runner requires the exact branch, an empty pre-existing staged index, and the 10,364,416,768-byte GGUF file. It refuses stale binaries after rebuilding. It records the native process exit status independently of shell pipelines, dumps fresh tensors, and reruns the packed Q6_K LM-head auditor on the new activation 298 and logits 299.

## Files changed

Only `tools/rawrxd_modelgenie_ir_executor.cpp`: the two `case Primitive::TopKFwd` and `case Primitive::MoEExecuteFwd` dispatch branches. Both now calculate `inputN`, `choicesN`, and `outputN` **after** `getOutput` has allocated storage. The failure guards log `TOPK_BIND_FAIL` or `MOE_BIND_FAIL` with actual dimensions, without silently skipping operations.

The patcher makes a timestamped backup of the original source, preserves CRLF/BOM, rejects unknown/partial source layouts, and is repeat-safe. It does not rewrite the numerical kernels, the GGUF parser, the native header generator, or the reference token0 executable.

## Expected results / next frontier

Check `evidence/NUGVERSE_ESTIMATOR_001/parity_dispatch_order_summary.txt` for structural `300/300` and `0 skipped`. If these gates close, the **new** predicted token and new packed Q6_K audit determine whether the remaining numerical drift is upstream. If MoE still fails, inspect the new binding diagnostics and the `GetExpertSlice` / shared-expert weight shapes. If token 93633 still does not win, compare op 0, 2, 4, 10, 11, 19, 20, 21, 22 and 298 against an independently verified reference with the same input token. Avoid changing precision until the first divergent operation is known.

## Re-run patcher regression tests

```powershell
python F:\rawrxd\tools\parity_frontier\test_dispatch_order.py
```

**Note:** This archive was created without access to the user's Windows filesystem. Source patch regression tests run locally, but no full GGUF execution or Git push is asserted here.
