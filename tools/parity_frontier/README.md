# ModelGenie numerical parity: local repair, full-run diagnostics, and controlled publish

## Verified remote discrepancy

On `feat/hexmag-polymorphic-repeat-tuner-masm` at `b7f4c35fe482c9f7f6e2acff4959268ab67e2f46`, the tracked executor **still** contains wrong GGML strided accesses in `DotRows` and embedding; the tracked token0 executor still has `uint16_t scales[8]` in Q6_K, and the bad `B[k*N+j]` MatMul indexing. These fixes may already be present in your **local working tree**. The kit detects already-fixed code and never overwrites an unrecognized implementation. GitHub direct write access returned HTTP 403, so this kit supplies a local, credentialed Git push instead.

## Install

Extract the archive into `F:\rawrxd\tools`. This yields `F:\rawrxd\tools\parity_frontier\` containing the kit. The package **does not** replace your executor sources or touch generated headers, GGUF model files, or submodules.

In PowerShell 7:

```powershell
# Dry run, does not modify files
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\run_parity.ps1

# Repair, inject trace, build via VS2022, run full model, audit Q6_K and save evidence
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\run_parity.ps1 -Apply

# Same, and Git stage/commit/push only allowlisted sources and measured results
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\run_parity.ps1 -Apply -Push

# If matched reference IR activation dump exists
pwsh -NoProfile -File F:\rawrxd\tools\parity_frontier\run_parity.ps1 -Apply -Push -ReferenceDir 'F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001\parity_reference'
```

Requirements: `F:\rawrxd` checked out on the named branch, VS2022 BuildTools, Python 3, existing `compile_ir_executor.bat`, and the 10,364,416,768-byte GGUF at `G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf`. An existing staging index causes the runner to stop rather than commit unrelated changes. Build+model run are **not** performed in the assistant container. Run only when enough storage is available for build and trace files.

The runner stages ONLY the two executor `.cpp` files, trace header, kit sources, and logs/summary under `evidence/NUGVERSE_ESTIMATOR_001/`. **It deliberately excludes** `OrganizedPiProject/projects/01-active-projects/SaaSEncryptionSecurity` and never touches its dirty deletion state. Backups are created alongside source as `.pre_numerical_parity.bak` / `.before_parity_trace.bak` and never staged. Old `parity_ir/op_*.bin` files are cleared to prevent stale evidence, not from any other location.

## Real-run evidence

- `evidence/NUGVERSE_ESTIMATOR_001/parity_ir_run.log`: actual IR executor output
- `evidence/NUGVERSE_ESTIMATOR_001/parity_ir_summary.txt`: branch SHA, GGUF SHA256, execution and parity gates, no invented PASS
- `evidence/NUGVERSE_ESTIMATOR_001/parity_q6_audit.log`: direct packed Q6_K vs executor LM-head output for op_298/op_299
- `evidence/NUGVERSE_ESTIMATOR_001/parity_ir/op_*.bin`: selected per-operation float32 activations (raw binaries are **not** pushed by default)
- `evidence/NUGVERSE_ESTIMATOR_001/parity_compare.log`: only with a real matched reference

`Q6_LAYOUT_SELFTEST=PASS` checks synthetic decode, not model parity. `LMHEAD_ARGMAX_MATCH=1` checks the LM head against the same final hidden state, not the earlier 27-block computation. The requested token `93633` must be confirmed against a trusted **full** model reference with the same input token, position, model, and sampling. A partial token0 executable returning `1597` is not that reference. The token0's simplified legacy MLA path remains partial; the numerical index/quant patches do not certify it as fully equivalent.

`-Push` publishes real measured FAIL evidence too, with explicit `TARGET_TOKEN_MATCH=0`; it does not fake a pass. A final real forward pass and independent reference are unavailable here. Direct GitHub updates from the assistant were blocked with HTTP 403.

## Applied numeric corrections

- GGML contiguous dimension zero: `weight[token*in+j]` for embedding and `weight[i*in+j]` for matvec.
- Q6_K uses `int8_t scales[16]`, block size 210, 16-value groups.
- token0 diagnostic MatMul uses `B[j*K+k]` and double-precision accumulation as a reference baseline.
- IR tracer instruments only successful output activations and preserves generated IR authority.
