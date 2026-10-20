# Deep2 TPS mutation gate

`scripts/deep2_tps_mutation_gate.ps1` runs one optimization candidate through a fail-closed loop:

1. Snapshot only the declared candidate files by SHA-256.
2. Run a mutation script with `RAWRXD_MUTATION_ROOT` and `RAWRXD_MUTATION_ALLOWED_FILES` set.
3. Reject undeclared source changes.
4. Build the candidate and run optional validation.
5. Run the flight-recorder benchmark and require every run to pass.
6. Require the candidate median TPS to exceed the baseline by `MinRelativeGain`.
7. Restore the exact snapshot on every rejection and verify its hashes.
8. Rebuild the baseline after rejection so a stale candidate executable cannot be measured later.

The controller never stages, commits, resets, or stashes the repository. Existing unrelated worktree changes are recorded and left alone. Use `-SkipRebuildAfterReject` only when the build output is external and independently controlled.

Example:

```powershell
& .\rawrxd\scripts\deep2_tps_mutation_gate.ps1 `
  -RepoRoot . `
  -MutationScript rawrxd/tools/unweightless_bridge_audit.ps1 `
  -Files @('rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv','rawrxd/src/deep2/vulkan_compute.h') `
  -BuildCommand cmake `
  -BuildArguments @('--build','_s12_parity_build','--target','deep2_end_to_end_bench','--config','Release','--parallel','8') `
  -ValidationCommand C:\VulkanSDK\1.4.357.0\Bin\spirv-val.exe `
  -ValidationArguments @('--target-env','vulkan1.2','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv') `
  -BenchmarkScript rawrxd/scripts/deep2_gpu_flight_recorder.ps1 `
  -BenchmarkArguments @('-Exe','_s12_parity_build/bin/deep2_end_to_end_bench.exe','-Model','F:\~dev\qwen2.5-coder-1.5b-base.gguf','-Tokens','32','-WarmupRuns','1','-Runs','3','-Q4Hot','-Q6Hot','-NoTrace') `
  -BaselineMedianTps 33.832 `
  -MinRelativeGain 0.01 `
  -ReportPath .rawrxd/tps_mutation_report.json
```

The mutation script is responsible for applying one candidate. A rejected candidate exits `2` and prints `RESTORE_VERIFIED=True`; an accepted candidate remains in the worktree for human review and exits `0`.

## Bounded variant sweep

Use the sweep controller when one idea has tunable variants. Each variant starts from the same declared-file snapshot; a rejection is restored before the next variant runs. The mutation script reads `RAWRXD_MUTATION_VARIANT` and must reject unknown values.

```powershell
& .\rawrxd\scripts\deep2_tps_mutation_sweep.ps1 `
  -MutationScript rawrxd/tools/mutate_qgemv_scalar_two_row.ps1 `
  -Variants @('scalar-two-row') `
  -Files @('rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv','rawrxd/src/deep2/vulkan_compute.h') `
  -BuildCommand cmake `
  -BuildArguments @('--build','_s12_parity_build','--target','deep2_end_to_end_bench','--config','Release','--parallel','8') `
  -ValidationCommand C:\VulkanSDK\1.4.357.0\Bin\spirv-val.exe `
  -ValidationArguments @('--target-env','vulkan1.2','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv') `
  -BenchmarkScript rawrxd/scripts/deep2_gpu_flight_recorder.ps1 `
  -BenchmarkArguments @('-Exe','_s12_parity_build/bin/deep2_end_to_end_bench.exe','-Model','F:\~dev\qwen2.5-coder-1.5b-base.gguf','-Tokens','32','-Runs','3','-Q4Hot','-Q6Hot','-NoTrace') `
  -BaselineMedianTps 33.832 `
  -MinRelativeGain 0.01
```

The sweep exits `0` only when a variant is accepted and leaves that variant for review. It exits `2` when every variant is rejected and writes one JSON report per attempt plus a summary.
