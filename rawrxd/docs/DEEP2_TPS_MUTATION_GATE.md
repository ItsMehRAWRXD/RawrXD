# Deep2 TPS mutation gate

`scripts/deep2_tps_mutation_gate.ps1` runs one optimization candidate through a fail-closed loop:

1. Enroll an immutable Gate 21 baseline with canonical paths, byte lengths, content hashes, and an isolated snapshot.
2. Run a mutation script with `RAWRXD_MUTATION_ROOT` and `RAWRXD_MUTATION_ALLOWED_FILES` set.
3. Reject undeclared source changes.
4. Build the candidate and run optional validation.
5. Run the flight-recorder benchmark only after the separate resume authorization is present,
   and require every run to pass.
6. Require the candidate median TPS to exceed the baseline by `MinRelativeGain`.
7. Restore the exact snapshot on every rejection and every non-promoted success through the crash-recoverable Gate 21 keeper.
8. Verify the restored inventory and optionally rebuild the baseline so a stale candidate executable cannot be measured later.
9. Append state transitions to the hash-linked `MutationLedger`.

The controller never stages, commits, resets, or stashes the repository. Existing unrelated worktree changes are fingerprinted and left alone; mutation of a pre-existing dirty file is rejected. Candidate source is restored by default even after an accepted measurement. Use `-Promote` only for an explicit promotion transaction. Use `-SkipRebuildAfterReject` only when the build output is external and independently controlled.

## Benchmark pause

The gate is source-only by default. It runs mutation, build, and validation, then records
`DRY_RUN_ONLY` and restores without starting a model. Supplying `-ResumeBenchmarks` is still
not sufficient: the process must also contain
`RAWRXD_D2_BENCHMARK_AUTHORIZATION=EXPLICIT_USER_RESUME`. This separate authorization is the
active D2/R9700 pause boundary.

## Gate 21/22 and MutationLedger

`scripts/deep2_gatekeeper.ps1` implements the source-only Gate 21/22 boundary:

- `-Action CaptureBaseline` creates a create-once baseline and verifies its complete snapshot.
- `-Action VerifyBaseline` rejects missing, changed, or invalidly enrolled files.
- `-Action Restore` stages and verifies the snapshot, writes a durable recovery record, restores, and verifies again.
- `-Action Recover` completes an orphaned `APPLYING` transaction.
- `-Action FaultTest` runs nine disposable-fixture failure tests and must report `test_count=9` and `passed=true`.

`scripts/deep2_mutation_ledger.ps1` stores canonical UTF-8 records in append-only JSONL. Each
entry binds the previous hash, an explicit byte length, and the exact canonical record bytes.
The separate `.head` file is checked on every append and verification. A tampered line, missing
head, sequence gap, length mismatch, or canonicalization change fails closed.

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

The mutation script is responsible for applying one candidate. A rejected candidate exits `2` and
prints `RESTORE_VERIFIED=True`. An accepted candidate is restored unless `-Promote` is explicitly
provided; promoted candidates remain live only after the promotion transaction verifies every
declared file and exits `0`.

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
