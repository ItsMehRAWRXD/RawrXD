# Q6 algebra mutation family

`tools/mutate_qgemv_q6_algebra.ps1` prepares reversible shader candidates for the existing TPS mutation gate. It does not run the model or change weights.

Variants:

- `hoist_scale`: computes `d * scale` once per four-value decode group;
- `half_load`: reads the Q6 block half through the existing packed four-byte loader;
- `hoist_scale_half_load`: combines both changes.
- `skip_unused_batch_rows`: avoids writing inactive shared activation planes when the push-constant batch is one.

Each variant requires the shader and generated SPIR-V to be declared in the gate's `-Files` list. The gate must compile, validate with `spirv-val`, run all correctness checks, and collect multiple valid TPS samples before accepting a candidate. A rejected candidate is restored by the gate and its restoration build remains enabled by default.

Example after benchmark resume:

```powershell
$env:RAWRXD_MUTATION_VARIANT = 'hoist_scale_half_load'
pwsh -NoProfile -File .\scripts\deep2_tps_mutation_gate.ps1 `
  -MutationScript .\tools\mutate_qgemv_q6_algebra.ps1 `
  -Files @('rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv') `
  -BuildCommand pwsh -BuildArguments @('-NoProfile','-File','scripts/build_s12_parity.ps1') `
  -ValidationCommand 'C:\VulkanSDK\1.4.357.0\Bin\spirv-val.exe' `
  -ValidationArguments @('--target-env','vulkan1.2','rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv') `
  -BenchmarkScript .\scripts\deep2_gpu_flight_recorder.ps1 `
  -BenchmarkArguments @('-Tokens',32,'-WarmupRuns',1,'-Runs',3,'-Q4Hot','-Q6Hot','-PrimaryOnly','-NoTrace') `
  -BaselineMedianTps 31.392 -MinRelativeGain 0.005 `
  -ReportPath .\audit\deep2_q6_algebra_mutation.json
```
