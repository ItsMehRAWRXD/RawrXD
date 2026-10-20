# Deep2 TPS receipt profiler

`deep2_tps_receipt_profiler.ps1` is a read-only analyzer for existing flight-recorder reports and `GPUFWD_TIMING` logs. It does not start the benchmark, change environment variables, alter model files, or mutate source.

It reports:

- median, minimum, and maximum decode TPS and token latency;
- route metadata such as primary-only execution, layer split, tile size, and Q6 hot-path status;
- the measured host intervals for upload, prime, range execution, handoff, and final materialization;
- the largest measured host interval and speedup required for 50/75/100/150 TPS.

Example:

```powershell
$evidence = @(
  'F:\wt_ide1\deep2_primary_only_q6packed_3x32'
  'F:\wt_ide1\deep2_current_control_pair'
)
pwsh -NoProfile -File .\scripts\deep2_tps_receipt_profiler.ps1 `
  -Paths ($evidence -join ',') `
  -OutputPath 'F:\wt_ide1\deep2_receipt_profile.json'
```

Use the resulting breakdown to choose the next optimization class. Do not add host intervals together as a proof of total latency when the runtime overlaps them; they are attribution signals, not a replacement for end-to-end TPS.
