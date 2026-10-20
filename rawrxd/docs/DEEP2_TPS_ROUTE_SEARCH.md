# Deep2 TPS route search

`deep2_tps_route_search.ps1` searches reversible runtime configurations without editing source files. It treats a failed configuration as a rejected candidate and continues through bounded variations of:

- primary-only versus layer-split execution;
- GPU throughput weights;
- Q4 tile size;
- the existing Q4/Q6 hot paths.

Every candidate is run through `deep2_gpu_flight_recorder.ps1`. A candidate is valid only when every requested run completes the token count with zero host-forward layers, nonfinite values, and fence failures. It is accepted only when its median exceeds `BaselineMedianTps * (1 + MinRelativeGain)`.

The search writes one isolated directory per candidate plus `route_search_summary.json`. It never changes source files, persistent environment variables, or the active runtime default. The `best` and `accepted` entries are recommendations for a separately reviewed configuration change.

Example after the GPU benchmark pause is explicitly lifted:

```powershell
pwsh -NoProfile -File .\scripts\deep2_tps_route_search.ps1 `
  -Exe 'F:\wt_ide1\_s12_parity_build\bin\deep2_end_to_end_bench.exe' `
  -Model 'F:\~dev\qwen2.5-coder-1.5b-base.gguf' `
  -BaselineMedianTps 30.101 -MinRelativeGain 0.005 `
  -Tokens 32 -WarmupRuns 1 -Runs 3 -NoTrace `
  -OutputDir 'F:\wt_ide1\deep2_route_search_3x32'
```

The search is evidence collection, not automatic promotion. Long-generation parity and a controlled A/B/A run remain required before changing the production default.
