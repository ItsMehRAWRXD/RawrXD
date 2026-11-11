# DEEP2-CLI-AGENTIC-BATCH-16-20261111

Baseline: `ce0acb9bfe3ce6d01531ef96c19d28298532f718`
Branch: `upload/ide-fixes-20261111`
Worker scope: one bounded implementation worker; no agents spawned.

## Changes

- `src/rawr_cli.cpp`: route `rawr run --backend=ollama` through the existing
  `llama3.2-3b` -> `llama3.2:3b` tag translation.
- `tests/q6k_row_differential_test.cpp`: replace the flat Q6_K test oracle with
  the canonical four-stream/interleaved layout and make dequant/GEMV mismatch
  return failure instead of printing a false-success result.

## Verification

Builds completed with MSVC Release configuration:

```text
cmake --build build_ide --config Release --target q6k_row_differential_test -j 2
cmake --build build_ide --config Release --target RawrXD-CLI-V2 -j 2
cmake --build build_ide --config Release --target deep2_fused_lmhead_verify -j 2
```

`evidence/DEEP2_CLI_AGENTIC_BATCH_16_q6k_parity.txt`:

- Q6_K dequant max absolute difference: `0`
- production GEMV max absolute difference: `0`
- row-sliced GEMV checks: `0` difference
- process exit: `0`

`evidence/DEEP2_CLI_AGENTIC_BATCH_16_runtime_baseline.txt` and
`evidence/DEEP2_CLI_AGENTIC_BATCH_16_cpu_q6_runtime.txt` are real production
CLI runs against `llama3.2-3b-Q2_K.gguf`. Both load the tied Q6_K LM head with
`rows=128256`, `cols=3072`, finite logits, RMS approximately `1.5`, and greedy
select token `1134` (`<<`) instead of the requested `DEEP2` token. The CPU-forced
run produces the same result. This remains a correctness failure; no product
correctness pass is claimed.

The direct fused verifier initially terminated with Windows status
`0xC0000409` before LM-head execution under its normal enhancement setup.
With explicit diagnostic controls
`RAWRXD_ENHANCE_SKIP=1`, `RAWR_REAP_CPU_ONLY=1`, and
`RAWRXD_DEEP2_DISABLE_Q6K_GPU=1`, it completed and wrote
`evidence/DEEP2_CLI_AGENTIC_BATCH_16_fused_lmhead_skip/`:

- LM head: Q6_K, `128256 x 3072`
- finite logits: `128256 / 128256`
- CPU/GPU parity result: `max=0`, `avg=0`, `PASS`
- GPU forward layers: `0`
- verifier process exit: `0`

`evidence/DEEP2_CLI_AGENTIC_BATCH_16_ollama_smoke.txt` records a real
`rawr run --backend=ollama` one-shot against the installed
`qwen2.5-coder:1.5b-base` tag: endpoint reachable, answer accepted at turn 1,
JSON completed, zero tool calls. The installed Ollama registry did not contain
`llama3.2:3b`, so that translated tag was not falsely reported as live-tested.
`rawr swarm --help` confirms the CLI entry point; no swarm was started because
this batch explicitly permits only one implementation worker.

## Disposition

Build and targeted unit/runtime checks are recorded. The real llama token is
still wrong, so T24 remains `FAIL`; real GPU forward, Strata wiring, GUI
verification, extension E2E, MASM LSP integration, T25, and promotion remain
open/held. The supplied GUI artifact was used only as verification context.
