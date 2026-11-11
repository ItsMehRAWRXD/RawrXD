# Rawr `run` Blocker Ledger

This ledger records source and observed evidence for the native
`rawr run <model> <prompt>` route. It does not issue a full-model certificate.

## Implemented source boundaries

- CLI route: `~dev/rawr_monolith_v2.cpp` parses `run`, model aliases, bounded
  generation, `--device=gpu|cpu|auto`, `--context`, `--interactive`,
  `--receipt`, `--audit`, and explicit `--agent`.
- Model resolution: `~dev/src/rawr_model_resolver.cpp` resolves direct GGUF
  paths, local roots, and validated aliases for the certified Llama Q2_K,
  Phi-3, Qwen3, Qwen3.8, and Nemotron files.
- Shared engine route: `~dev/src/rawr_run_stream.cpp` owns one persistent
  `Deep2Engine`, explicit device policy, context admission, streaming output,
  deterministic sampling, and structured receipts.
- EOS ownership: `~dev/rawrxd/src/deep2/Tokenizer.hpp` exposes EOS identity;
  `Deep2Engine` stops before emitting the EOS control token.
- Agent route: `--agent` uses the existing `run_agent_session` and registered
  authority instead of silently routing to the audit-only driver.

## Evidence

- Release build: PASS — `F:\rawrxd\~dev\build\Release\rawr.exe`.
- Native primitives CTest: PASS — `1/1` in `F:\rawrxd\~dev\build`.
- CLI help and invalid-device parsing: PASS.
- Llama alias resolution: PASS — selected
  `F:\OllamaModels\_r1_iso\03_llama32_3b\llama3.2-3b-Q2_K.gguf`.
- CPU-only Llama smoke: FAIL CLOSED — model loaded and context admission
  passed, but the first CPU forward produced non-finite output in
  `blk.0.attn_q.weight`; no token was emitted. Receipt:
  `F:\rawrxd\evidence\rawr_run_phase1_cpu_smoke_20261020.json`.
- Q5_K specialized row-4 and row-8 real-weight probes: PASS with independent
  GGML and integer-lane comparisons. These are component results, not model
  certification.
- Prior Qwen3.5 production probe: execution-only evidence reported `552`
  GPU operations/token, `0` CPU operations, `1.408` decode TPS, and no
  independent full-model parity. It is not a certification receipt.

## Open blockers

- `RAW-RUN-001 CPU_NUMERICAL_FAILURE`: CPU fallback path is not a valid
  functional fallback until the first-layer non-finite output is diagnosed.
- `RAW-RUN-002 GPU_EXECUTION_FAIL_CLOSED`: the R9700/Vulkan pause was
  explicitly lifted and a GPU smoke was launched. Vulkan initialized and
  reached the resident graph, but prefill failed on a non-finite resident
  output. The first unsupported GPU boundary was `blk.0.attn_v.weight`,
  GGML type `Q3_K` (type 11); Q3_K shader admission is not yet numerically
  validated. Evidence:
  `F:\rawrxd\evidence\rawr_run_llama_layerdiag_20261020_v2.txt`.
- `RAW-RUN-003 EOS_RUNTIME_NOT_CERTIFIED`: EOS handling is implemented at the
  shared tokenizer/engine boundary but needs a completed multi-token run.
- `RAW-RUN-004 LLAMA_PARITY_NOT_REPRODUCED`: the existing reported Llama
  receipt was not independently rerun here; no new `FULL_MODEL_CERTIFIED`
  claim is made.
- `RAW-RUN-005 QWEN_FULL_MODEL_OPEN`: Qwen3/Qwen3.5/Qwen4Exp still require
  production graph coverage, multi-token state continuity, and independent
  parity across their actual architectures.
- `RAW-RUN-006 AGENT_E2E_NOT_RUN`: the explicit agent route is connected to
  existing authorization and bounded-loop code, but no model-driven tool
  transaction was run in this turn.
- `RAW-RUN-007 PERFORMANCE_OPEN`: specialized GEMV artifacts route only via
  opt-in, parity-tested selection. No claim of 40 TPS or 100+ TPS is made.

## Certification rule

`FULL_MODEL_CERTIFIED` remains false until the selected model completes all
layers, emits multiple autoregressive tokens with correct EOS behavior, passes
independent parity, records zero unauthorized CPU fallback, and produces a
reproducible receipt. Component tests, build success, and process exit `0`
cannot close these gates.

## Next 25 blocker queue

Each item remains open until its stated evidence exists; listing an item is not
an implementation claim.

1. `RAW-RUN-008` — Q3_K GPU GEMV: independent device/reference parity.
2. `RAW-RUN-009` — First non-finite GPU layer: per-layer finite checkpoint.
3. `RAW-RUN-010` — Q2_K/Q4_K/Q5_K/Q6_K mixed-format parity in one model.
4. `RAW-RUN-011` — GPU output projection finite-output validation.
5. `RAW-RUN-012` — CPU Q2_K first-layer non-finite diagnosis.
6. `RAW-RUN-013` — CPU/GPU tokenizer identity receipt.
7. `RAW-RUN-014` — Prompt-token history parity across prefill positions.
8. `RAW-RUN-015` — KV-cache append/readback parity across two tokens.
9. `RAW-RUN-016` — Recurrent-state reset and model-rebind verification.
10. `RAW-RUN-017` — EOS token identity and non-emission receipt.
11. `RAW-RUN-018` — Multi-token streaming stdout receipt.
12. `RAW-RUN-019` — Deterministic replay hash for identical request/configuration.
13. `RAW-RUN-020` — Llama 255/255 tensor binding receipt through `rawr run`.
14. `RAW-RUN-021` — Complete 28-layer Llama execution coverage receipt.
15. `RAW-RUN-022` — Independent Llama logits parity through the CLI route.
16. `RAW-RUN-023` — Qwen3 architecture admission and tensor-role map.
17. `RAW-RUN-024` — Qwen3.5 96-layer hybrid topology execution.
18. `RAW-RUN-025` — Qwen4Exp operator binding in production executor.
19. `RAW-RUN-026` — Two-shard offset and payload-bound validation.
20. `RAW-RUN-027` — Zero unauthorized CPU fallback on GPU policy.
21. `RAW-RUN-028` — GPU queue/device-loss recovery receipt.
22. `RAW-RUN-029` — Specialized quant pipeline cache parity and identity.
23. `RAW-RUN-030` — Warm-residency upload/miss accounting over multiple tokens.
24. `RAW-RUN-031` — Agent tool transaction with authorization and rollback.
25. `RAW-RUN-032` — Sustained performance receipt; no 40/100/150 TPS claim yet.
