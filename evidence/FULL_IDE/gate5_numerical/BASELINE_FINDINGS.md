# Gate 5 numerical and production seam baseline

Inspection revision: `843a14c3298ab6aade87fbb597748bd8311f2716` (working-tree numerical changes also present). No product/runtime/CMake source edits were made in this workstream before its D1 reassignment.

## Historical evidence and present scope

Preserve `evidence/GAP_AUDIT_2026-10-13/GATE5_NUMERICAL_PARITY.md` and its receipts as historical bounded-error evidence. The recorded 129-position comparison reports CPU/reference greedy agreement 117/129 and GPU/reference agreement 116/129. Both first argmax disagreements occur at position 7; full-logit differences exist at position 0. Recorded worst CPU max-absolute error is 1.188872, worst GPU max-absolute error 1.168507. These are historical measurements, not a fresh execution at the inspection revision.

The Gate 5 directory currently retains summary JSON/text, token files and command files. Its `ref_head`, `d2_cpu_head` and `d2_gpu_head` raw artifact directories are absent. Thus the 387 historical raw logit files cannot be revalidated from that directory without regeneration. Historical summaries are preserved.

## Correction: actual independent reference activation format

`inspect_reference_traits.py` calls the exact reference dependency's public `ggml_get_type_traits_cpu` export, without model execution or GPU initialization. `reference_binary_traits.json` contains executable/dependency SHA-256 values and the measured traits:

- Q4_K (12) uses Q8_K (15).
- Q6_K (14) uses Q8_K (15).
- Q4_0 (2) and Q8_0 (8) use Q8_0 (8).

The historical explanation that this TinyLlama K-quant reference differs because it uses per-32 Q8_0 activations is unsupported and contradicted for Q4_K/Q6_K by the actual reference binary. Both those weight families use per-256 Q8_K. This correction does not delete or alter historical measurements.

## Acceptance gap

`tools/gate5_independent_logits_compare.py` and `tools/gate5_reverify_sweep.ps1` classify disagreement as acceptable when the reference margin is less than the same position's measured max error. They impose no independent maximum end-to-end error. This may describe an observed ordering change, but it does not independently bound acceptable numerical error. For example, reference logits [1,0] versus corrupted logits [0,1000] satisfy margin 1 < observed error 1000 despite opposite greedy choices.

The separate kernel relative bound <=1e-4 has pre-existing authority in the Gate 4 certification. Operator maxabs 1e-4 and first-logit-error maxabs 1e-2 are existing localization thresholds in the comparator. `DIAGNOSTIC_CONTRACT.json` freezes these existing diagnostic bounds and strict greedy equality before a proposed fresh run; they are not a new release tolerance definition.

`tools/gate7_tps_reference_check.py` currently emits PASS_BOUNDED for any finite reference stream that fails exact agreement, without enforcing a numerical bound. Its preserved result is 127/128 decisions matching, first mismatch at position 7. It should not be promoted to exact greedy correctness.

## Real Native IDE seam

The actual `RawrXD-Win32IDE-Native` CMake target uses `src/cpu_inference_engine_impl.cpp` (CMakeLists.txt:1799), **not** the obsolete `src/cpu_inference_engine.cpp`. `Win32IDE.cpp` calls `NativeEngineInfer`, which calls CPUInferenceEngine::Tokenize and GenerateStreaming.

The selected implementation has concrete failures for the certified TinyLlama GQA model:

- LoadModel heuristically derives `head_dim` and `kv_dim` but does not assign `m_headDim` or `m_kvDim`.
- Eval reads `m_headDim` (default 0), and uses `kv_dim=m_embeddingDim` rather than the model's K/V projection width. TinyLlama has embedding width 2048 and K/V width 256. Its K/V projection check fails before real generation.
- ConfigureGeneration is empty; generation options are ignored.
- Its tokenization is greedy text matching rather than the model's score/merge based tokenizer.
- RuntimeGraph::Executor is currently used by tools, not by this Native IDE numerical implementation.

Smallest coherent production repair would replace the selected implementation's separate numerical loop with a RuntimeGraph adapter, retain public NativeEngineInfer API, use a per-instance real tokenizer, and expose backend/nonfinite/position/error receipts. This adapter is deferred by the user's D1/D2 priority change and has not been implemented.

## Model lifetime prerequisite for any product adapter

Universal::Ingest currently returns mutable process-global `g_last` and closes/replaces the prior process-global mapped Reader on every load (`universal_gguf.cpp:1149–1162`). Copying IngestReport alone does not retain mapping ownership; later loads can invalidate prior executor tensor pointers. An adapter needs an owned value-returning session retaining mapping + report + tokenizer + provenance, or an enforceable shared fail-closed lifetime guard.

## Fresh diagnostic disposition

Two bounded-run attempts refused to launch before loading any model. Attempt 2 records competing `deep2_strata_bench.exe` PID 26016 with `--prefill 8 --generate 64 --spec 64 --repeat-prompt --gpu --tag gate7_run2_repeat`. Its frozen process snapshot is `bounded_pos0_7_attempt2/manifest.json`. No GPU/reference model execution occurred in this workstream. Process-name snapshots alone are insufficient to claim complete GPU isolation.

Current status: **historical bounded evidence preserved; exact reference/product-path certification remains OPEN**. D1 true batched prefill now takes priority. No source ownership transfer or root-cause repair has been claimed complete.
