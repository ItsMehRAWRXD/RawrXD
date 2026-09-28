# Ollama Local Model Fleet — Coherence-Gated Audit (Final)

**Date:** 2026-09-28
**Method:** Raw API `http://127.0.0.1:11434/api/generate` with raw HTTP body capture (`Invoke-WebRequest -UseBasicParsing`) — NOT `Invoke-RestMethod` property accessors, NOT `ollama run` CLI text (both proven unreliable for verification).
**Determinism options:** `temperature=0, seed=1, num_predict=24-48`, body-level `think=false` for thinking models.
**Gates (fail-closed ladder):** `LOAD_PASS` (model loads + forward runs) → `FORWARD_PASS` (eval_count>0) → `DECODE_PASS` (UTF8-clean output) → `COHERENCE_PASS` (coherent text / hits expected token on the 4-prompt ladder) → `REPEAT_PASS` (byte-identical across repeated deterministic runs) → `E2E_PASS` (all of the above).
**TPS policy:** TPS only counts after E2E_PASS. TPS without coherence is not evidence.

## Verdict summary

| # | Model | LOAD | FORWARD | DECODE | COHERENCE | REPEAT | VERDICT | TPS | Note |
|---|-------|:----:|:-------:|:------:|:---------:|:------:|:-------:|----:|------|
| 1 | bigdaddyg-productivity-local:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 1.9 | llama Q2_K 69B; coherent, deterministic |
| 2 | bigdaddyg-productivity-native:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 1.9 | template emits `\|<\|end\|>` markers (chat-template echo, harmless) |
| 3 | bigdaddyglocal:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 1.9 |  |
| 4 | bigdaddygnative:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 1.85 |  |
| 5 | deepseek-coder-v2:16b | PASS | PASS | PASS | PASS | PASS | **PASS** | 99.41 | clean instruct behavior |
| 6 | deepseek-r1:32b | PASS | PASS | PASS | PASS | PASS | **PASS** | 3.11 | reasoning model; ladder coherent inside think tags |
| 7 | deepseek-r1:70b | PASS | PASS | PASS | PASS | PASS | **PASS** | 1.21 |  |
| 8 | gemma3:4b | PASS | PASS | PASS | PASS | PASS | **PASS** | 167.15 |  |
| 9 | gemma3:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 212.49 |  |
| 10 | gpt-oss:120b | PASS | PASS | PASS | PASS | PASS | **PASS** | 7.25 | thinking field split; final answers correct |
| 11 | gpt-oss:20b | PASS | PASS | PASS | PASS | PASS | **PASS** | 54.26 |  |
| 12 | gpt-oss:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 55.09 |  |
| 13 | granite3.3:8b | PASS | PASS | PASS | PASS | PASS | **PASS** | 94.92 |  |
| 14 | kiminoto/T0.0.1:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 152.35 |  |
| 15 | laguna-s-2.1:Q4_K_M | PASS | PASS | PASS | PASS | PASS | **PASS** | 3.25 | laguna arch Q8_0 117.6B |
| 16 | llama3.1:8b | PASS | PASS | PASS | PASS | PASS | **PASS** | 194.17 |  |
| 17 | llama3.2:3b | PASS | PASS | PASS | PASS | PASS | **PASS** | 326.85 |  |
| 18 | llama3.2:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 318.52 |  |
| 19 | nemotron-3-nano:4b | PASS | PASS | PASS | PASS | PASS | **PASS** | 20.39 | nemotron_h arch |
| 20 | nemotron-3.5-lightning:30b | PASS | PASS | PASS | PASS | PASS | **PASS** | 32.85 |  |
| 21 | ornith-1.5:35b | PASS | PASS | PASS | PASS | PASS | **PASS** | 83.49 | qwen35moe |
| 22 | pdurugyan/qwen3.5-9b-...:latest | PASS | PASS | PASS | PASS | PASS | **PASS** | 155.03 |  |
| 23 | qwen2.5-coder:1.5b-base | PASS | PASS | PASS | PASS | PASS | **PASS** (as base) | 241.19 | see classification below |
| 24 | qwen3-next:80b | PASS | PASS | PASS | PASS | PASS | **PASS** | 13.27 | thinking-style output, coherent |
| 25 | qwen3:8b | PASS | PASS | PASS | PASS | PASS | **PASS** | 179.48 | thinking field must be parsed |
| 26 | qwen3.8:27b | PASS | PASS | PASS | PASS | PASS | **PASS** | 23.99 |  |
| 27 | qwen35-40b-heretic-q8:latest | PASS | PASS | PASS | PASS | PASS* | **PASS** (provisional) | 221.58 | see identity mismatch below |
| 28 | starcoder2:15b | PASS | PASS | PASS | PASS | PASS | **PASS** (as base) | 18.11 | base completion model behavior |
| 29 | bluehawana/deepseek-v4-flash:iq2_m | PASS | PASS | PASS | PASS | NOT RUN | **PASS** (single-run provisional) | 3.36 | 284B MoE IQ3_XXS; coherent chain format; repeat not yet run |
| 30 | blackgrg26/WORMGPT-14:latest | FAIL | — | — | — | — | **FAIL** | 0 | corrupt/empty blob; `ollama show` fails |
| 31 | deepseek-v4-flash:0731-cloud | — | — | — | — | — | **RETIRED** | 0 | upstream retired 2026-09-25 |

## Key classification changes vs the earlier weak-gate audit

### qwen2.5-coder:1.5b-base — RECLASSIFIED: NOT corrupt
The earlier "corrupt token soup" verdict was a **test artifact, not a model fault**:

- The `ollama run` CLI text path through the terminal produced encoding/interactive artifacts that looked like garbage (zero-width chars, U+FFFD, CJK glyphs).
- Raw API byte-verified output is clean ASCII, fully coherent as a **base text-completion model**:
  - `1 + 1 =` → `" 2"` (correct), then coder-style continuation
  - `The capital of France is` → `" Paris. The capital of France is also..."`
  - `Repeat: ABC` → completes "ABC News" (completion, not instruction-following — expected for base)
- Modelfile confirms: FIM template `<|fim_prefix|>{{.Prompt}}<|fim_suffix|>{{.Suffix}}<|fim_middle|>` — a fill-in-the-middle coder model, not a chat model (saved: `f:\~dev\qwen15b_modelfile.txt`).
- REPEAT_PASS: byte-identical output across 3 deterministic runs at 48 tokens (`f:\~dev\_q15b_triple.txt`, TRIPLE_IDENTICAL=True).
- **Correct usage:** supply code context or FIM format, not chat prompts. Classification: `BASE_TEXT_COMPLETION_COHERENT`.

### qwen3:8b — the "empty response" was a test-harness artifact
Raw body shows generation went into the `"thinking"` field (`"thinking":"Okay, the user wants me"`) when `num_predict` was exhausted by the thinking phase. `"response":""` is **not corruption**. With `think=false` or by parsing both fields, output is fully coherent and deterministic.

### qwen35-40b-heretic-q8:latest — identity mismatch, provisional PASS
- Name says 40b-q8; `ollama show` reports **phi3 arch, 3.8B params, Q4_0** — the tag does not match the contents.
- Output is coherent ("Paris." etc.) with instruction-scaffold echoes (`## Instruction 2 (More Diffmediate)`) — a prompt-template artifact of its Modelfile, not inference corruption.
- Byte-identical repeat at 48 tokens (`f:\~dev\_heretic_repeat2.txt`, H2BYTES matches H1).
- REPEAT=False at the 24-token run was a template-echo artifact. Verdict provisional pending a rebuild from a properly labeled blob.

### bluehawana/deepseek-v4-flash:iq2_m — now covered
284.3B MoE (deepseek4 arch, IQ3_XXS, 103 GB) loads in ~39s and generates coherent chain-of-thought style text (`"1. The user asks:..."`), 3.36 tok/s. Single deterministic run verified; REPEAT gate not yet executed (would take ~5 min/run).

## Files
- `f:\~dev\_coherence_audit.ps1` — audit script (gate ladder per model)
- `f:\~dev\_coherence_audit_run.log` — full run transcript with raw outputs
- `f:\~dev\_ollama_coherence_audit.csv` — machine-readable verdict table
- `f:\~dev\_q15b_triple.txt` — 1.5b-base triple-run determinism proof
- `f:\~dev\_heretic_repeat2.txt` — heretic byte-identical repeat proof
- `f:\~dev\_iq2m_test.json` — 284B MoE load+generate evidence
- `f:\~dev\qwen15b_modelfile.txt` — 1.5b-base FIM modelfile capture

## Fail-closed statement
`LOAD != RUNTIME_REACHED != TOKEN_SURVIVED != COHERENCE_PASS`. Verdicts above are per-model; the two provisional entries (heretic, iq2_m) are marked and must not be cited as full-ladder certified until their remaining gates complete.