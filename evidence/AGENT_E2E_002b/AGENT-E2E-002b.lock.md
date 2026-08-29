# AGENT-E2E-002b — LOCK / VERDICT

**Status:** `AGENT-E2E-002b=FAIL` (honest — capability gap, not fake green)

**Started:** 2026-08-29  
**Authority chain (prerequisite):** tokenizer/specials PASS · raw BOS parity PASS · no-BOS UE PASS · CPU llama `-fa off` oracle MATCH · FA-auto tip informational only · HexMag MASM frozen/out of chase

---

## Certification flags (recorded)

| Flag | Value |
|------|-------|
| `demo_break` | `false` |
| `scripted_runtime` | `false` |
| `fa_auto_authority` | `false` (not used in pass/fail) |
| HexMag | frozen / out of chase (orchestration authority not chased) |
| Deep2 inference | authority path (Q4_K_M via `build-win32ide-fresh`) |

## Frozen model

- **Path:** `F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- **SHA256:** `9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0`

## Required proof chain

```text
real model output → real tool decision → real filesystem/code action → real build/run → goal.satisfied
```

## Case results

### 01_compile

- `agent_exit=0`, `elapsed_ms≈243679`
- Real Deep2 greedy generation occurred (`[GREEDY] enabled=1`)
- Model emitted **prose**, not `TOOL_CALL:` / tool JSON
- `transcript_has_tool_calls=false`
- `source_mutated=false`
- Independent proof: `build_exit=1`, `run_exit=-1`, `stdout=NO_EXE`
- **`goal.satisfied=false` / `PASS=false`**

### 04_logic_bug (headline)

- `agent_exit=0`, `elapsed_ms≈116917`
- Real Deep2 greedy generation; no tool calls
- `source_mutated=false`
- Independent proof: `build_exit=0` (logic bug compiles), `run_exit=1`, `stdout=FAIL got=-1 expected=5`
- **`goal.satisfied=false` / `PASS=false`**

## What was proven (infrastructure)

1. `RawrXD-Agentic` rebuilt against certified `InferenceEngine` (`build-win32ide-fresh`).
2. `QuantKernelRegistry` initializes on `loadModel` — Q4_K `GetGEMV(12)` match=1.
3. Agentic no longer `QUANT_FATAL`s on Q4_K (prior `build-ninja` binary was stale/uninitialized registry).
4. `RAWRXD_GREEDY=1` forces deterministic sampling in `generateText`.
5. B3_STATE / KERNEL / LinearW file traces default OFF (agentic usable).
6. Zero GGUF embed row for SPM byte-fallback token 35 (`<0x20>`) tolerated (`WARN_EMBED`) instead of hard-aborting prefill.
7. Agentic parser accepts RawrXD `TOOL_CALL: name {json}` grammar (in addition to JSON tool objects).
8. Harness: `scripts/RUN_AGENT_E2E_002b.ps1` — fails hard on mocked/scripted/demo-break markers; FA-auto not consulted.

## What failed (honest gap)

TinyLlama-1.1B-Chat under Deep2 **does not emit tool decisions** for the 002b repair tasks. Without tools there is no filesystem mutation and no agent-driven build/run loop. Independent verifiers correctly stay red.

`ide_agent_loop_cert --mode deep2` spine attempt aborted immediately (`SPINE_EXIT=-1073740791` / `0xC0000409`) with empty stdout — recorded under `evidence/AGENT_E2E_002b/spine_ide_agent_loop/`; not used as a green substitute.

## Explicit non-substitutions

- No demo-break prepass
- No scripted runtime / canned `TOOL_CALL`
- No FA-auto tip used as authority
- No HexMag chase (frozen)
- No claiming `goal.satisfied` from prose/`SUCCESS` strings

## Artifacts

- `evidence/AGENT_E2E_002b/MODEL_SHA256.txt`
- `evidence/AGENT_E2E_002b/SUITE_RESULTS.json`
- `evidence/AGENT_E2E_002b/01_compile/` (prompt, console, transcript, RUN_SUMMARY, proofs)
- `evidence/AGENT_E2E_002b/04_logic_bug/` (same)
- `scripts/RUN_AGENT_E2E_002b.ps1`

## Next unlock (not claimed here)

A model that reliably emits `TOOL_CALL:` under Deep2, **or** a larger GGUF with tool-call finetune, while keeping `demo_break=false` / `scripted_runtime=false`.
