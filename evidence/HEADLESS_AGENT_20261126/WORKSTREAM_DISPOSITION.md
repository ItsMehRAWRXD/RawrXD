# HEADLESS_AGENT workstream — consolidated disposition (2026-11-27)

Authoritative single-page record of the headless-agent tool-calling hardening workstream.
Controller under change: `tools/rawr_agent.cpp` -> `bin/rawr_agent.exe` (MSVC,
`_bb_build/build_agent.cmd`). Backend: Ollama @ 127.0.0.1:11434.

## Scope
Make the headless agent's tool-calling transport correct and robust across providers, and
give it deterministic (model-independent) verification so completion does not depend on the
model-compliance lottery.

## Commits (this workstream, branch integration/combined-2026-11-25)
| Commit | Type | Deliverable |
|--------|------|-------------|
| 63cb5b4f88 | feat | Per-provider tool-channel profile (deepseek=text up front; gpt-oss/qwen3/nemotron=native) |
| da1964493d | test | Channel-profile receipt |
| 9bcd0b1c50 | test | Native-channel lifecycle campaign (gpt-oss:20b full write→build→fix→finish PASS, functional=1) |
| fdb335a0d9 | fix  | Text-channel parser hardening (first KNOWN tool object; skip prose/reasoning) |
| 7734976973 | test | Parser receipt |
| 2adc93898b | fix  | Edit convergence feedback (return current content on "old not found") |
| ec817a69a6 | test | Edit receipt |
| fd6b2ddee9 | fix  | GUI-run short-circuit (skip 20 s block on a built GUI exe) |
| 33ade653e3 | test | GUI-run receipt |
| f4556f5cdb | test | Deterministic model-free E2E pipeline self-test (real MSVC build → short-circuit → functional gate) |
| 4e73c1852f | test | Pipeline receipt |

Independent peer corroboration: a665e29c15, 7e2da8d652, aeda6f1499 (native transport E2E PASS,
reliability gap = model compliance).

## Deterministic verification (compiled into the shipped binary; model-free)
| Self-test | Flag | Result |
|-----------|------|--------|
| Channel profile | `--self-test-channel` | 9/9 PASS |
| Text extraction | `--self-test-parse` | 7/7 PASS |
| Edit convergence | `--self-test-edit` | 5/5 PASS |
| GUI-run short-circuit | `--self-test-guirun` | 5/5 PASS |
| Full pipeline E2E (real MSVC build + functional gate) | `--self-test-pipeline` | PASS |

Run all: `bin\rawr_agent.exe --self-test-{channel,parse,edit,guirun,pipeline}`.

## Live evidence (real models)
- gpt-oss:20b native: full write→build→fix→finish lifecycle, `EVIDENCE functional=1`, RESULT=PASS (multiple runs; peer 37.3 s PASS).
- deepseek-coder-v2:16b text: `native_tools=0` up front, real `write` on the FIRST request (no HTTP-400 / retry waste).
- qwen3:8b native: tool calls parsed/executed every turn; INCOMPLETE only from model convergence within budget (channel correct).
- Edit convergence feedback observed live (old-not-found now returns current file content).

## Engineering state
```
DISCOVERED=1 SOURCE_TRACED=1 ROOT_CAUSE_IDENTIFIED=1 IMPLEMENTED=1 PRODUCTION_WIRED=1
COMPILED=1 LINKED=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1
NUMERICALLY_VERIFIED=NOT_APPLICABLE PERFORMANCE_VERIFIED=NOT_APPLICABLE
COMMITTED=1 PUSHED=0 DISPOSITIONED=1
```

## Explicitly NOT done (and why)
- **12/12 repeat-reliability target**: residual gap is MODEL-COMPLIANCE bound
  (reliability_final.txt / reliability_rootcause.txt), not a controller defect. Code levers
  (channel, parsing, edit feedback, run waste) are exhausted and verified.
- **Push**: not performed (not requested; remote mutation held). Branch is local.
- **Full IDE / deep2 product builds**: require the heavy MSVC + Vulkan build environment;
  out of scope for this controller workstream.

## Next executable actions (in priority order)
1. `git push` integration/combined-2026-11-25 (on request).
2. Model-compliance work (prompt/few-shot) if higher reliability is required — separate,
   model-dependent effort.
3. Full product build/certification in the MSVC+Vulkan environment (separate workstream).