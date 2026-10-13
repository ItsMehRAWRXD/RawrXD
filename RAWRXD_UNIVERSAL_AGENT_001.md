# RAWRXD_UNIVERSAL_AGENT_001 — `rawr ask` evidence & crash acceptance

Date: 2026-10-13
Status: PARTIAL PASS — host crash fixed; host-owned evidence routing not yet enforced.
This file records a fingerprinted acceptance run of the universal `rawr ask`
controller (`src/rawr_cli.cpp` + `src/rawr_core.cpp` + `src/rawr_core.hpp` +
`src/rawr_reasoning.hpp`). It is an honest snapshot, not a claim of completion.

## Build provenance (reproducible)

- Canonical build recipe: `src/build_rawr.bat` → `bin/rawr.exe`.
  `cl /std:c++20 /EHsc /O2 ... rawr_cli.cpp rawr_core.cpp /link winhttp ws2_32 advapi32 kernel32 user32`
- Built binary fingerprint at this report: `bin/rawr.exe` 853504 B, SHA256 `F7E1A0D97BC25893E8B40463` (low 24 hex).
- source_sha256 (low 24 hex) recorded at commit time via `git show --stat` / manifest below.
- Toolchain: MSVC VS2022 BuildTools; nlohmann/json bundled under `include/`.

## Runtime configuration observed

- Backend (active): `llama-server.exe` serving `F:\rawrxd\llama3.2-3b-Q2_K.gguf`
  on `http://127.0.0.1:8080/v1/chat/completions` (ctx-size 8192).
- NOTE: the served model is a 3B Q2_K. Several "agent reasoning" results below
  are gated by MODEL CAPABILITY, not by the controller. This is called out per test.

## What was fixed in this cycle (verified)

1. `type_error.306` JSON crash on the ask path — FIXED.
   - `InferenceClient::complete`: null-`usage`, null/missing `message.content`
     and non-string fields are now guarded (no crash on `"usage": null`).
   - `answerUniversal`: a model reply that parses to a non-object (number,
     string, array) is normalized to null and guarded with `is_object()` before
     any `.value(...)` — this was the "cannot use value() with number" path.
   - Containment: `main` already wraps dispatch in `try/catch` → EXIT_CRASH(42).
   - Result: math, entanglement, tool-read, spoof all return EXIT 0.
2. Bounded injected history: `buildUniversalPrompt` now injects only the most
   recent 8 turns (truncated to 600 chars each) instead of the entire
   `evidence/agent_memory.jsonl`, stopping small-model regurgitation.
3. Host-authoritative `tools_executed` (H2): `cmdAsk` counts only receipts the
   executor actually ran (`ActionStatus::Executed`); model-`Proposed` calls are
   reported but never counted, and plain output lists only real executions
   (with a "N proposed call(s) suppressed" line). Fixes the spoof "14 vs 1 real".

## Acceptance matrix (this report is the record)

| Test                  | Exit | Host ledger              | Result | Notes |
|-----------------------|------|--------------------------|--------|-------|
| JSON_NULL_REGRESSION  | 0    | n/a                      | PASS   | no `type_error.306` across number/null/malformed replies |
| MATH (17×19)          | 0    | no tools                 | MODEL  | returned 114 (wrong; 323). Model error, not a crash |
| ENTANGLEMENT          | 0    | no tools                 | PARTIAL| no FTL-signaling caveat (prompt/model gap) |
| README_READ           | 0    | receipts:[], tools_exec:0| FAIL   | invented first line despite zero tool receipts |
| RECEIPT_SPOOF         | 0    | 1 executed + 13 proposed | FAIL   | real search ran once (query="executed"); 13 duplicate *proposed*; `tools_executed:14` counts proposals |

## Remaining host-side defects (owner: controller, NOT model)

- H1 Host-owned evidence routing. If the request asks to read/search a file,
  the host must REQUIRE a matching successful receipt; if absent, return
  ToolRequired/UnableToVerify — never invent file content. README_READ fails this.
- H2 Receipt authority. `tools_executed` must count only `ActionStatus::Executed`
  receipts, not `Proposed` ones. Spoof shows 14 vs 1 real.
- H3 Circuit breaker / dedup boundary: identical read-only calls are suppressed
  for execution, but the loop did not terminate — 13 duplicate proposals leaked.
  Force a final_answer after N duplicates.
- H4 No-tools enforcement: the spoof question prohibited tools yet a real
  `search_text` executed. A host no-tools flag must reject tool proposals.
- H5 Source-scope: `search_text` still surfaced `.json`/`.archive` hits; tighten
  the default source-extension allow-list.

## Model-vs-controller conclusion

The controller no longer crashes and its ledger fields are host-derived
(their values are set from the executor, not from model text). The remaining
README_READ "invented content" and entanglement caveat are evidence-gating and
model-quality issues respectively. With a capable backend the entanglement and
arithmetic lines are expected to resolve without controller changes; H1–H5 are
controller work that must pass before the gate RAWRXD_UNIVERSAL_AGENT_001 can
be marked PASS.

## Regenerate

    src\build_rawr.bat
    .\bin\rawr.exe ask "read the file README_PRODUCTION.md and report its first line" --json

## Verified gate results (frozen baseline, binary from committed bytes)

Baselines on `origin/local-30b-backend`:
- `bcb7c60ae` checkpoint freeze (host-verified evidence contract; index tree c2df5e39cd compiled RC=0)
- `7e19c58c9` logLine stderr routing (pure `--json` stdout)

| Gate                | Result | Evidence (frozen binary, 3B Q2_K backend) |
|---------------------|--------|------------------------------------------|
| Reproducible build  | PASS   | `git archive <commit>` + cl -> RC=0; binary SHA recorded |
| type_error.306      | PASS   | EXIT 0 across number/null/malformed replies |
| H2 receipt counting | PASS   | `tools_executed` counts only `ActionStatus::Executed` |
| H1 evidence routing | PASS   | README_READ -> "I could not verify ... any content I offered would be invented"; tools_executed=0, no fabricated first line |
| H4 no-tools enforce | PASS   | spoof -> tools_executed=0, receipts=[], grounded=false; forged `[tool-receipt]` has no authority; host logged "tool execution refused by host policy" |
| --json purity       | PASS   | `logLine()` now `fprintf(stderr,...)`; stdout is pure JSON (ConvertFrom-Json OK) |
| H3 breaker          | OPEN   | duplicate proposals must terminate the loop at host level (file under active edit) |
| H5 source scope     | OPEN   | exclude `.archive`/`.log`, drop `.json`/`.md` from default code-scope; `all=true` must remain gated by host authorization policy, not just isExcludedFromWalk |

Release gate still requires H3 + H5 to pass from the same frozen revision before RAWRXD_UNIVERSAL_AGENT_001 can be marked complete.

