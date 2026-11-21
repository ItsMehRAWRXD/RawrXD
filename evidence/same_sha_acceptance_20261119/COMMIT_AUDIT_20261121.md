# Commit audit — 2026-11-21 (Sprint 1)

Branch: `fix/ide-default-model-scan` (origin == local at audit time).

## 49feb27d28 — test(ide): verify model selector 1206 populates 234 items
- Scope: **control 1206** (model selector). `gui_model_selector_probe3.ps1`
  enumerates `GetDlgCtrlID == 1206`; `model_probe3_result.txt` records
  `FINAL COUNT=234 CURSEL=0 BLANK_ITEMS=0`.
- Verdict: **scope correct (1206); evidence-only, no product code.**

## 249db218fb — fix(ide): define onBackendSelectionChanged
- Adds `Win32IDE::onBackendSelectionChanged()` in
  `src/win32app/Win32IDE_AgentCommands.cpp` (34 lines) to satisfy the linker.
- Behavior: reads `CB_GETCURSEL` of the backend selector (1226), maps
  index→{deep2,strata,ollama}, persists preference, sets
  `RAWRXD_CHAT_BACKEND`, shows a `STRATA_NOT_ROUTABLE` MessageBox for strata.
- Audit findings:
  1. **Persistence is duplicated.** It writes
     `F:\rawrxd\.rawrxd\cli_backend_pref.txt` directly with `fopen_s`,
     reimplementing the CLI's `saveBackendPref()` (`src/rawr_cli.cpp:1763`).
     The path is hardcoded (`rawr_cli.cpp:1744` hardcodes the same
     `F:\rawrxd` root).
  2. **Hardcoded developer path** `F:\rawrxd\.rawrxd\...` — portability FAIL
     (same class of defect as `F:\rawrxd\models`).
  3. **Second persistence channel.** It also sets the
     `RAWRXD_CHAT_BACKEND` environment variable, which the CLI path does not
     use; routing/persistence should have one source of truth.
  4. **Notification/routing are not duplicated** — the strata
     `STRATA_NOT_ROUTABLE` MessageBox is the intended unavailable-backend
     contract (no silent Ollama fallback).
- Verdict: **handler present and links, but duplicates persistence and
  hardcodes a developer path.** Follow-up: route GUI persistence through a
  shared, portable helper (see Sprint 3 resolution policy).

## Historical evidence
- `gui5_result.txt` marked **SUPERSEDED** (banner prepended, original body
  preserved verbatim). Its `CB_COUNT=1 CB_CURSEL=1` is a
  `SendMessageTimeoutW` return-value misread, not combo state.