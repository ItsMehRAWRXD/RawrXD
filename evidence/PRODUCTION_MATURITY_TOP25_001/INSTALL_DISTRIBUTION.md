# PRODUCTION_MATURITY_TOP25_001 — Install / Distribution / Retention

ASOF_LOCAL=2026-11-13  
PROMOTE=0 · CERTIFIED=0 · RELEASE=HELD · NOT_RUN≠PASS

## Purpose

Improve signals that Top-25 recognition care about: **installation**, **documentation**, **distribution**, **retention**, and **competitive performance artifacts** — sealed only with real runs under this pack and `COMPETITIVE_HARNESS_001/`.

## Installation (local-first)

| Path | Status | Notes |
|------|--------|-------|
| Win32IDE local Extensions Install API | WIRED (historical) | `evidence/IDE_PRODUCT_FINISH_BATCH_085/EXTENSION_TOP25_CATALOG.txt` — 25 IDE package formats; `OPTIONAL_CLOUD=OFF` |
| CLI `rawr.exe` (build_ninja) | PRESENT | Used by REAP / quality curve peers; EXE SHA bind per-run |
| Turnkey IDE smoke | RUNNABLE after 2026-11-13 script repair | `pwsh -File scripts/Smoke-IDE-TurnKey.ps1` |
| MinGW historical certs (b061/b062/b136) | UNLAUNCHABLE | Missing `libstdc++-6.dll` — do not ship as install proof |

### Quick install smoke (measured this turn)

```text
pwsh -File scripts/Smoke-IDE-TurnKey.ps1 -SkipAgenticParityScript -SkipUiMarshalling
→ EXIT=1  FAIL chat_copilot_parity_symbols (tool role label color)
→ logs/turnkey_ide_smoke_last.json ok=false  (timestamp 2026-11-13)
```

## Documentation

| Doc | Role |
|-----|------|
| `LAW.txt` (this pack) | Fail-closed authority: PROMOTE=0, no invented % |
| `COMPETITIVE_HARNESS_001/STATUS.txt` | Suite mapping + real exits/scores |
| `docs/REVERSE_ENGINEERING_GAME_DEVELOPMENT.md` | Game-dev guidance — **no harness** (NOT_RUN) |
| `benchmarks/README.md` | TPS suite docs (not re-run this turn under contention) |
| `scripts/QUICK-START-GUIDE.md` | Legacy tooling quick start (paths may be D:\rawrxd) |

## Distribution

- Origin branch target: `feature/ide-agentic-product-path-20261026`
- Ship docs/evidence/scripts progression only when measured; no certification invention.
- Extension catalog remains local-package oriented (VSIX / JetBrains / etc.) — marketplace optional/off.

## Retention signals (honest)

| Signal | State |
|--------|-------|
| Local install path without cloud | CATALOG_WIRED (085) — not re-certified today |
| Smoke harness reaches product checks | YES (after parse repair) — currently FAIL on parity |
| Competitive coding harness launches | YES (SWE null-agent) — SCORE=0.0% ≠ PASS |
| Semantic MiniMax ≤16GiB quality | OPEN (peer QUALITY_CURVE / AL10–14) |
| User retention metrics (DAU/etc.) | NOT_RUN (no telemetry campaign this pack) |

## Competitive performance artifacts

See `COMPETITIVE_HARNESS_001/runs/`:

- `swebench_null_validate.*` — SCORE=0.0% EXIT=0 null agent
- `ide_turnkey_smoke_fixed.*` — EXIT=1 parity fail
- `cert_dll_miss.note.txt` — b061/b062/b136 unlaunchable

## Law

```text
SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS
NOT_RUN != PASS
PROMOTE=0 until PRODUCT_OPEN_PASS && SESSION_ENTER_PASS && GENERATED_TOKENS>0 && TOKEN_COMMIT_PASS
  [+ independent multi-family coverage]
```
