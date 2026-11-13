# Top-25 recognition gap board (fail-closed)

**ASOF:** 2026-11-13 · **PROMOTE=0** · **CERTIFIED=0** · **RELEASE=HELD**  
**Witness:** `MEASURE.txt` · **Law:** `LAW.txt` · **Parent:** `../SCOREBOARD.md`

Axis status vocabulary: `ABSENT` | `DRAFT` | `MISMATCH` | `MEASURED_OPEN` | `RUNTIME_REACHED` | `PASS`  
`NOT_RUN != PASS`. Feature checklists ≠ production %.

| Axis | Bar (Top-25 ops) | Measured state | Gap / next executable |
|------|------------------|----------------|------------------------|
| INSTALLATION | One-command install OR documented local build that runs | Local `rawr.exe` **RUNTIME_REACHED** (`build_clean`); package install **ABSENT** (winget no hit; SHA placeholders) | Ship signed artifact + SHA; keep local path as authority until then |
| DOCUMENTATION | First-run docs match real CLI + real release assets | Pre-fix docs **MISMATCH** (rawrxd.exe / MSI / deb / docker pull invents) | Honest LOCAL_INSTALL + INSTALL banner; package paths marked NOT_PUBLISHED |
| DISTRIBUTION | winget/choco/brew/apt live with checksums | Manifests **DRAFT**; `PLACEHOLDER_SHA256`×3; claimed MSI **ABSENT** on `v1.0.0` | Bind SHA to real zip/MSI; publish only after bind; apt/yum scripts unproven |
| USER_RETENTION | D1/D7/D30 or onboarding funnel measured | **NOT_RUN** / schema was ABSENT | Land schema + optional local event log; no invented cohort PASS |
| COMPETITIVE_PERFORMANCE | Measured vs peers / production semantic | Parent SCOREBOARD: CLI/GUI **Not certified**; MiniMax STREAM **NOT_PASS** | Continue numeric/semantic gates outside this pack; no MiniMax FULL here |
| TOP25_PARITY (rollup) | Conjunction of axes | **MEASURED_PARTIAL** (ops audited; not certified) | Close publish+doc match+retention measure+competitive cert |

## Highest-leverage landings (this turn)

1. Evidence pack + gap board + STATUS (this directory).
2. `distribution/README.md` + manifest `NOT_PUBLISHED` banners.
3. Honest `docs/guides/LOCAL_INSTALL.md` + INSTALL/GETTING_STARTED fail-closed headers.
4. Retention schema `RETENTION_METRICS.schema.json` with `STATUS=NOT_RUN`.
5. Parent SCOREBOARD `TOP25_PARITY` → MEASURED_PARTIAL (ops).

## Explicit non-goals this pack

- MiniMax FULL loads / REAP 16GB matrix reruns.
- Inventing published package-manager listings.
- Claiming CERTIFIED/PROMOTE from docs alone.
