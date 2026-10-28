# RECEIPT — WIN32IDE_FULL_SOURCE_AUDIT_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PERFECT=0
WORKSPACE=G:\~dev\rawrxd
MOTD_ACK=1
ASOF_UTC=2026-10-28T09:20:00Z
RELINK=NO
NO_INVENT_PASS=1
POST_GATE=COMMAND_HANDLERS_FICTION_GATE_001
```

## Verdict

Full source inventory + gap audit completed fail-closed. Current EXE SHA
matches `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F`.
IDE is not perfect: OPEN list non-empty; many seals remain HISTORICAL_SHA_ONLY
(`89BFD614…` / `D121659F…`). No PROMOTE/CERTIFIED invented.
A14 FEATURE_FICTION dispositioned GATED by `COMMAND_HANDLERS_FICTION_GATE_001`
(RELINK=NO).

## Counts (return)

| Scope | Metric | N |
|-------|--------|--:|
| src/ | cpp | 5585 |
| src/ | c | 192 |
| src/ | h | 1762 |
| src/ | hpp | 2754 |
| src/ | asm | 1328 |
| src/ | sum those exts | 11621 |
| src/ | all files | 15089 |
| win32app/ | cpp | 524 |
| win32app/ | h / hpp / asm | 140 / 43 / 10 |
| win32app/ | cpp+c+asm | 534 |
| CMake | WIN32IDE_SOURCES net | **806** |
| CMake | win32app linked | **203** |
| CMake | win32app orphan/omit | **332** |

## EXE

| Field | Value |
|-------|-------|
| Path | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| Size | 331634176 |
| SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| Match | **1** |

## Seals vs CURRENT EXE

| SHA | Role |
|-----|------|
| `866E9D1B…` | CURRENT — HMAC absorb, live tetrad post-HMAC, TOKEN64_003, MULTI_FAMILY_002, K2_002 BLOCKED_OOM, PromoteReady tip, fiction gate hold |
| `D121659F…` | HISTORICAL_SHA_ONLY — post-relink tetrad, TOKEN64_002 |
| `89BFD614…` | HISTORICAL_SHA_ONLY — post-Camellia tetrad, K2_001, Headless tools, bridge/stub sweeps, MULTI_FAMILY_001 |
| `32C28BF7…` | historical note only — AGENTIC_CAMELLIA_STUB_GATE ondisk drift |

## Linked stub scan summary

- Fake-success empty `return true` in Mode/SO/AD/Camellia/HMAC paths: none found
- XOR: `src/core/unlinked_symbols_batch_005.cpp:182` / `:186` gated `#if !RAWR_HAS_MASM`
- FEATURE_FICTION: **GATED** — `COMMAND_HANDLERS_FICTION_GATE_001` GateFiction×276 (`GATED_FICTION_EXPLICIT`); was OPEN A14
- GateStub in linked net: 0
- crypto_stubs.cpp: not linked

## Prioritized OPEN backlog (paths)

1. Camellia self_test=-8 — `evidence/CAMELLIA_SELFTEST_RFC_001/` (BLOCKED_DOCUMENTED; still OPEN vs RFC)
2. PROMOTE_READY=0 / R28 HELD / TIP_CLIMB HOLD / Inference SPLIT HOLD — `evidence/PROMOTE_READY_CONJUNCTION_001/`
3. `evidence/K2_FULL_PRODUCT_GEN_002/` — BLOCKED_OOM on CURRENT `866E9D1B…` (weights 44152MB > host 37099MB; no smaller on-disk quant); prior `K2_FULL_PRODUCT_GEN_001` HISTORICAL `89BFD614…`
4. win32app orphans among 332 — disposition product-intent vs keep GATED_OMIT
5. Re-bind claimed RUNTIME for seals still on `89BFD614…` / `D121659F…`

## Post-gate note (COMMAND_HANDLERS_FICTION_GATE_001)

A14 cleared OPEN→GATED without tip relink. Strict OPEN rows remaining: **A22**, **A33** (+ A32 partial). `PERFECT=0` still (OPEN non-empty).

## Explicit non-claims

```
PERFECT=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
OPEN_LIST_EMPTY=0
NOT_RUN != PASS
HISTORICAL_SHA_ONLY != CURRENT_COVER
```

## Artifacts

- `evidence/WIN32IDE_FULL_SOURCE_AUDIT_001/LAW.txt`
- `evidence/WIN32IDE_FULL_SOURCE_AUDIT_001/RECEIPT.md`
- `evidence/WIN32IDE_FULL_SOURCE_AUDIT_001/MATRIX.md`
- `evidence/WIN32IDE_FULL_SOURCE_AUDIT_001/INVENTORY.md`
- `evidence/COMMAND_HANDLERS_FICTION_GATE_001/`
