# AGENTIC_COMPOSER_UX_001 — receipt

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T09:40:00Z
RELINK=NOT_PERFORMED
RUNTIME_REACHED=NOT_RUN
P1=S-004
```

## Authority

Fail-closed bind of Win32IDE Agentic Composer UX to real active local /
ProductOpen session model. MessageBox and `default-model` refused as success.

| Field | Value |
|-------|-------|
| Handler TU | `src/win32app/Win32IDE_AgenticComposerUX.cpp` |
| SOURCE_SHA256 | `51CCC551425FB741CFD9F954C8DF1D85B46519ED9514042F299C0B0B2F8AC2CE` |
| Model owners | `Win32IDE::getLoadedModelPath`, `rawr::ProductSessionOpen` + `RAWRXD_PRODUCT_MODEL` |
| UX orchestrator | `RawrXD::Agentic::AgenticComposerUX` |
| Status surface | `appendToOutput` / `ShowError` (not MessageBox) |

## Sealed tetrad (untouched)

| Item | Value |
|------|-------|
| Cite | `LIVE_TETRAD_POST_CAMELLIA_001` |
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| PROMOTE | 0 |
| Tip relink | NOT_PERFORMED — no SHA invalidate this seal |

## Source edits (SOURCE_WIRED only)

| ID | Change | Disposition |
|----|--------|-------------|
| C01 | Real model resolve; ban default-model | SOURCE_WIRED |
| C02 | Empty model FAIL_CLOSED; no StartSession | SOURCE_WIRED |
| C03 | Remove MessageBox success | SOURCE_WIRED |
| C04 | Host pointer + null-check for static callbacks | SOURCE_WIRED / residual in LAW |

## Explicit non-claims

- No PERFORMANCE_PASS
- No TOKEN_SURVIVED
- No RUNTIME_REACHED (RELINK required)
- No invent PASS
- No tip EXE SHA rewrite
