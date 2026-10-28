# RECEIPT — WIN32IDE_STUB_SWEEP_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:20:00Z
```

## Verdict

Product-path stub sweep complete. Mode*/SO_*/AD_* remain **GATED fail-closed**
(`GateMode` / `return -1` / `nullptr`). No new linked return-0 fake-success holes
found in those surfaces. HMAC MagBuf leftover dispositioned under
`WATCHDOG_HMAC_PRODUCT_001` (SOURCE_WIRED; RUNTIME_REACHED=NOT_RUN; no relink).

## Confirmed fail-closed

- `GateMode` logs `SYNTHETIC=partial` — no Mode PASS claim
- `AD_ProcessGGUF` / `SO_*` ints → `-1`
- `SO_CreateMemoryArena` → `nullptr`
- batch_010/011 **not** in Win32IDE CMake link

## Source touch this mission

- `unlinked_symbols_batch_005.cpp` get_baseline HMAC wire (S06)
- `win32ide_watchdog_init.cpp` ownership comment

## EXE

| Field | Value |
|-------|-------|
| SHA256 | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Relink | NO |

## Paths

- `evidence/WIN32IDE_STUB_SWEEP_001/LAW.txt`
- `evidence/WIN32IDE_STUB_SWEEP_001/MATRIX.md`
- `evidence/WIN32IDE_STUB_SWEEP_001/RECEIPT.md`
- `evidence/WATCHDOG_HMAC_PRODUCT_001/`
