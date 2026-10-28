# WIN32IDE_STUB_SWEEP_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:20:00Z
EXE_SHA256=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
```

| ID | Surface | Linked? | Disposition | Cite |
|----|---------|---------|-------------|------|
| S01 | Mode* GateMode | YES `rawrxd_subsystem_api.cpp` | GATED_FAILCLOSED | B02 |
| S02 | SO_*/AD_* -1/nullptr | YES same TU | GATED_FAILCLOSED | B03 |
| S03 | batch_010/011 Mode/SO/AD | NO CMake omit | GATED_OMIT | LAW_BATCH_009_010_OWNER |
| S04 | batch_005 XOR auth file | NO under MASM=1 | GATED_!RAWR_HAS_MASM | B01 |
| S05 | MagBuf watchdog CRC | YES init+001+005 | CLEARED_JOIN_CRC | B04 |
| S06 | HMAC get_baseline→get_hmac_key | SOURCE_WIRED; EXE not relinked | SOURCE_WIRED_FAILCLOSED / RUNTIME=NOT_RUN | WATCHDOG_HMAC_PRODUCT_001 |
| S07 | RawrXD_Watchdog.asm body | obj~816B END-only | GATED_OMIT_BODY | WATCHDOG_HMAC_PRODUCT_001 |
| S08 | asm_link_stubs / mode_runtime | NO | GATED_OMIT | B06/B07 |
| S09 | batch_017 / sovereign=0 / orch ASM=0 | omit / intentional | GATED | B09–B12 |
| S10 | NEW return-0 fake-success in product Mode/SO/AD | none found | NONE_OPEN | this sweep |

Preserve LIVE_TETRAD_POST_CAMELLIA_001 on SHA `89BFD614…`. No invent PASS on unwired HMAC runtime.
