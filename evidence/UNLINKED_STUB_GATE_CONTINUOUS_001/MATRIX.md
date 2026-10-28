# UNLINKED_STUB_GATE_CONTINUOUS_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
TIP_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
ASOF_UTC=2026-10-28T17:24:00Z
RELINK=NOT_RUN
OBJECT_SMOKE=PASS
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
```

## GATED this continuous sweep

| ID | Surface | Linked Win32IDE? | Disposition | Notes |
|----|---------|------------------|-------------|-------|
| U01 | Deep2APIServer Init/Start | YES batch_022 | **GATED_FAILCLOSED** | was return true |
| U02 | ProductionAPIServer init/start | YES batch_022 | **GATED_FAILCLOSED** | was true + running flag |
| U03 | CompressionEngine::initialize | YES batch_022 | **GATED_FAILCLOSED** | was return true |
| U04 | SetCompletionBackendNative | YES batch_021 | **SOURCE_WIRED_PTR** | bool; absorb NOT_AUTH |
| U05 | AgentCoordinator C API | YES batch_021 | **GATED_FAILCLOSED** | ABI→Ship header; Create null |
| U06 | BraidedLoader_Init(const char*) | YES orphan | **GATED_FAILCLOSED** | real 2-arg in .c |
| U07 | ValidateDMAAlignment | YES batch_015 | **GATED_FAILCLOSED** | ~0ull |
| U08 | asm_link_stubs.cpp | NO | **GATED_OMIT** | B06 #error |

**GATED_COUNT (this seal rows U01–U08) = 8**

## Prior GATED (cited, not re-opened)

| ID | Surface | Disposition | Cite |
|----|---------|-------------|------|
| P01 | Mode* GateMode | GATED_FAILCLOSED | STUB_SWEEP / B02 |
| P02 | SO_*/AD_* -1/nullptr | GATED_FAILCLOSED | STUB_SWEEP / B03 |
| P03 | batch_010/011/017/018/019/020 | GATED_OMIT | CMake COMMENT |
| P04 | subsystem_mode_runtime | GATED_OMIT | B07 |

## Still OPEN (honest)

| ID | Surface | Why OPEN |
|----|---------|----------|
| O01 | Real AgentCoordinator body | Ship/*.cpp empty; Full Source not linked |
| O02 | Deep2APIServer HTTP listen/bind | APIServer helper exists; class methods fail-closed |
| O03 | ProductionAPIServer serverImpl | no Crow/HTTP owner |
| O04 | CompressionEngine compress/decompress | initialize gated; bodies absent |
| O05 | GhostText product absorb | NOT_AUTHORIZED (needs exact user auth) |
| O06 | Product RELINK candidate SHA | concurrent ninja lock; tip stay 748B |
| O07 | batch_009 hwsynth SYNTHETIC=partial | prior sweep note; not return-0 theater |
| O08 | Watchdog HMAC runtime on tip | SOURCE_WIRED prior; RUNTIME=NOT_RUN |

**STILL_OPEN = 8** (O01–O08)

```
SOURCE_WIRED (obj smoke + source edits) != RUNTIME_REACHED (tip 748B)
NOT_RUN != PASS
PROMOTE=0
```
