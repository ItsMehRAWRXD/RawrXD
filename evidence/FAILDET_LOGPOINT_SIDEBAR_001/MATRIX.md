# FAILDET_LOGPOINT_SIDEBAR_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T17:08:00Z
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
CANDIDATE_SHA=B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F
ABSORB=NOT_AUTHORIZED
RELINK=NO
NO_INVENT_PASS=1
```

| ID | Surface | Linked tip 748B? | Proof | Disposition |
|----|---------|------------------|-------|-------------|
| T01 | FailureDetector TU | YES | CMake+MAP+strings; `/api/failure/stats` Active HTTP=200; nokey 401 | SOURCE_WIRED + HEADLESS_RUNTIME_REACHED; MET=0 |
| T01b | hookToolResult reject_synthetic | YES (string) | tip+candidate strings FOUND=1 | SOURCE_WIRED A05 consumer; GUI E2E NOT_RUN |
| T02 | LogpointBridge | NO | MAP=0; tip/cand strings ABSENT; CMake omit | GATED_OMIT; RUNTIME=NOT_RUN |
| T02b | native_debugger_conditional_bp | NO | prior omit (SWEEP_002) | OWNER_OMIT |
| T03 | SidebarBridge | NO | MAP=0; tip/cand strings ABSENT; CMake omit | GATED_OMIT+GATED_STUB; RUNTIME=NOT_RUN |
| T03b | Win32IDE_Sidebar.cpp | YES | product owner (not this seal's orphan) | KEEP |

## Runtime scoreboard (tip 748B)

```
SHA_MATCH=1
READY=1
FAILURE_STATS_HTTP=200
FAILURES_HTTP=200
NOKEY_HTTP=401
HEADLESS_FAILDET_ACTIVE=1
PROMOTE=0
```

## Explicit non-claims

SOURCE_WIRED ≠ RUNTIME_REACHED ≠ MET · NOT_RUN ≠ PASS · B421 ≠ tip · ABSORB≠authorized · PROMOTE=0
