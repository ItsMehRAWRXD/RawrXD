# MATRIX — WIN32IDE_FULL_SOURCE_AUDIT_002

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
ASOF_UTC=2026-10-28T17:00:00Z
NO_INVENT_PASS=1
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
```

Statuses: CLEARED | GATED | BLOCKED | OPEN | NOT_RUN | HISTORICAL_SHA_ONLY | SOURCE_WIRED

## Tip bind + build tree

| ID | Surface | Status | Note |
|----|---------|--------|------|
| T01 | TIP_FREEZE_001 EXE | CLEARED | SHA `748B210A…` verified on disk |
| T02 | link001 candidate pre-fix | GATED | `B421…` = GhostText witness; ≠ tip; ABSORB blocked |
| T03 | TIP_FREEZE_001\bin overwrite | CLEARED | untouched this campaign (hash lock) |
| T04 | Historical freezes | CLEARED | preserved; no rewrite |

## Prior AUDIT_001 rows (rebind)

| ID | Surface | Status | Note |
|----|---------|--------|------|
| A13 | Camellia self_test=-8 | BLOCKED | `CAMELLIA_SELFTEST_RFC_001` |
| A14 | FEATURE_FICTION | GATED | GateFiction×277; fail-closed |
| A22 | PromoteReady emit | OPEN | PROMOTE_READY=0 |
| A26 | K2 full gen | BLOCKED | BLOCKED_OOM |
| A32 | win32app orphans | OPEN | 323 orphans; 294 OPENISH / 29 GATEDISH |
| A33 | IDE perfect | OPEN | OPEN list non-empty |

## Closure-matrix OPEN (tip 748B; countable)

| ID | Gate | Status | Sibling? |
|----|------|--------|----------|
| A02 | Camellia RFC | BLOCKED | no |
| A04 | Agent bridge GUI+headless same SHA | OPEN | partial AgentRunLoop |
| A05 | No fabricated tool success | RUNTIME_PARTIAL | stubs sibling |
| A06 | Safe writes | RUNTIME_REACHED≠MET | partial |
| A07 | Tool approval negatives | RUNTIME_REACHED≠MET | execute_command sibling |
| A08 | Lifecycle safety | OPEN | no |
| A09 | Crash + data-loss recovery | SOURCE_WIRED→OPEN | **this stream**: minidump added to CrashReporter; tip RUNTIME NOT_RUN |
| A10 | CMake-omit legitimacy | OPEN | this audit buckets |
| A11 | K2 full gen | BLOCKED | no |
| A12 | Source inventory | OPEN | refresh landed; PERFECT=0 |
| A13 | Target attribution | OPEN | 885 objs / 323 orphans classified partial |
| A14 | Findings adjudication | OPEN | P0/P1 remain |
| A15 | Promotion | HELD | PROMOTE=0 |
| G02 | AgentRunLoop E2E | OPEN | **SIBLING** |
| G04/G05 | Debug/Auto modes | OPEN | Composer sibling-adjacent |
| G07 | Swarm 1–16 RUNTIME | OPEN | PathB sibling |
| S-005/U06 | ConPTY | SOURCE_WIRED | Composer/ConPTY sibling |
| U03–U18 many | UI polish | OPEN | Phase 7 |
| I02–I11 many | Inference | OPEN/BLOCKED | Phase 3/9 |

## OPEN tally (strict countable; no invent PASS)

| Class | N |
|-------|--:|
| Audit matrix OPEN rows (A04,A08,A09,A10,A12,A13,A14) | **7** |
| BLOCKED (A02,A11) | **2** |
| HELD (A15) | **1** |
| Orphan OPENISH TUs | **294** |
| GateFiction GATED (not OPEN) | **277** |
| Sibling-owned (do not claim close) | AgentRunLoop / execute_command / Composer / stubs |

A09 note: SOURCE_WIRED advanced (minidump in linked CrashReporter). **≠ MET** until tip RUNTIME seal. `rawr_crash_handler.cpp` GATED_OMIT_SUPERSEDED.
