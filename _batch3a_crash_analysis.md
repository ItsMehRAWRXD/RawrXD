GATE=BATCH3A_LONG_DURATION_30MIN_001

RUN1: Crashed at 125s (2min), stable 16.7MB before crash, 182 handles, 4 threads
RUN2: Crashed at 245s (4min), stable 19MB for 3min then 1GB spike (19MB→1090MB) then crash

CRASH_PATTERN:
  - Resources stable for 2-3 minutes (no leak)
  - Sudden 1GB working set spike (19MB → 1090MB)
  - CPU spike (2.9s → 29s → 58.7s)
  - Process exits ~1 minute after spike

RESOURCE_COUNTERS_BEFORE_CRASH:
  MAX_WORKING_SET_MB=1090.2
  MAX_PRIVATE_BYTES_MB=743
  MAX_HANDLE_COUNT=214
  HANDLE_GROWTH=7 (stable, not a leak)
  MAX_THREAD_COUNT=5
  THREAD_GROWTH=2 (stable, not a leak)

CRASH_CATEGORY=Unexpected process exit after memory spike
ACCESS_VIOLATION_COUNT=0 (not detected by harness)
STACK_OVERFLOW_COUNT=0 (not detected by harness)
LINGERING_PROCESSES=0 (run 2)

HYPOTHESIS:
  The 1GB spike is consistent with a model loading or large memory mapping.
  No RAWRXD_AGENT_MODEL env var set, no --model flag passed.
  Possible causes:
    1. Background subsystem initialization (auto-feature-registry, MCP bridge)
    2. Deferred Win32 operation triggering large allocation
    3. Workspace scan or indexing operation

VERDICT=FAIL (crash detected, root cause not yet identified)
NEXT_ACTION=Investigate what triggers the 1GB spike at ~3min after launch
