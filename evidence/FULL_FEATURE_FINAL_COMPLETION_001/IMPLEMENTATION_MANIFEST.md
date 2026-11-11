# IMPLEMENTATION_MANIFEST — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:08:00Z
PROMOTE=0
CERTIFIED=0
FINAL_CANDIDATE_SHA256=EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE

## Merged / absorbed (not all on one EXE yet)

| Feature | Implementation | Tip SHA with PASS |
|---------|----------------|-------------------|
| EXT host wire + smoke | ExtHostWire / QuickJS | EA5D tip_final_004 |
| Chat AIM Ctrl+Enter + CJK | CreateWindowExW chat EDIT + harness | EA5D tip_final_004 |
| ConPTY full matrix | Win32TerminalManager DynCreatePseudoConsole + capture fixes | D28128AE tip_terminal_conpty_001 |
| Native debug backend | WaitForDebugEvent harness | 7F8EB407 tip_debug_001 (Debug CRT) |
| Packaging RC stage | tip package + manifest | BD529691 full_feature_rc_001 |

## RelWithDebInfo gap

`build_tip_debug_rel` configured (build.ninja) but `tip_debug_rel_001` not staged this absorb — non-D CRT debug tip still OPEN.

```
SOURCE_IMPLEMENTED != TEST_PASSED
MULTI_TIP_FEATURES != SINGLE_SHA_PRODUCT_PASS
```
