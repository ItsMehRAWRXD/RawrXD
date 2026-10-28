# SHELL_LAYOUT_PHASE5_001 — matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:25:00Z
EXE_RELINK=0
```

| ID | Surface | Evidence / cite | Disposition |
|----|---------|-----------------|-------------|
| P0 | Shell phase 0 frame-only | `P1_UI_SHELL_LAYOUT_001/PHASE_00.txt` | PASS (frozen) |
| P1 | Shell phase 1 activity | `P1_UI_SHELL_LAYOUT_001/PHASE_01.txt` | PASS (frozen) |
| P2 | Shell phase 2 +sidebar | `P1_UI_SHELL_LAYOUT_001/PHASE_02.txt` | PASS (frozen) |
| P3 | Shell phase 3 +editor | `P1_UI_SHELL_LAYOUT_001/PHASE_03.txt` | PASS (frozen) |
| P4 | Shell phase 4 +status | `P1_UI_SHELL_LAYOUT_001/PHASE_04.txt` | PASS (frozen) |
| P5 | Terminal chrome geometry in `LayoutIDE` | `Win32IDE_ShellLayout.cpp` empty body after `phase < 5` | GATED_UNIMPLEMENTED |
| P5E | Product claim PASS on PHASE=5 | LAW forbids | FORBIDDEN |
| P5S | Silent-skip PHASE=5 in cert packets | LAW forbids | FORBIDDEN |
| P6 | Full spatial legacy | `P1_UI_SHELL_LAYOUT_001/GATE.txt` | NOT_RUN |
| W1 | `Win32IDE_Window.cpp::createWindow` second shell | orphan TU; Core owns CreateWindowEx | GATED_INTENTIONAL_DUAL_PATH_REFUSE |
| W2 | Window ownership runtime | `P1_UI_WINDOW_OWNERSHIP_001` | RUNTIME_OWNERSHIP=PASS; OVERALL=FAIL (`/FORCE:MULTIPLE`) — separate gate |

## PhaseFromEnvironment / restrict

| Predicate | Value |
|-----------|-------|
| env | `RAWRXD_SHELL_LAYOUT_PHASE` |
| default | 3 |
| rebuild | `RAWRXD_SHELL_LAYOUT_REBUILD` |
| `RebuildRestrictActive` | rebuild && phase ∈ [0,4] |
| phase 5 in CBT allow-list | NO |
| `UseLegacySpatial(5)` | false |
| Core `LayoutIDE` path at 5 | YES (rebuild && !legacy) → hits gated stub |

## Fail-closed reminder

`GATED_UNIMPLEMENTED != PASS`. No invented terminal PASS. No PROMOTE.
