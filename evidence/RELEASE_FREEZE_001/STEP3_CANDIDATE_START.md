# STEP3_CANDIDATE_START — release/freeze-001

```
ASOF_UTC=2026-11-09T15:15:00Z
PROMOTE=0
CERTIFIED=0
CANDIDATE_SHA=PENDING_NO_BUILD_YET
BASE_GIT=b7db735b7644d4c9df57cef75a6e4c28c590dccf
WORKTREE=F:\rawrxd\.worktrees\release-freeze-001
BRANCH=release/freeze-001
```

## Absorbed tip input (not inherited as PASS)

- tip_cc79_integ_002 EXE SHA256 `F5F4807E…` — OUTPUT_HWND=PASS verified on-disk
- EXACTLY_ONCE remains NOT_VERIFIED until runtime correlation on candidate
- Uncommitted tip Ext/debug sources on dirty `repair/menu-handler-defects` **not** auto-merged this pass (avoid thrash); tracked separately under B3

## Smallest repairs landed (source only)

| ID | Change | Files |
|----|--------|-------|
| H57 | AgentSession TU in Native sources; create+ledger on AgenticBridge Initialize/Execute/Stop | CMakeLists.txt, Win32IDE_AgenticBridge.{h,cpp} |
| EXACTLY_ONCE | reject evidence + disable Send while in-flight; `exactly_once_submit` evidence at request_started | Win32IDE.cpp |
| H21 | WM_DPICHANGED surgical in lifecycle (no full Core link — Core untracked + duplicates lifecycle) | Win32IDE_lifecycle.cpp |

## Explicit non-goals this pass

- Full H01 `Win32IDE_Core.cpp` link (duplicate WindowProc/createWindow)
- Ext CMake absorb / H51 reverify / H42 native-linker
- Build thrash — **build once** when coherent; SHA still PENDING

## Law

```
SOURCE_WIRED ≠ RUNTIME_REACHED
PENDING_NO_BUILD_YET ≠ CANDIDATE_SHA
TIP_F5F4807E ≠ CANDIDATE_PASS
PROMOTE=0
```
