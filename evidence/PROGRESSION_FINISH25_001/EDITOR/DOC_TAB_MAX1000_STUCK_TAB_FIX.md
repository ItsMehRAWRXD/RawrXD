# DOC_TAB_MAX1000_STUCK_TAB_FIX

ASOF_LOCAL=2026-11-09T01:57:51-05:00
TIP_SOURCE=LANDED
- Win32IDE.h: kMaxOpenDocuments=1000
- Win32IDE_lifecycle.cpp: 1000 cap; demote unopenable stuck tabs to Untitled
- Win32IDE_FileOps.cpp: session restore capped at 1000

## Rebuild

SCRIPT=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\rebuild_link_progression.ps1
REBUILD=OK
NOTE=First cmake attempt hit ninja recompact Permission denied; cleared .ninja_log/.ninja_deps and reran same script; NINJA_EXIT=0; elapsed ~91s
STAGE_EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
PROGRESSION_CANDIDATE_SHA=71D1459754830B5987E2291CE2FA43E3A8B6900F27AC1997A8B4D9F7B523CE05
SIZE=2594304
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_LINKED_OPTREF
BINARY_HASH=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\BINARY_HASH.txt
STRING_WITNESS=Invalid Document Tab + stuck-tab Untitled demote + kMaxOpenDocuments=1000 restore cap present in EXE

## Smoke (brief)

HARNESS=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR\smoke_stuck_tab_demote.ps1
LOG=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR\SMOKE_DOC_TAB_MAX1000_STUCK_TAB.txt
SEED=session active=1 path="t8 01 doc" (leaf-only / missing)
MSGBOX_INVALID_DOC_TAB=True
DEMOTE_OBSERVATION=MSGBOX_ONLY
TAB_LABEL_READ=INCONCLUSIVE (empty TCM_GETITEMW reads; process exited -1073740771 after OK)
FINISH25_PASS=NOT_CLAIMED
INVENT_PASS=0

## Authority

PROMOTE=0
CERTIFIED=0
CONTROLLING_FINISH25_SEALS=UNCHANGED
NOT_RUN!=PASS
