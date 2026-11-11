P1_NON_AUTHORITY_EDITS
======================
status=OUTSIDE_CERTIFIED_P1
frozen_sha=D7BD2FFBD23BDFD6DDE2553F05BD1CD7ED38998555D3784603534496F7B24091
promote_tip_at_capture=4e338bb8a (docs quarantine) / working tree restored to HEAD for listed files
policy=Do not fold into P1 before smoke PASS. If smoke FAIL and a hunk directly fixes the observed failure, fold only that minimal fix, rebuild, NEW SHA.

PATCHES
-------
evidence/p1_non_authority/UNCOMMITTED_OUTSIDE_P1.patch
  - src/win32app/Win32IDE_HexMag.cpp
  - src/win32app/Win32IDE.h
  - src/deep2/sovereign_moe_fused.asm

evidence/p1_non_authority/UNCOMMITTED_CREATEWINDOW_DIAG.patch
  - src/win32app/Win32IDE_Core.cpp  (ReManifest createWindow ladder — NOT in frozen EXE)
  - src/win32app/main_win32.cpp     (SEH gate reporting — NOT in frozen EXE)

NOTE
----
CREATEWINDOW_DIAG was WIP localization instrumentation discovered during smoke S1.
It was never part of SHA D7BD2FFB… and has been restored out of the working tree.
