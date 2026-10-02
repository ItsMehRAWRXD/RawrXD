# BATCH 07 — SECONDARY SYSTEMS
# REPO_WIDE_AUDIT_2026_10_01
#
# AUDITED TREE : F:\~dev\rawrxd   HEAD 9f67682f (dirty tree)
# METHOD        : existence + real byte size + stub classification, per system.

===============================================================================
FINDING B7-001  —  SIX NAMED SECONDARY SYSTEMS DO NOT EXIST AT ALL
===============================================================================
SEVERITY: P0 — UNIMPLEMENTED

MEASURED (file absence verified on disk, not inferred from CMake):

  System                 Expected file                        Status
  ---------------------  -----------------------------------  ------------
  Task system            src/win32app/Win32IDE_Tasks.cpp      ABSENT
  File watcher (IOCP)    src/win32app/IocpFileWatcher.cpp     ABSENT
  File watcher (IDE)     src/win32app/Win32IDE_IOCPFileWatcher.cpp  ABSENT
  Plugin loader          src/plugin_system/win32_plugin_loader.cpp   ABSENT
  VSIX loader            src/modules/vsix_loader_win32.cpp    ABSENT
  VS Code marketplace    src/win32app/VSCodeMarketplaceAPI.cpp ABSENT
  VS Code ext API (IDE)  src/win32app/Win32IDE_VSCodeExtAPI.cpp ABSENT
  SoloIDE entry          src/soloide/UI/SoloIDE.cpp            ABSENT

  src/win32app/ contains 43 .cpp files total (B1-001). Every one of the eight
  files above is referenced by CMakeLists.txt and none is on disk. They are
  part of the 225 dropped from WIN32IDE_SOURCES.

  The extension/plugin surface is therefore entirely absent: no loader, no
  marketplace, no IDE API. src/soloide/ retains only 38-61 byte headers
  (`#pragma once` + a stub banner); every SoloIDE .cpp is absent.

CLASSIFICATION: UNIMPLEMENTED (8 systems, 0 bytes)

===============================================================================
FINDING B7-002  —  SYSTEMS THAT DO EXIST: real code, adoption not yet traced
===============================================================================
SEVERITY: P2 — for census completeness; see Batch 4/3 for reachability

  System             File                              Bytes
  -----------------  --------------------------------  ----------
  Launch configs     src/win32app/launch_config.cpp       13,184
  LSP client         src/win32app/Win32IDE_LSPClient.cpp  13,540
  LSP server         src/win32app/Win32IDE_LSPServer.cpp  10,608
  LSP AI bridge      src/win32app/Win32IDE_LSP_AI_Bridge.cpp 4,926
  Git panel          src/win32app/Win32IDE_GitPanel.cpp   16,353
  Terminal split     src/win32app/Win32IDE_TerminalSplit.cpp 9,146
  MCP                src/win32app/Win32IDE_MCP.cpp        8,798
  MCP hooks          src/win32app/Win32IDE_MCPHooks.cpp  14,618
  CICD settings      src/win32app/CICDSettings.cpp        7,745
  Build runner       src/win32app/Win32IDE_BuildRunner.cpp 6,857
  IDE config header  src/win32app/Win32IDE_Settings.h    3,802
  Watchdog           src/win32app/Win32IDE_Watchdog.cpp   1,194

  None of these is a stub. Reachability from wWinMain is audited in Batch 04
  and is NOT claimed here.

  NOTE on the file watcher: the IDE references a watchdog (1,194 B) that
  exists, but the actual IOCP file-watcher implementation it depends on
  (Win32IDE_IOCPFileWatcher.cpp) does not exist. A watchdog with no file
  watcher to supervise is not a file watcher.

===============================================================================
FINDING B7-003  —  STRAY BUILD ARTIFACTS COMMITTED INTO src/
===============================================================================
SEVERITY: P2 — hygiene / duplicate-source hazard

  File                                          Bytes
  --------------------------------------------  ----------
  src/cli/RawrDumpAuthority.cpp.new                 (duplicate of .cpp)
  src/win32app/Win32IDE_Commands.cpp.old          4,332
  src/win32app/Win32IDE_MCPHooks.cpp.old            48
  src/win32app/Win32IDE_Sidebar.cpp.old           8,260
  src/win32app/AutonomousAgent.cpp.bak               46
  src/deep2/sovereign_q4k_gemv_v2.asm.obj           53
  src/deep2/build/evidence/authority_test.sha256    93
  src/deep2/DEEP2_HEAD.cpp / DEEP2_MINE.cpp / DEEP2_CLEAN.cpp
  src/deep2/SAMPLER_HEAD.cpp / SAMPLER_MINE.cpp

  Two consequences:
   1. `.new`/`.old`/`.bak` copies of real sources sit beside the live files.
      A grep for a symbol can match the dead copy, so "this symbol exists at
      file:line" is not by itself evidence that the live build contains it.
      This audit did not use grep counts alone for any claim.
   2. `.obj` files are committed build output. `sovereign_q4k_gemv_v2.asm.obj`
      at 53 bytes is not a valid object file.

  Recorded because it is a direct source of false evidence in future audits.

CLASSIFICATION: P2 hygiene; contributes to INVALID_MEASUREMENT risk

===============================================================================
BATCH 07 CLOSURE
===============================================================================
STATUS = PARTIAL (measured, with reachability deferred to Batches 03/04)

  SYSTEMS_CHECKED ............................ 16
  ABSENT_ENTIRELY ............................ 8   (task, 2x file watcher,
                                                    plugin loader, VSIX,
                                                    marketplace, VSCode API,
                                                    SoloIDE entry)
  PRESENT_AND_REAL ........................... 12
  STRAY_DUPLICATE_ARTIFACTS .................. 9+