T24_PACKAGE_MANIFEST
====================
Package: RawrXD-Win32IDE-Native
Version: finish-25-candidate-20261104-v7
Source Commit: b31eefcb56 (fix/deep2-multimodel-safety-20261025)
Source Branch: fix/deep2-multimodel-safety-20261025
Build Date: 2026-11-04T07:50:00Z

Binary: bin\RawrXD-Win32IDE-Native.exe
Binary SHA-256: 499D43A225EC52635381B9E0C7360ABA8902E8FE9C9E68B49C52577055B8F14C
Binary Size: 1874432 bytes

Build Configuration:
  Compiler: MSVC 19.44.35228 (x64)
  Build System: CMake + Ninja
  Configuration: Release
  Platform: x64 (amd64)
  Target: RawrXD-Win32IDE-Native

Source Changes (vs sealed reference 3B720981):
  T07 - Binary/NUL rejection in loadFileIntoEditor, openFileDialog, openRecentFile
  T08 - addDocumentTab() call in openFileDialog() + tab pointer stability
  T10 - Unconditional armFileSafetyMonitor() on cold launch
  String fixes - SendMessageW for EM_SETCUEBANNER, SendMessageA for EM_REPLACESEL/GETTEXTRANGE/SETTEXTEX/SB_SETTEXT
  String fixes - strcpy_s, null termination after strncpy
  String fixes - TreeView/ListView heap-allocated string pointers freed on delete
  Fix 4 - saveAll() iterates all modified document buffers
  Fix 5 - closeFile() calls removeDocumentTab()
  Fix 7 - Multi-file --open support
  Fix 14 - Sidebar cleanupSidebarStrings() on window destruction
  Fix 15 - RunGit() _popen -> CreateProcess with child process tracking (T05)
  Fix 16 - runInTerminal _popen -> CreateProcess with child process tracking (T05)
  Fix 17 - Remaining EM_SETTEXTEX SendMessage -> SendMessageA (string safety)
  Fix 18 - Sidebar debug variables heap string pointers (LVIF_TEXT stability)
  Fix 19 - VSCodeUI ESP list sequence number heap string pointer
  Fix 20 - cleanupVSCodeUIStrings() called from onDestroy()
  Fix 21 - Agent callback lifetime: shared_ptr<fullOutput> in ExecuteAgentCommand()
  Fix 22 - Multi-document dirty-buffer: hasUnsavedBuffers()/promptSaveAllChanges()
  Fix 23 - Unicode file dialogs: GetOpenFileNameW/GetSaveFileNameW throughout
  Fix 24 - Problems panel wired into production startup (T080)
  Fix 25 - Compiler diagnostic parser: default omitted column to 1 (T080)
  Fix 26 - CLI rawr tools run subcommand
  Fix 27 - CLI --approve-mutations flag support

Gate Status:
  T07=PASS (binary rejection verified, integrity preserved)
  T08=PASS (document tab registration verified via --open)
  T10=PARTIAL (source fix applied; runtime blocked by editor automation limits)
  T17=PASS (File --> Open verified via --open code path, file integrity preserved)
  T15_STANDALONE_TOOL=PASS (editFiles works via rawr.exe tools run)
  T15_AGENT_LOOP=FAIL (Deep2 inference engine layer-12 attention numeric fault - product defect)
  T15_TIMEOUT=PASS (cancel-after-ms terminates process with exit 130)
  T05=PARTIAL_PASS (Request A cancelled cleanly; child process cleanup applied)
  T080=NOT_VERIFIED (Problems panel wired, parser fixed, runtime test pending)
  T18_T19=BLOCKED (requires T05 full pass)
  T24=PACKAGE_PRODUCED
  T25=HELD (independent certification review required)

Controls:
  REBUILD=HELD
  PROMOTE=0
  CERTIFIED=0

Sealed Reference (preserved, not modified):
  SHA-256: 3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
  Path: build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
