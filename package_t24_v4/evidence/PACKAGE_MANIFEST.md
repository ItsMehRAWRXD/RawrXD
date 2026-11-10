T24_PACKAGE_MANIFEST
====================
Package: RawrXD-Win32IDE-Native
Version: finish-25-candidate-20261104-v4
Source Commit: 97d1110854 (fix/deep2-multimodel-safety-20261025)
Source Branch: fix/deep2-multimodel-safety-20261025
Build Date: 2026-11-04T02:59:00Z

Binary: bin\RawrXD-Win32IDE-Native.exe
Binary SHA-256: E254F46AE213A2C6E7A60E02A6625DBF51F413FE52562C1707575D2A2D6F956B
Binary Size: 1834496 bytes

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

Gate Status:
  T07=PASS (binary rejection verified, integrity preserved)
  T08=PASS (document tab registration verified via --open)
  T10=PARTIAL (source fix applied; runtime blocked by editor automation limits)
  T17=PASS (File --> Open verified via --open code path, file integrity preserved)
  T15_STANDALONE_TOOL=PASS (editFiles works via rawr.exe tools run)
  T15_AGENT_LOOP=FAIL (model does not emit editFiles tool calls - model behavior issue)
  T15_TIMEOUT=PASS (cancel-after-ms terminates process with exit 130)
  T05=PARTIAL_PASS (Request A cancelled cleanly; child process cleanup applied)
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
