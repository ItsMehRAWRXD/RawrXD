T24_PACKAGE_MANIFEST
====================
Package: RawrXD-Win32IDE-Native
Version: finish-25-candidate-20261103-v2
Source Commit: 9de45928fe (fix/deep2-multimodel-safety-20261025)
Source Branch: fix/deep2-multimodel-safety-20261025
Build Date: 2026-11-03T19:47:00Z

Binary: bin\RawrXD-Win32IDE-Native.exe
Binary SHA-256: E71DEBB220FD07F0D6F2C6F416DD0DBF437BBAB8F5ECDB59C50237BF7E411323
Binary Size: 1831424 bytes

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
  String fixes - SendMessageW for EM_SETCUEBANNER, SendMessageA for EM_REPLACESEL/GETTEXTRANGE/SETTEXTEX
  String fixes - strcpy_s, SB_SETTEXTA, null termination after strncpy
  String fixes - TreeView/ListView heap-allocated string pointers freed on delete
  Fix 4 - saveAll() iterates all modified document buffers
  Fix 5 - closeFile() calls removeDocumentTab()
  Fix 7 - Multi-file --open support
  Fix 14 - Sidebar cleanupSidebarStrings() on window destruction

Gate Status:
  T07=PASS (binary rejection verified, integrity preserved)
  T08=PASS (document tab registration verified via --open)
  T10=PARTIAL (source fix applied; runtime blocked by editor automation limits)
  T17=PASS (File --> Open verified via --open code path, file integrity preserved)
  T15_STANDALONE_TOOL=PASS (editFiles works via rawr.exe tools run)
  T15_AGENT_LOOP=FAIL (model does not emit editFiles tool calls - model behavior issue)
  T15_TIMEOUT=PASS (cancel-after-ms terminates process with exit 130)
  T05=PARTIAL_PASS (Request A cancelled cleanly; Request B model didn't emit tool call)
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
