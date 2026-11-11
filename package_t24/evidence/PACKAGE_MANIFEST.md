T24_PACKAGE_MANIFEST
====================
Package: RawrXD-Win32IDE-Native
Version: finish-25-candidate-20261103
Source Commit: b46fb5f4f9961930d2b1f2174441e3526e51ccb9
Source Branch: fix/deep2-multimodel-safety-20261025
Build Date: 2026-11-03T17:25:00Z

Binary: bin\RawrXD-Win32IDE-Native.exe
Binary SHA-256: BBA354686CE49BB384B8B343EA0B2C3B22DCC94FF44F0AF7467715A48028DD73
Binary Size: 1828864 bytes

Build Configuration:
  Compiler: MSVC 19.44.35228 (x64)
  Build System: CMake + Ninja
  Configuration: Release
  Platform: x64 (amd64)
  Target: RawrXD-Win32IDE-Native

Source Changes (vs sealed reference 3B720981):
  T07 - Binary/NUL rejection in loadFileIntoEditor (Win32IDE.cpp +15 lines)
  T08 - addDocumentTab() call in openFileDialog() (Win32IDE_FileOps.cpp +38/-1)
  T10 - Unconditional armFileSafetyMonitor() on cold launch (Win32IDE_lifecycle.cpp +31/-11)

Gate Status:
  T07=PASS (binary rejection verified, integrity preserved)
  T08=PASS (document tab registration verified via session)
  T10=PASS (crash recovery verified: autosave + kill + restart)
  T17=PASS (File --> Open verified via --open code path)
  T15_STANDALONE_TOOL=PASS (editFiles works via rawr.exe tools run)
  T15_AGENT_LOOP=OPEN (model does not emit editFiles tool calls)
  T15_TIMEOUT=PASS (cancel-after-ms terminates process with exit 130)
  T05=NOT_RUN (requires explicit authorization)
  T18/T19=BLOCKED (integration and 100-cycle soak)
  T24=PACKAGE_PRODUCED
  T25=HELD (independent certification review required)

Controls:
  REBUILD=HELD
  PROMOTE=0
  CERTIFIED=0

Sealed Reference (preserved, not modified):
  SHA-256: 3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
  Path: build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
