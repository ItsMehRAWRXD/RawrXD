P1_PRODUCT_RUNTIME_AUTHORITY_002 — evidence contract (Batch 1 dormant lane)
============================================================================

Batch 1 scope: linked MASM authority + process singleton + fail-closed startup.
Slice 06 USER_PROMPT hook integrated. Stage-chain hooks FORWARD..UI_EMIT wired in source;
P1PRA E2E certification pending physical witness (see E2E_CONTRACT.txt, RECONCLUSION_REGISTER.txt).

Runtime writes machine-readable RUN.log to:

  %RAWRXD_EVIDENCE_ROOT%\P1_PRODUCT_RUNTIME_AUTHORITY_002\RUN.log   (when set)
  <exe_dir>\logs\P1_PRODUCT_RUNTIME_AUTHORITY_002\RUN.log            (fallback)

Enable lane (Win32IDE only; frozen certification targets unchanged):

  cmake -B build_win32ide -G Ninja ^
    -DRAWRXD_BUILD_WIN32IDE=ON ^
    -DRAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY=ON

Build:

  ninja -C build_win32ide RawrXD-Win32IDE

Run with evidence root:

  set RAWRXD_EVIDENCE_ROOT=f:\~dev\rawrxd\evidence
  build_win32ide\bin\RawrXD-Win32IDE.exe

Expected Batch 1 fields in RUN.log:

  P1PRA_SYMBOL_LINKED=1
  P1PRA_STATE_ADDRESS=0x...
  P1PRA_RESET_COUNT=1
  P1PRA_STARTUP_FINALIZE_MASK=0x...   (nonzero — fail-closed)
  P1PRA_FAIL_MASK=0x...
  P1PRA_FINALIZE=0x...
  EXE_PATH=...
  PID=...
  PRODUCT_INFERENCE_AUTHORITY=NOT_CERTIFIED
  P1_PRODUCT_RUNTIME_AUTHORITY_002=FAIL
  RAWRXD_V1_0_0_RC1=HOLD

RC disposition unchanged until end-to-end physical chain passes.
