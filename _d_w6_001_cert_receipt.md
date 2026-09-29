================================================================================
RAWRXD ENGINEERING CERTIFICATION RECORD
================================================================================

PROGRAM:    D_W6_001_Shutdown_Stability
GATE:       D_W6_001_SHUTDOWN_STABILITY
VERSION:    1

STATUS:     PASS

DATE_UTC:   2026-09-29
ENGINEER:   Copilot
BRANCH:     model-correctness
COMMIT:     04b5b84d2
BUILD:      build49 (EXE=20,404,224B, 0 C-errors, 0 LNK4006)

-------------------------------------------------------------------------------
OBJECTIVE
-------------------------------------------------------------------------------

Verify that the D-W6-001 shutdown stack overflow fix (moving Deep2Engine
cleanup from WM_DESTROY to WM_CLOSE) resolves STATUS_STACK_OVERFLOW (0xC00000FD)
across repeated launch→generate→exit cycles.

-------------------------------------------------------------------------------
TEST CONFIGURATION
-------------------------------------------------------------------------------

EXE:        F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe (20.4MB)
MODEL:      F:\models\qwen2.5-coder-1.5b-base.gguf (986MB)
PROMPT:     "hello"
SEED:       1
MAX_TOKENS: 1-2 per run

-------------------------------------------------------------------------------
RESULTS
-------------------------------------------------------------------------------

Run 1:  EXIT=0  PASS
Run 2:  EXIT=0  PASS
Run 3:  EXIT=0  PASS
Run 4:  EXIT=0  PASS
Run 5:  EXIT=0  PASS
Run 6:  EXIT=0  PASS
Run 7:  EXIT=0  PASS
Run 8:  EXIT=0  PASS

TOTAL:  8/8 PASS
FAIL:   0
STATUS_STACK_OVERFLOW: 0

-------------------------------------------------------------------------------
FIX DETAILS
-------------------------------------------------------------------------------

DEFECT:     D-W6-001
ROOT_CAUSE: ~Deep2Engine → ~VulkanCompute::cleanup() (100+ local vars, deep
            destructor chain) was called from WM_DESTROY, which is nested
            inside DestroyWindow's internal teardown. Combined stack depth
            overflowed the default 1MB thread stack.
FIX:        Moved chat engine cleanup (unloadModel + reset) from WM_DESTROY
            to WM_CLOSE, BEFORE DestroyWindow is called. WM_DESTROY now
            only calls PostQuitMessage(0).
COMMIT:     d8e593331

-------------------------------------------------------------------------------
VERDICT
-------------------------------------------------------------------------------

GATE=D_W6_001_SHUTDOWN_STABILITY
VERDICT=PASS
ALL_RUNS_CLEAN_EXIT=1
STATUS_STACK_OVERFLOW=0
TOTAL_RUNS=8
PASSED=8
FAILED=0

W6_INTEGRATION_CERT_001 upgraded from PASS_WITH_DEFECTS to PASS.

SIGNED_OFF: Copilot (2026-09-29)

================================================================================
