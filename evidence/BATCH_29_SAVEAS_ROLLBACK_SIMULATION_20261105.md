# Batch 29 — Save As rollback and local acceptance (2026-11-05)

Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Production source defect fixed

`src/win32app/Win32IDE.cpp` / `Win32IDE::saveFileAs()` restored `m_currentFile` after failed Save As but did not restore `m_currentDirectory` when the original filename was empty. The original directory is now captured and restored on save failure. Commit `eb3fa6ed0e35bd70abcb7ce471a0d0f4c7de75ac`.

## Actual local test execution

Compiled and ran a standalone C++20 Save As state simulation using GCC `-Wall -Wextra -Werror -fsanitize=undefined -fno-omit-frame-pointer`. Exit code 0, **15/15 PASS**.

Cases: 01 untitled save; 02 exact disk readback; 03 clear dirty after success; 04 filename update; 05 directory update; 06 cancel; 07 cancel state preserved; 08 cancel dirty and disk preserved; 09 injected failure; 10 failure restores filename/directory; 11 failure preserves dirty; 12 nonexistent parent; 13 missing parent restores state; 14 successful retry; 15 retry exact disk readback and clean state.

Test source: `/mnt/data/batch29_saveas_state_smoke.cpp` (local conversation artifact, not repository source).
Test log: `/mnt/data/batch29_saveas_state_smoke.log` (local conversation artifact).

## Important limitations

This local executable simulates the intended state transitions and performs real temporary disk IO, but does **not** compile or call `Win32IDE::saveFileAs`, `GetSaveFileNameW`, `MoveFileExW`, or any Windows GUI control. It does not prove the native IDE's Save As path works.

Native Windows compilation, GUI Save As/Cancel/Retry, long path, file-sharing conflict, ACL/metadata preservation, autosave/session recovery, Build/Run, agent production editFiles and Deep2 numeric correctness remain OPEN.

No native gate has been marked PASS and no promotion is authorized.
