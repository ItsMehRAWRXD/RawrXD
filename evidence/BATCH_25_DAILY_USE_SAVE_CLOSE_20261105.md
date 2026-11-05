# Batch 25 — Daily-use IDE save/close safety (2026-11-05)

Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Real native IDE source repairs

Target: `src/win32app/Win32IDE_FileOps.cpp`.

1. `promptSaveAllChanges` previously called `saveAll()` and unconditionally returned true on YES. This could allow close after failed save or cancelled Save As. It now checks for remaining dirty buffers/editor and blocks close with a warning. Commit `14d25d028dd8e8c12e51e292a26a9bb8d040f522`.
2. `saveAll` previously indexed `m_openDocuments[i]` using `m_documentBuffers.size()` without checking the former's size. It now guards the index. Same commit.
3. `saveAll` previously displayed `All files saved` merely because a save was attempted. It now reports success only when no dirty buffers remain, otherwise reports unsaved files. Commit `48a4ed68a240cf8bb0c73bb3d60915ea024e25f6`.
4. `hasUnsavedBuffers` previously ignored `m_fileModified` when an active editor had not yet been registered as a document tab. It now includes active-editor dirty state, and the close prompt no longer bypasses that case. Commit `5ecfd8094c61828ad15d1bdfc64fb6656e803ad9`.

## Executed local simulation

`python /mnt/data/batch25_save_close_simulation.py` exited 0 and produced 15/15 PASS. Scenarios cover clean close, cancel, discard, successful save, failed save, untitled buffer, multiple documents, one failed among several, dirty active editor, failed active save, and truthful status text.

**Evidence boundary:** The 15/15 result is for a Python state-machine simulation of the intended Save/Close behavior. It is NOT a native Win32IDE binary test. The source changes were committed through GitHub connector; a Windows compile or GUI close test has not run.

Local artifacts:
- `/mnt/data/batch25_save_close_simulation.py`
- `/mnt/data/batch25_save_close_simulation.log`

## Highest priority native acceptance still open

Build Win32IDE with MSVC; run physical File->New/Edit/Save As/Cancel/Close, Save All with one failing target, restart/recovery, UTF-8 roundtrip, 10-tab soak, strict A-Stop-B, real model tool calls, production editFiles disk persistence, Deep2 numeric reference and GPU, independent package verification. Never mark production gates PASS based on simulated state transitions.
