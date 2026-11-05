# Batch 26 — Native IDE Save All daily-use reliability

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Actual native IDE source repairs

File: `src/win32app/Win32IDE_FileOps.cpp`.

- `bd4a810a2832b963cb194c77749cdfb94d3eef21`: Save All no longer excludes dirty untitled tabs merely because `m_openDocuments[i]` is empty; it attempts `saveFile()` for modified tabs and active editor, restoring the originally selected tab after the loop.
- `f23406e3eb5f095e2f240e1e6440c1b2a415a8a9`: stop Save All on the first failed or cancelled save; avoid continuing to mutate later files after failure.

## Executed tests and scope

1. Local Python behavioral simulation of intended Save All state machine: **15/15 PASS**. Scenarios: clean file, named/untitled save, cancelled Save As, failed save, two/three dirty tabs, nonactive failure, active failure, no writes after failure, status correctness and tab restoration. File `/mnt/data/batch26_save_all_simulation.log`.
2. GitHub source/static checks: **9/9 PASS**. Checked real branch text for bool saveFile declaration, untitled tab semantics, loop predicates, no empty-path skip, fail-fast, active restoration, active dirty save, close protection and status predicate.

**Important:** Python simulation is independent of the Win32IDE source and is NOT a product binary or native GUI test. Source assertions check the committed source text but do not compile or execute it. Neither constitutes a native acceptance PASS.

## Native Windows gates still unverified

Compile with MSVC, exercise real untitled Save As and cancel, verify exact file bytes, verify failed disk write blocks close, multi-tab switching and restoration, Unicode save/reopen, restart recovery, build/run, local model, production agent tool write/readback, strict cancellation, soak, packaging and independent certification. The 15 daily-use acceptance gates remain open pending native evidence.
