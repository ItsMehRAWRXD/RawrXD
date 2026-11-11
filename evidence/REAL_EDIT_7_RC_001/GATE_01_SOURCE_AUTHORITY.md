# GATE_01 — Source authority

ASOF_UTC=2026-11-03T07:10:00Z
WORKSPACE=F:\rawrxd
GIT_HEAD=dace16621672f3bfff9af5522b839eda4006b266
GIT_HEAD_SUBJECT=fix: harden native editor persistence and IDE commands
CMAKE_TARGET=RawrXD-Win32IDE-Native
BUILD_DIR=F:\rawrxd\build_real_edit7_rc
PROMOTE=0
CERTIFIED=0

## Compiled translation units (RAWRXD_NATIVE_IDE_SOURCES)

Exact list from `F:\rawrxd\CMakeLists.txt` (`set(RAWRXD_NATIVE_IDE_SOURCES ...)`):

1. src/win32app/main_win32.cpp
2. src/win32app/Win32IDE.cpp
3. src/win32app/Win32IDE_Sidebar.cpp
4. src/win32app/Win32IDE_VSCodeUI.cpp
5. src/win32app/Win32IDE_PowerShellPanel.cpp
6. src/win32app/Win32IDE_PowerShell.cpp
7. src/win32app/Win32IDE_Logger.cpp
8. src/win32app/Win32TerminalManager.cpp
9. src/win32app/Win32IDE_FileOps.cpp
10. src/win32app/Win32IDE_Commands.cpp
11. src/win32app/Win32IDE_Debugger.cpp
12. src/win32app/Win32IDE_AgenticBridge.cpp
13. src/win32app/Win32IDE_AgentCommands.cpp
14. src/win32app/Win32IDE_AgentStepTimeline.cpp
15. src/win32app/Win32IDE_Autonomy.cpp
16. src/win32app/Win32IDE_Deep2Bridge.cpp
17. src/win32app/Win32IDE_AgenticLoopBridge.cpp
18. src/win32app/Win32IDE_GhostText.cpp
19. src/win32app/Win32IDE_GhostTextIntegration.cpp
20. src/backend/ollama_client.cpp
21. src/cloud_api_client.cpp
22. src/win32app/Win32IDE_lifecycle.cpp
23. src/win32app/TransparentRenderer.cpp
24. src/gguf_loader.cpp
25. src/GGUFLoader.cpp
26. src/gguf_vocab_resolver.cpp
27. src/streaming_gguf_loader.cpp
28. src/cpu_inference_engine_impl.cpp
29. src/utils/ErrorReporter.cpp
30. src/utils/Diagnostics.cpp
31. (+ generated chat route header; optional VulkanRenderer.cpp when ENABLE_VULKAN=ON)

## Working-tree note at configure time

`git status` showed dirty `src/win32app/Win32IDE.cpp` and `src/win32app/Win32IDE.h`
(chat/Ollama crash-isolation deltas). Those files were included in the RC compile.
Gate 01 records HEAD + TU list; candidate EXE SHA is recorded separately after link.

## Frozen / do-not-overwrite

- KNOWN_FAILING_SHA=3C750E19089BFC1DDC49793425503D6F07FD982E302C8BCB86588AD36A846CC5
  (baseline Dirty/Save FAIL evidence preserved; binary not located under F:\rawrxd at RC time)
- SEAL prod absorb held: `.worktrees\product_seal_clean_a5ae60ef_build\bin\...` SHA prefix CB34EF4E — not rebuilt
- Prior AAC10557 PHYSICAL_ACCEPT 01-06 is a different gate matrix; not copied into this 15-gate RC

## P0 path (source verify)

- EN_CHANGE → `m_fileModified=true` → DocumentBuffer sync → `updateMenuEnableStates()` in
  `Win32IDE_lifecycle.cpp` (editor hwndCtl branch)
- Save As: `saveFileAs()` rejects if `!m_hwndMain || !IsWindow(m_hwndMain)`;
  `ofn.hwndOwner = m_hwndMain`; restores prior path on failed write
- Document save path: `std::ofstream(..., binary|trunc)` — ATOMIC_SAVE=NOT_EQUIVALENT
  (session JSON uses MoveFileEx temp replace; document Save does not)

RESULT=PENDING_SHA_RECORD

NEW_CANDIDATE_SHA=EFC863F906E5DDF72B8DB87B720ADF5FF28DCCEAABDA393F2788B90A83F512CF
RESULT=RECORDED

