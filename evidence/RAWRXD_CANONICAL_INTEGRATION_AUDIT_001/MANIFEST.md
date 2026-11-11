# RAWRXD_CANONICAL_INTEGRATION_AUDIT_001

PROMOTE=0. TIP_CLIMB=HOLD. No checkout was reset, cleaned, merged, cherry-picked, pushed, deleted, or overwritten. Stub fallback was not enabled. Source presence is not a PASS.

## Checkout identity

| Path | Git | HEAD | Dirty |
| --- | --- | --- | --- |
| `F:\rawrxd` | branch `fix/deep2-multimodel-safety-20261025` | `a7b14a9f8c61c239c3834b1028274a1060170b92` | 10987 porcelain lines, 10977 untracked, 0 staged |
| `F:\~dev\rawrxd` | no `.git` | none | unversioned tree, directory mtime 2026-10-13 |
| `G:\~dev\rawrxd-cmake-clean` | detached | `fd27fd184e39c73da5a1f49cdb9bb32a5d7a44f6` | 14 porcelain lines; agent files are dirty and are not in HEAD |
| `G:\VSC0de` | detached | `1c3a108b5d45cf98d301966be0dab087f41049b7` | 14682 porcelain lines, 14674 untracked |
| `G:\~dev\rawrxd` | `feature/ide-agentic-product-path-20261026` | `530399a834abc9794b2ef0f8a733319594204385` | 2109 untracked; agent session files are in HEAD |

`G:\~dev\rawrxd` and `G:\~dev\rawrxd-cmake-clean` are worktrees of one repository. `F:\rawrxd` does not contain objects `530399a834ab` or `fd27fd184e39`, and it has no local ref for `feature/ide-agentic-product-path-20261026`. Ancestry between the canonical F: HEAD and the agentic branch is not established in either object database.

`fd27fd184e39` is an ancestor of `530399a834ab`. The six commits after it are the reference-link receipt, the session journal, the rewrite/drain fix, the headless session proof, the Win32 review window, and the UI_003 window proof.

## Untracked prefix counts

`F:\rawrxd` (first path component): build_ide 2197, build_reap 2185, build_crashfix_verify 2175, build_daily_verify 2174, kartgib_work 1759, evidence 70, tmp_build 35, WorldForge_Drop5 33, WorldForge_Drop4 26, WorldForge_Drop3 24, agent_e2e_fixture 16, kartgib 15.

`G:\VSC0de`: Deep2Engine 9014, e646868227 3129, 110a328ea5 2278, src 144, certification 42, ipa_sign_service 15, policies 15, tools 7, assets 6, agent_test_ws 4, docs 2, .cursor 2.

`G:\~dev\rawrxd`: evidence 2018, src 31, plus incoming dump directories. All 31 `src` paths are under `src/voxel/`. They are not in HEAD.

`G:\~dev\rawrxd-cmake-clean` porcelain, preserved as-is:

```
MM CMakeLists.txt
M  src/win32app/AgentHttp.cpp
M  src/win32app/AgentRunLoop.cpp
A  src/win32app/AgentSession.cpp
AM src/win32app/AgentSession.hpp
A  src/win32app/AgentSessionKill.cpp
A  src/win32app/AgentSessionProof.cpp
A  src/win32app/AgentSessionRestore.cpp
MM src/win32app/AgentToolExec.cpp
MM src/win32app/AgentToolShell.cpp
 M src/win32app/Win32IDE.cpp
MM src/win32app/main_win32.cpp
?? src/win32app/AgentSessionBar.cpp
?? src/win32app/AgentSessionGuiProof.cpp
```

## Stub

Only `F:\~dev\rawrxd\cmake\empty_target_stub.cpp` exists. The production target that fails the no-stubs gate is `RawrXD-Win32IDE`. `CMakeLists.txt` lines 8807-8808 pass that file to `add_executable` after the `WIN32IDE_SOURCES` filter, so the filter never removes it. `EnforceNoStubs(RawrXD-Win32IDE)` then matches `*_stub.cpp`.

The translation unit defines `RawrXD_EmptyTargetStub::anchor` and nothing else references that symbol. Fourteen other targets in the same file also list the stub. The configure error names `RawrXD-Win32IDE`. The bench targets are `EXCLUDE_FROM_ALL`.

The same path is absent from `F:\rawrxd`, both G: RawrXD worktrees, and `G:\VSC0de`.

## Agent session comparison

These files are in `G:\~dev\rawrxd` HEAD and are byte-identical in the cmake-clean worktree. They are absent from `F:\rawrxd`, `F:\~dev\rawrxd`, and `G:\VSC0de`.

| File | SHA-256 prefix | Bytes |
| --- | --- | --- |
| AgentSession.cpp | EFDA62F8AD0FD5B1 | 4159 |
| AgentSessionBar.cpp | 30E8B1282103524D | 3901 |
| AgentSessionGuiProof.cpp | B7C7E375C4EF8B0A | 2489 |
| AgentHttp.cpp | ACCB89E72E35C9C7 | 3946 |
| AgentRunLoop.cpp | AED7B0D3B5A737EA | 1320 |

`Win32IDE_LocalServer.cpp` is the conflict to refuse a blind copy: `F:\~dev\rawrxd` has a 459-byte graph-restoration unit that exports no symbol. Both G: worktrees have a 217490-byte file, SHA-256 prefix `67E69710719AEB94`. `F:\rawrxd` does not have the file.

UI_003 and Build 003 were not re-run. Their published receipts stay on the G: branch. They are not F: runtime results. Ask, Plan, Debug, full IDE shell, complete agent workflow, and 16-model orchestration remain NOT_RUN.

## Ranked integration sequence

1. Keep every dirty tree. Do not discard the cmake-clean overlay. The committed copy of those agent bytes already exists at `530399a834ab` on `G:\~dev\rawrxd`.
2. Treat `F:\rawrxd` as the destination checkout and `530399a834ab` as the agent-session source. Do not start from `F:\~dev\rawrxd`. That tree is unversioned, its local server unit is hollow, and its IDE target links the stub.
3. On a new integration branch created from `F:\rawrxd` only after an explicit request, bring the agent session, journal, review, stop, and restore sources from `530399a834ab`. Do not copy `F:\~dev\rawrxd\src\win32app\Win32IDE_LocalServer.cpp` over the G: implementation.
4. Leave KartGib, `kartgib_work`, and the WorldForge drop directories on F: untouched. Leave `G:\~dev\rawrxd\src\voxel` untracked and out of the IDE target. Leave `G:\VSC0de` as its own detached checkout.
5. For the strict configure on whichever tree is actually built, delete the `cmake/empty_target_stub.cpp` argument from `add_executable(RawrXD-Win32IDE ...)` only. Keep `RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK` OFF. Do not set `RAWRXD_EMERGENCY_STUB_LINK`. Reconfigure and record the first real missing symbol. That configure has not been run.
6. Link, then launch one process. Record the absolute path and SHA-256 from the live process. Open one known source file. Then run one agent request through the GUI and record file changes, terminal output, Stop, and Restore.
7. Promotion stays 0 until that F: executable passes the workflow above. Isolated G: proofs do not transfer.

## Acceptance tests still NOT_RUN

- Strict configure of a Win32IDE target whose SOURCES list does not contain `empty_target_stub.cpp`
- Compile and link of that target
- One F: process, live path, and SHA-256
- GUI open of a known nonempty source file with visible text
- One agent request, diff review, Stop, and Restore on that same process
- Agentic E2E and multi-model execution
