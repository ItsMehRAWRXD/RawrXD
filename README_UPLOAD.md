# Computer-Use upload slice (2026-11-10)

This orphan branch contains **only** the computer-use source/integration trees from local tip:

`18d4c3f98e8c15f6362bbcb7389a7c82eef970af` (computer-use 14/14 on `evidence/oneshot-upload-20261109`).

## Why orphan?

Pushing the full tip/branch to `ItsMehRAWRXD/RawrXD` fails GitHub pre-receive **GH008** (unknown/missing Git LFS objects / LFS budget). `GIT_LFS_SKIP_PUSH=1` does not bypass that check.

This branch commits the listed paths as **regular Git blobs** (no `.gitattributes` LFS filters) so the computer-use delta can land without the historical LFS payload.

## Included paths

- `src/computer_use/**`
- `src/win32app/Win32IDE_ComputerUse.cpp`
- `src/win32app/Win32IDE.h`
- `src/win32app/Win32IDE_AgentCommands.cpp`
- `src/win32app/Win32IDE_VSCodeUI.cpp`
- `src/agentic/tool_core.hpp`
- `CMakeLists.txt`
- `third_party/computer_use_src/**`
- `evidence/IDE_RELEASE_READINESS_001/computer_use_001/**` (text receipts; `build_src` ninja artifacts omitted)

## Not included

Full repo history, LFS-tracked binaries/archives, and the 4DE0 package.
