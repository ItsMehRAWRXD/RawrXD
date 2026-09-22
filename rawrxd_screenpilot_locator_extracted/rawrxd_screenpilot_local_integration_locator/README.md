# ScreenPilot local integration locator

This package is intentionally non-destructive. It does not modify the repository.

It exists because the public/default GitHub tree names `Win32IDE_LocalServer.cpp`,
`tool_server.cpp`, and `RawrXD_AgentLoop.cpp` in comments/CMake references, but
the actual files were not present in the inspected `main`/PR #15 tree.

Run `locate_screenpilot_server.ps1` against the real local `F:\~dev` tree first.
The result tells the coding agent where the shipping listener actually lives and
also flags the authority-lifetime and Win32 agent-loop stubs found during the
connected-repository audit.
