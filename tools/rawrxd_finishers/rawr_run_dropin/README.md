# RawrXD finishers — one-command autonomous runner

This is an actual source drop, not a milestone checklist. It does **not** alter your F: drive by itself. No third-party production runtime dependencies (WinHTTP is built into Windows).

### Windows build (MSVC x64 Developer PowerShell)

Extract folder to `F:\rawrxd\tools\rawr_run_dropin`:

```powershell
cmake -S F:\rawrxd\tools\rawr_run_dropin -B F:\rawrxd\tools\rawr_run_dropin\build -A x64
cmake --build F:\rawrxd\tools\rawr_run_dropin\build --config Release
ctest --test-dir F:\rawrxd\tools\rawr_run_dropin\build -C Release --output-on-failure
```

### Run a task

Direct executable:

```powershell
F:\rawrxd\tools\rawr_run_dropin\build\Release\rawr_run.exe run modelname "do this: audit my source, repair the bug, build, and verify" --workspace F:\rawrxd
```

For a `rawr run ...` PowerShell entry immediately after building, dot-source the included session-only adapter, then run:

```powershell
. F:\rawrxd\tools\rawr_run_dropin\activate.ps1
rawr run modelname "do this: audit my source, repair the bug, build, and verify" --workspace F:\rawrxd
```

Default backend: Deep2 OpenAI-compatible server on `127.0.0.1:11436`. The server must be running already with the named model. For Ollama add `--backend ollama`; requires a matching Ollama model tag.

**To make `rawr run` part of the actual native `rawr.exe`**, rather than a session PowerShell function, use the two C++/CMake integration hooks in `INTEGRATE_INTO_RAWR.md`. Do not replace an existing CLI binary blindly.

### Implemented

- Native HTTP/JSON model adapter for Deep2 or Ollama; no NDJSON splice or `rfind` parsing
- JSON or byte-counted SNAP-style model tool requests
- Fail-closed tool-name validation (`gash` rejected, never silently executed)
- Multi-turn model/tool/result loop with retry, execution timeouts, and request-specific state
- Guarded tools: `list`, `read`, `grep`, `write`, `edit`, `exec`, `verify`
- Workspace path boundaries, protected model/Git/binary paths, exclusive file creation
- Direct subprocess spawning, bounded output, Windows Job Object cleanup on timeout
- Mutation tracking and build/test receipts, truthful verified/unverified/blocked statuses
- JSONL audit trail, server-reported token counts and approximate generation throughput

### What is **not** integrated or certified

- Existing Windows `F:\rawrxd` files, its actual `rawr.exe` main, and SNAP supervisor (not accessible here)
- Real Deep2 local model loading / automatic Deep2 server start
- Real-model instruction-following and SNAP-call generation quality
- Streaming incremental token display, resume-after-restart, browser/multi-agent tools
- Windows MSVC build/runtime (tests here executed on Linux with locally simulated model HTTP)

Run first on a disposable workspace. `--allow-exec` permits arbitrary local executables, so treat it as an explicit trust decision.
