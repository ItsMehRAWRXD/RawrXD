# RawrXD SNAP supervisor (source drop)

Windows-only, C++20, Win32/SDK only. Companion to the existing SNAP Process Guard; does not replace it.

## Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Run

```powershell
.\build\Release\snap_supervisor.exe run -- "F:\rawrxd\tools\deep2_agentic_loop.exe" --model "F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf" --task "Fix the off-by-one bug"
.\build\Release\snap_supervisor.exe scan
.\build\Release\snap_supervisor.exe cleanup 12345
.\build\Release\snap_supervisor.exe cleanup 12345 --confirm
```

Optional `--state DIR` sets receipt directory (default `%LOCALAPPDATA%\RawrXD\snap`). Optional `--progress FILE --stall-ms 120000` emits *warnings only* if the heartbeat file stops changing; the model must update that file from its host integration.

## Safety and boundaries

- Only processes started with `run` get a verified ownership record and a kill-on-close Job Object.
- A crashed supervisor closes its Job handle and Windows terminates its assigned child processes. Orphan cleanup is intended for abnormal cases, not a replacement for Job Objects.
- `cleanup` verifies PID, process creation time, exact image path, and that the recorded supervisor is no longer alive. It is dry-run without `--confirm`.
- `scan` reports candidates, not proof of staleness. Inaccessible processes are never killed.
- The supervisor does not kill based on RAM usage, forcibly reset GPU drivers, or automatically kill on heartbeat stalls.
- JSONL is diagnostic output, not a tamper-proof audit log. The state directory must be protected using appropriate Windows ACLs before deployment across multiple trust levels.
- Progress-file writes and JSONL are advisory; this is not a full GPU utilization monitor, crash dump system, or proof of memory reclamation.
- The program uses CREATE_NO_WINDOW; child stdout/stderr inherit normal process defaults, so adapt handle redirection if console streaming is required.
- Do not elevate this tool unnecessarily; no cross-user process management is intended.

## Acceptance tests to run on Windows

1. Launch a known test executable and check STARTED/EXITED JSONL receipts.
2. Terminate the supervisor while its child runs; verify Job Object kill-on-close.
3. Run two concurrent sessions; verify neither can clean up the other while its supervisor is alive.
4. Forge a stale PID record with mismatched creation time; verify cleanup refuses.
5. Exercise command-line arguments containing spaces and embedded quotation marks.
6. Confirm a stall warning does not kill a legitimately long-running inference.
7. Verify paths with non-ASCII characters and state-directory write failures fail closed.
8. Integrate GPU memory telemetry separately and check actual recovery on your hardware.

This code has not been compiled or run against your local RawrXD checkout or GPUs in this environment. It is a foundation drop, not a certified production release.
