# RawrXD AutoClosure source drop — RAWRXD_AUTOCLOSURE_001

Purpose: remove the repeated manual certification choreography and give RawrXD a bounded, self-driving source-closure path using only C++20, Win32, and the existing Deep2 engine.

## What this closes

1. **Single model authority**
   - One `--model` path is hashed once with source-only SHA-256.
   - The same loaded engine instance is used by the fast inference gate and the autonomous agent loop.
   - Receipt records `MODEL_PATH`, `MODEL_SHA256`, and `MODEL_FILE_SIZE_BYTES`.

2. **No dependency on the stuck `Deep2Engine::generate()` controller**
   - `DecodeBounded()` drives the already-public production primitives directly:
     `tokenize -> embedToken -> forwardTokenAllLayers -> advancePersistentKv -> computeLogits -> argmax`.
   - This makes the first real token the gate, instead of waiting through a long multi-phase generation loop.

3. **Strict GPU authority**
   - Calls `setVulkanStrictNoCpuFallback(true)` and `enableVulkan(true)`.
   - Requires `isRealGpuForward()`.
   - Requires zero delta from `vulkanGemvFallbackCount()`.
   - Rejects `vulkanStrictViolation()`.

4. **Hard bounds / no babysitting**
   - Gate generation has a fixed token budget (default 8).
   - Agent has iteration and tool-call budgets.
   - Build and test subprocesses have hard kill timeouts.
   - The top-level `--autoclose` invocation runs a worker child. The parent kills the worker on `--wall-ms` and writes a timeout FAIL receipt. A wedged GPU/driver therefore cannot leave the gate running forever.

5. **Always-written receipt**
   - Success and ordinary failures write the same receipt.
   - Parent watchdog also writes a FAIL receipt if it has to terminate the child.

6. **Autonomous source loop**
   - Model can read/list/search/write/replace source, view `git diff`, and request build/test.
   - Successful source edits immediately trigger configured build + test.
   - `finish` is accepted only after final configured build and test pass.
   - Exact replacement must match once; writes are atomic; paths are confined to the workspace.

## Files

- `src/closure/RawrXDAutoClosure.hpp`
- `src/closure/RawrXDAutoClosure.cpp`
- `integration/CMakeLists.txt.snippet`
- `integration/main_win32_hook.cpp.snippet`
- `apply_rawrxd_autoclosure.ps1`

## Install

From PowerShell:

```powershell
Set-Location <unzipped-drop>
.\apply_rawrxd_autoclosure.ps1 -RepoRoot "F:\~dev\rawrxd" -PatchCMake
```

The installer patches the CMake target and the shipping `main_win32.cpp` entry point automatically, but only after it finds exactly one supported WinMain/wWinMain signature. It creates timestamped backups and refuses ambiguous source drift.

Rebuild once.

## Fast inference closure only

```powershell
& "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" `
  --autoclose `
  --model "G:\OllamaModels\YOUR_MODEL.gguf" `
  --workspace "F:\~dev\rawrxd" `
  --gate-tokens 8 `
  --nonce "7E91B462" `
  --receipt "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_autoclose.txt" `
  --wall-ms 300000
```

Expected authoritative closure fields include:

```text
MODEL_LOADED=PASS
TOKENIZER_READY=PASS
FORWARD_PASS_OK=PASS
LOGITS_FINITE=PASS
GENERATED_TOKEN_COUNT=8
REAL_GPU_FORWARD=PASS
CPU_FALLBACKS=0
STRICT_GPU_VIOLATIONS=0
SYNTHETIC_TOKEN_OUTPUT=0
STUB_FALLBACKS=0
VERDICT=PASS
```

## Autonomous read/edit/build/test closure

Put the engineering task in `F:\~dev\task.txt`, then:

```powershell
& "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" `
  --autoclose `
  --model "G:\OllamaModels\YOUR_MODEL.gguf" `
  --workspace "F:\~dev\rawrxd" `
  --task-file "F:\~dev\task.txt" `
  --build 'cmake --build F:\~dev\rawrxd\win32ide_strict\build_v4 --target RawrXD-Win32IDE --config Release' `
  --test 'F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe --cert-fast' `
  --nonce "7E91B462" `
  --receipt "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_autoclose.txt" `
  --command-timeout-ms 180000 `
  --wall-ms 1800000
```

The loop does not accept the model saying “done” as evidence. A configured build and test must both return exit code 0.

## Important integration note

This drop is deliberately built on the production Deep2 public API already used by repository tests. It does **not** replace `Deep2Engine_GpuForward.cpp`, the rectangular GEMV fixes, or quant kernels. It removes the fragile orchestration around them.

The source was prepared against the current public RawrXD API surface visible in the repository. Your `F:\~dev` working tree is newer than the public branch, so the installer is fail-closed: it auto-patches only when the CMake target and exactly one supported WinMain/wWinMain entrypoint can be identified. Otherwise it makes no blind entrypoint edit and reports the drift. Once installed, everything is driven by `--autoclose`.
