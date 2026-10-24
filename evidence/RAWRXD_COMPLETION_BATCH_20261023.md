# RawrXD completion batch audit

## Verified in this batch

- Native IDE gate ledger (121–150): standalone Release build and CTest pass (1/1).
- Win32 IDE x64-host Release target: executable produced and startup observed.
- PowerShell process handling: bounded output drain, timeout, and owned child cleanup are wired.
- PowerShell and debugger panel command routing: native subclass handlers preserve the original window procedure.
- Codex native command source and dependency-free transport: source integrated.

## Still requiring runtime evidence

The following remain `NOT_RUN` or `NOT_CERTIFIED` until a real receipt is captured: Q3_K GPU shader and GGML parity, Q2_K differential replay, GPU forward dispatch, 150 TPS, complete 39-test GUI interaction, WebView2 rendering, Deep2 streaming, GhostText, model-driven edit/build/test/recovery, LSP/extensions/debugger/Git surfaces, dual-GPU execution, and end-to-end autonomous certification.

The Apple IPA signing roadmap is out of scope for this Windows RawrXD build and has not been represented as completed.

## Certification policy

Infrastructure and compile receipts do not promote model or IDE certification. `FULL_MODEL_CERTIFIED` and `FULL_PASS` require executable evidence for every applicable gate, with no silent fallback.

## Reproduction

```powershell
cmake -S src/ide_gates -B build_ide_gates -G "Visual Studio 17 2022" -A x64
cmake --build build_ide_gates --config Release --parallel 1
ctest --test-dir build_ide_gates -C Release --output-on-failure
```
