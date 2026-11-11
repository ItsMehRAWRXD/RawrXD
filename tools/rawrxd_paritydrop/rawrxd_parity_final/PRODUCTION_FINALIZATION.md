# RawrXD / Deep2 parity finalization source drop

This package extends the previously delivered C++20 autonomous runner with an offline evidence gate. It is **not** a replacement for the existing `F:\rawrxd` IDE, and does not claim Cursor/Kilo/Copilot feature parity without independent tests.

## Build (Windows MSVC Developer PowerShell)

```powershell
cmake -S F:\rawrxd\tools\rawr_parity_final -B F:\rawrxd\tools\rawr_parity_final\build -A x64
cmake --build F:\rawrxd\tools\rawr_parity_final\build --config Release
ctest --test-dir F:\rawrxd\tools\rawr_parity_final\build -C Release --output-on-failure
. F:\rawrxd\tools\rawr_parity_final\activate.ps1
```

The included `activate.ps1` is adjusted for this package directory; alternatively invoke `build\Release\rawr_run.exe` directly.

## Run

```powershell
& F:\rawrxd\tools\rawr_parity_final\build\Release\rawr_run.exe run qwen2.5-coder:32b 'Fix a failing test, build, and verify' --workspace F:\rawrxd\h01_ws\H01-01 --max-turns 30 --ledger F:\rawrxd\evidence\real_task_01.jsonl
```

The Deep2 HTTP server must be serving the model. `--backend ollama` uses Ollama instead. Use a disposable workspace first; model-generated edits can be wrong. `--allow-exec` allows arbitrary process execution and should be used only in a trusted sandbox.

## Test without a model (mock tests, not production certification)

```powershell
python test_e2e_mock.py build\Release\rawr_run.exe
```

## Real-model evidence gate

After running 10+ *distinct, previously unseen* tasks with explicit ledger paths:

```powershell
python parity_gate.py F:\rawrxd\evidence\real_task_*.jsonl --min-tasks 10 --min-pass-rate 0.9 --report F:\rawrxd\evidence\parity_gate.json
```

In PowerShell wildcard expansion may not occur for native Python commands; use:

```powershell
python parity_gate.py @(Get-ChildItem F:\rawrxd\evidence\real_task_*.jsonl | ForEach-Object FullName) --min-tasks 10 --min-pass-rate 0.9
```

`parity_gate.py` verifies event integrity, a real tool execution trail, mutation/build/test receipts, and a terminal verified status. It does NOT verify independent functional correctness, GPU parity, safety of arbitrary shell commands, or editor UX. Review actual diffs and run held-out tests. Do not use simulated-model ledgers for the real-model gate.

## Not completed by this package

- Integrating the runner into the user's existing `rawr.exe`/Win32 IDE command handlers
- Automatic GGUF model loading, GPU kernel speed, 1M context, and inference numerical parity
- Persistent resume/checkpoints, browser automation, background agents, inline editor completions, language servers, extension ecosystem, or Copilot-like review UI
- Independent real-model task suite, Windows build verification, or real-world security audit

These gaps prevent any credible claim of production-finalized Cursor/Kilo/Copilot parity.
