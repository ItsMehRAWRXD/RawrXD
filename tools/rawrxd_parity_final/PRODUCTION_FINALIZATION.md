# RawrXD production-hardening source drop

This package contains a production-hardened C++20 autonomous runner plus the
verification tooling that proves its claims. It extends the previously
delivered runner with security hardening, a parser/path-guard fuzz harness, a
PE-header hardening verifier, and a CI gate.

It is **not** a replacement for the existing `F:\rawrxd` IDE, and it does not
claim Cursor/Kilo/Copilot feature parity.

## Contents

| File | Purpose |
| --- | --- |
| `rawr_run.cpp` | Native model/tool execution loop (dependency-free C++20, OS libs only) |
| `CMakeLists.txt` | Hardened build configuration (Release + ASan Debug) |
| `activate.ps1` | PowerShell `rawr run` adapter; locates and hardening-checks the runner |
| `parity_gate.py` | Offline evidence gate for task receipts |
| `parity_gate_evidence.py` | Real-ledger gate harness **with negative controls** |
| `test_e2e_mock.py` | Mocked Deep2/Ollama end-to-end test (no model required) |
| `rawr_fuzz_parsers.cpp` | Fuzz harness for the JSON codec, tool validator and path guards |
| `PRODUCTION_FINALIZATION.md` | This document |

## 1. Build (Windows MSVC, x64)

Run from the directory this file is in. The drop's own directory is
`rawrxd_parity_final`:

```powershell
cmake -S F:\rawrxd\tools\rawrxd_parity_final -B F:\rawrxd\tools\rawrxd_parity_final\build -A x64 -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ENABLE_HARDENING=ON
cmake --build F:\rawrxd\tools\rawrxd_parity_final\build --config Release
ctest --test-dir F:\rawrxd\tools\rawrxd_parity_final\build -C Release --output-on-failure
```

`RAWRXD_ENABLE_HARDENING` defaults to ON. Disabling it produces a working but
**unhardened** binary that `activate.ps1` will explicitly warn about.

## 2. Verify the hardening reached the binary

Passing flags on a command line is not proof. Parse the PE headers:

```powershell
pwsh -ExecutionPolicy Bypass -NoProfile -File F:\rawrxd\scripts\verify_hardening.ps1 -Path F:\rawrxd\tools\rawrxd_parity_final\build\Release\*.exe
```

Expected: `DllCharacteristics=0xC160`, i.e.
`DYNAMIC_BASE` (ASLR) + `NX_COMPAT` (DEP) + `HIGH_ENTROPY_VA` + `GUARD_CF` (CFG).

## 3. Test without a model

```powershell
py -3 F:\rawrxd\tools\rawrxd_parity_final\test_e2e_mock.py F:\rawrxd\tools\rawrxd_parity_final\build\Release\rawr_run.exe
py -3 F:\rawrxd\tools\rawrxd_parity_final\parity_gate_evidence.py
```

The first exercises tool rejection (`gash`), guarded edit, build, CTest verify,
the JSONL ledger and the HTTP schema for **both** backends. The second runs the
gate against a ledger it generates, then asserts the gate **rejects** a missing
ledger, an empty ledger, and one without `VERIFIED_SUCCESS` — so a gate that
simply always passes cannot pass this suite.

## 4. Fuzz the security-critical parsers

```powershell
cmake -S F:\rawrxd\tools\rawrxd_parity_final -B F:\rawrxd\tools\rawrxd_parity_final\build_asan -A x64 -DCMAKE_BUILD_TYPE=Debug
cmake --build F:\rawrxd\tools\rawrxd_parity_final\build_asan --config Debug --target rawr_fuzz_parsers
& F:\rawrxd\tools\rawrxd_parity_final\build_asan\Debug\rawr_fuzz_parsers.exe 20000
```

On Linux/macOS substitute an `-fsanitize=address,undefined` build. The harness
covers the hand-rolled JSON codec (manual index arithmetic), framed-tool
parsing, the fail-closed tool-name validator, and workspace containment.

## 5. Run a real model

```powershell
. F:\rawrxd\tools\rawrxd_parity_final\activate.ps1
rawr run qwen2.5-coder:32b 'Fix a failing test, build, and verify' --workspace <DISPOSABLE_WORKSPACE> --max-turns 30 --ledger <ledger.jsonl>
```

The Deep2 HTTP server must already be serving the model. `--backend ollama` uses
Ollama instead. **Use a disposable workspace first** — model-generated edits can
be wrong. `--allow-exec` permits arbitrary process execution and must only be
used in a trusted sandbox.

## 6. Real-model evidence gate

After 10+ *distinct, previously unseen* tasks with explicit ledger paths:

```powershell
py -3 F:\rawrxd\tools\rawrxd_parity_final\parity_gate.py @(Get-ChildItem F:\rawrxd\evidence\real_task_*.jsonl | ForEach-Object FullName) --min-tasks 10 --min-pass-rate 0.9 --report F:\rawrxd\evidence\parity_gate.json
```

PowerShell does not expand wildcards for native commands, hence the `@(...)`.

`parity_gate.py` verifies event integrity, a real tool-execution trail,
mutation/build/test receipts and a terminal verified status. It does **NOT**
verify functional correctness of the patch, GPU parity, safety of arbitrary
shell commands, or editor UX. Review actual diffs and run held-out tests. Do
not feed simulated-model ledgers to the real-model gate.

## Verified on this machine

Verified 2026-10-15 on Windows 11 x64, MSVC 19.44, CMake 4.4.2:

- Clean `/W4` Release build, zero warnings, for both binaries
- PE headers: `DYNAMIC_BASE`/`NX_COMPAT`/`HIGH_ENTROPY_VA`/`GUARD_CF` all set
- `rawr_run --self-test` passes (JSON codec, frames, gash rejection, guarded
  write/read/edit, `PATH_GUARD`, `PROTECTED_MUTATION`)
- `ctest` 2/2 pass (`rawr_run_self_test`, `rawr_fuzz_parsers`)
- `test_e2e_mock.py` passes for deep2 and ollama backends
- `parity_gate_evidence.py`: real ledger accepted; missing/empty/no-success
  ledgers rejected
- Fuzz harness: 60k JSON + 120k frame inputs, clean **under AddressSanitizer**

## NOT verified here

These are unproven, and nothing in this package should be read as claiming them:

- Real-model autonomous task results, and the 90% success rate over 10+ unseen
  tasks
- Integration into the existing `rawr.exe` / Win32 IDE command handlers
- Streaming UI, persistent task resume/checkpoints
- Competitive GPU inference speed and inference numerical parity
- Cursor-level editing UX, Kilo-level agent orchestration, extension ecosystem

## Known bug fixed during verification

`test_e2e_mock.py` originally configured with the default multi-config Visual
Studio generator, so `ctest --test-dir build` reported *"Test not available
without configuration"* and the verify step could never succeed. The build and
verify steps now pass `--config Release` / `-C Release`, which single-config
generators ignore. The runner itself was correct throughout: it reported
`COMPLETED_UNVERIFIED` and exited non-zero rather than fabricating success.

Additionally, `/DYNAMICBASE`, `/NXCOMPAT` and `/HIGHENTROPYVA` are **linker**
options and must never be passed to the compiler (MSVC fails with D8021). Each
optimisation flag needs its own CMake generator expression, because packing
several into one `$<...>` yields a single mangled argument.
