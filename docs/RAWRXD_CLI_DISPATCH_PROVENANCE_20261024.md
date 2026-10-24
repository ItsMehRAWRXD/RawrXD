# RawrXD CLI dispatch provenance audit

Current checkout reported: `local-30b-backend`, HEAD
`4cdbf7f963cc0f4f3f032aa7d3819ecdfef4957d`.

The `CMakeLists.txt` target `RawrXD-CLI-V2` declares
`src/rawrxd_cli_v2.cpp` as its entry point. That file contains
`if (cmd == "doctor") return CmdDoctor();` and
`if (cmd == "models")` handling. The reported `rawr doctor` and
`rawr models` output (usage, exit 0) does not match those branches.
Do not assume the handlers are missing; verify which executable is run.

## Current-binary acceptance checks (PowerShell, Windows)

```powershell
Set-Location F:\rawrxd
$exe = (Resolve-Path .\build_msvc\bin-msvc\rawr.exe).Path
$meta = [ordered]@{
    branch = (git branch --show-current)
    head = (git rev-parse HEAD)
    exe = $exe
    sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash
}
$meta | ConvertTo-Json
& $exe doctor 2>&1 | Tee-Object -FilePath .\evidence\rawr_doctor_current.log
$doctorExit = $LASTEXITCODE
& $exe models 2>&1 | Tee-Object -FilePath .\evidence\rawr_models_current.log
$modelsExit = $LASTEXITCODE
"doctorExit=$doctorExit modelsExit=$modelsExit"
```

Use the *exact* absolute executable path, not an alias, PATH lookup, or
another build tree. Compare the CLI build target's linker output and
`CMakeFiles/RawrXD-CLI-V2.dir` inputs with this executable. Confirm
`rawr.exe` SHA-256 matches the provenance receipt.

### Functional assertions
- `doctor`: must report real environment diagnostics; usage text alone fails.
- `models`: must return inventory or explicit service-unavailable error;
  usage text alone fails.
- Ollama: each model must return nonempty content or a classified nonzero
  error with raw response and stream frames retained.
- Deep2: fresh same-binary GGUF correctness evidence required; previous
  `nemotron_q6kfix.txt` is stale and excluded.
- GPU: nonzero actual dispatch and matched tokens required before 150 TPS.

## Cross-branch recovery controls
Audit source one file at a time, record original branch and SHA-256, then
selectively port Qt-era features to Win32/C++20 without adding dependencies.
Do not certify cross-platform outputs merely because a compiler accepts
the target flag; link and execute on the destination OS/architecture.
