# Launch RawrXD-Win32IDE for the agent fix→build→run loop demo.
# Prefer freshly built build-ninja binary; fall back to last known EXE.

$ErrorActionPreference = "Stop"
$candidates = @(
    "F:\~dev\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe",
    "F:\~dev\rawrxd\build-fresh-aug22\bin\RawrXD-Win32IDE.exe"
)
$exe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "RawrXD-Win32IDE.exe not found" }

$model = "F:\~dev\tinyllama_fresh.gguf"
$project = "F:\~dev\rawrxd\fixtures\agent_loop_broken_hello"

Write-Host "EXE:     $exe"
Write-Host "MODEL:   $model  (select in IDE)"
Write-Host "PROJECT: $project  (Open Folder)"
Write-Host "PROMPT:  Fix the compile error and run the program"
Write-Host ""
Write-Host "Spine already proven scripted: build-ninja\bin\ide_agent_loop_cert.exe --mode scripted"
Write-Host "Deep2 model-driven: ide_agent_loop_cert.exe --mode deep2 --model `"$model`""

Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe)
