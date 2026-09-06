$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$env:VK_ICD_FILENAMES = 'C:\__no_vulkan_icd__.json'
$env:RAWRXD_SKIP_STREAMER_POSTLOAD = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:RAWRXD_BRIDGE_CPU_ONLY = '1'
$env:RAWRXD_SKIP_DEFERRED_MODEL_LOAD = '1'
$env:RAWRXD_INFERENCE_CTX = '512'
$p = Start-Process 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe' -PassThru
Start-Sleep -Seconds 15
Write-Host "alive15=$(-not $p.HasExited) exit=$($p.ExitCode)"
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
