$ErrorActionPreference = 'Continue'
$exe = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_bin\RawrXD-Win32IDE_r1cap.exe'
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$port = 11438
Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }
Start-Sleep 1
$out = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_r1cap\out.txt'
$err = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_r1cap\err.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$bat = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_r1cap\run.bat'
@(
  '@echo off',
  'set RAWRXD_HOST_DECODE=1',
  'set DEEP2_DUALSTICK_ARM=0',
  'set RAWRXD_NO_VULKAN=1',
  'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
  ('"' + $exe + '" --headless --local --port ' + $port + ' --dir "G:\~dev\rawrxd" > "' + $out + '" 2> "' + $err + '"')
) | Set-Content $bat
Start-Process $bat -WindowStyle Hidden
$ok = $false
for ($i = 0; $i -lt 45; $i++) {
  try {
    if ((Invoke-WebRequest "http://127.0.0.1:$port/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep 1 }
}
Write-Host "HEALTH=$ok"
if (-not $ok) { Get-Content $err -Tail 20 -EA SilentlyContinue; exit 1 }
$tiny = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
function Post($u,$o,$t=600) {
  try {
    $r = Invoke-WebRequest $u -Method POST -Body ($o|ConvertTo-Json -Compress -Depth 5) -ContentType 'application/json' -UseBasicParsing -TimeoutSec $t
    return "$($r.StatusCode)"
  } catch { return "ERR:$($_.Exception.Message)" }
}
$l1 = Post "http://127.0.0.1:$port/api/model/load" @{ modelPath = $tiny }
$g1 = Post "http://127.0.0.1:$port/api/generate" @{ prompt = 'Say OK'; stream = $false; options = @{ num_predict = 16 } }
$u1 = Post "http://127.0.0.1:$port/api/model/unload" @{}
$l2 = Post "http://127.0.0.1:$port/api/model/load" @{ modelPath = $tiny }
$g2 = Post "http://127.0.0.1:$port/api/generate" @{ prompt = 'Say OK'; stream = $false; options = @{ num_predict = 16 } }
Write-Host "LOAD1=$l1 GEN1=$g1 UNLOAD=$u1 LOAD2=$l2 GEN2=$g2"
$lines = @("LOAD1=$l1","GEN1=$g1","UNLOAD=$u1","LOAD2=$l2","GEN2=$g2","HEALTH=$ok")
[IO.File]::WriteAllLines('G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\R1CAP_RELOAD_SMOKE.txt', $lines)
Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }
if ($g1 -eq '200' -and $g2 -eq '200') { exit 0 } else { exit 1 }
