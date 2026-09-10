# Phase0: Tiny → unload → Phi in ONE process (path-switch OpenSession)
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001'
$smoke = Join-Path $ev 'smoke_phase0'
New-Item -ItemType Directory -Force -Path $smoke, (Join-Path $ev 'smoke_bin') | Out-Null
$tiny = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$phi = Join-Path 'G:\~dev\rawrxd\_r1_iso\02_phi3_mini' 'Phi-3-mini-4k-instruct-q8_0.gguf'
if (-not (Test-Path -LiteralPath $tiny)) { throw "missing tiny $tiny" }
if (-not (Test-Path -LiteralPath $phi)) { throw "missing phi $phi" }

$exeSrc = @(
  'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe',
  'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r1soft_SEALED.exe',
  'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r01_laa.exe'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_phase0.exe'
Copy-Item -LiteralPath $exeSrc -Destination $exe -Force
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$port = 11436
$base = "http://127.0.0.1:$port"

function Kill-Port {
  Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
  }
  Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
    $_.Name -match 'RawrXD' -and $_.CommandLine -match "$port"
  } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Start-Sleep 2
}

Kill-Port
$out = Join-Path $smoke 'phase0.out.txt'
$err = Join-Path $smoke 'phase0.err.txt'
$bat = Join-Path $smoke 'phase0.run.bat'
@(
  '@echo off',
  'set RAWRXD_HOST_DECODE=1',
  'set RAWRXD_FORCE_CPU_INFERENCE=1',
  'set DEEP2_MINIMAL_ENHANCE=1',
  'set DEEP2_DUALSTICK_ARM=0',
  'set RAWRXD_NO_VULKAN=1',
  'set DEEP2_MARS=0',
  'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
  " `"$exe`" --headless --local --port $port --dir G:\~dev\rawrxd > `"$out`" 2> `"$err`""
) | Set-Content $bat
Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $h = Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 2
    if ($h.StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep 1 }
}
if (-not $ok) { throw 'phase0 health timeout' }

function Post([string]$url, $obj, [int]$t = 900) {
  $json = $obj | ConvertTo-Json -Compress -Depth 6
  try {
    $r = Invoke-WebRequest -Uri $url -Method POST -Body $json -ContentType 'application/json' -UseBasicParsing -TimeoutSec $t
    return @{ Code = [int]$r.StatusCode; Body = [string]$r.Content }
  } catch {
    $c = 0
    if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode }
    return @{ Code = $c; Body = [string]$_.Exception.Message }
  }
}

$gen = @{ prompt = 'Reply with exactly: OK'; stream = $false; options = @{ num_predict = 48 } }
$steps = [ordered]@{}
$steps.TINY_LOAD = Post "$base/api/model/load" @{ modelPath = $tiny } 600
$steps.TINY_GEN = Post "$base/api/generate" $gen 600
$steps.UNLOAD = Post "$base/api/model/unload" @{} 60
$steps.PHI_LOAD = Post "$base/api/model/load" @{ modelPath = $phi } 1200
$steps.PHI_GEN = Post "$base/api/generate" $gen 1200
$alive = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue)
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
function Clip([string]$s, [int]$n = 160) {
  if (-not $s) { return '' }
  if ($s.Length -le $n) { return $s }
  return $s.Substring(0, $n)
}
$lines = @(
  "EXE=$exe",
  "EXE_SHA256=$sha",
  "PHI_PATH=$phi",
  "PORT=$port",
  "TINY_LOAD=$($steps.TINY_LOAD.Code)",
  "TINY_GEN=$($steps.TINY_GEN.Code) body=$(Clip $steps.TINY_GEN.Body)",
  "UNLOAD=$($steps.UNLOAD.Code)",
  "PHI_LOAD=$($steps.PHI_LOAD.Code) body=$(Clip $steps.PHI_LOAD.Body)",
  "PHI_GEN=$($steps.PHI_GEN.Code) body=$(Clip $steps.PHI_GEN.Body 200)",
  "PROCESS_SURVIVED=$([int]$alive)"
)
$pass = ($steps.TINY_LOAD.Code -eq 200 -and $steps.TINY_GEN.Code -eq 200 -and
         $steps.PHI_LOAD.Code -eq 200 -and $steps.PHI_GEN.Code -eq 200 -and $alive)
$lines += "PHASE0_TINY_PHI_PASS=$([int]$pass)"
[IO.File]::WriteAllLines((Join-Path $ev 'PHASE0_TINY_PHI.txt'), $lines)
$lines | ForEach-Object { Write-Host $_ }
Kill-Port
if ($pass) { exit 0 } else { exit 1 }
