# Cold Phi-only — read path from models_aj.json (avoid ~ expansion / Join-Path quirks)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ev = $here
$smoke = Join-Path $ev 'smoke_phi_cold'
New-Item -ItemType Directory -Force -Path $smoke, (Join-Path $ev 'smoke_bin') | Out-Null
$models = Get-Content -LiteralPath (Join-Path $ev 'models_aj.json') -Raw | ConvertFrom-Json
$phiRow = $models | Where-Object { $_.Stage -eq 'D' } | Select-Object -First 1
$phi = [string]$phiRow.Path
if (-not [IO.File]::Exists($phi)) { throw "missing phi: $phi" }

$exeSrc = $null
foreach ($c in @(
  (Join-Path (Split-Path $ev) 'G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r01_laa.exe'),
  (Join-Path (Split-Path $ev) 'G3_R1_TEN_GGUF_LIFECYCLE_001\smoke_bin\RawrXD-Win32IDE_r1soft_SEALED.exe')
)) {
  if (Test-Path -LiteralPath $c) { $exeSrc = $c; break }
}
if (-not $exeSrc) { throw 'no EXE' }
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_phi_cold.exe'
Copy-Item -LiteralPath $exeSrc -Destination $exe -Force
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$port = 11437
$base = "http://127.0.0.1:$port"
Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
}
Start-Sleep 1
$out = Join-Path $smoke 'out.txt'
$err = Join-Path $smoke 'err.txt'
$bat = Join-Path $smoke 'run.bat'
$dirArg = (Resolve-Path -LiteralPath (Join-Path (Split-Path (Split-Path (Split-Path $ev))) '..\..\..') -EA SilentlyContinue)
# product --dir is repo root rawrxd
$rawrxd = (Get-Item -LiteralPath (Join-Path $ev '..\..\..')).FullName
# ev = .../G3_R1_CAPABILITY_CERT_001 → ../../.. = evidence? 
# $ev = G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001
# parent x3 = rawrxd
$rawrxd = (Resolve-Path -LiteralPath (Join-Path $ev '..\..\..')).Path

$batLines = @(
  '@echo off',
  'set RAWRXD_HOST_DECODE=1',
  'set RAWRXD_FORCE_CPU_INFERENCE=1',
  'set DEEP2_MINIMAL_ENHANCE=1',
  'set DEEP2_DUALSTICK_ARM=0',
  'set RAWRXD_NO_VULKAN=1',
  'set DEEP2_MARS=0',
  'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
  ('"' + $exe + '" --headless --local --port ' + $port + ' --dir "' + $rawrxd + '" > "' + $out + '" 2> "' + $err + '"')
)
[IO.File]::WriteAllLines($bat, $batLines)
Start-Process -FilePath $bat -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Hidden | Out-Null
$ok = $false
for ($i = 0; $i -lt 90; $i++) {
  try {
    $h = Invoke-WebRequest -Uri ($base + '/api/engine/capabilities') -UseBasicParsing -TimeoutSec 2
    if ($h.StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $ok) {
  Get-Content -LiteralPath $err -EA SilentlyContinue | Select-Object -Last 30
  throw 'health timeout'
}

function Post($url, $obj, $t) {
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

$load = Post ($base + '/api/model/load') @{ modelPath = $phi } 1800
$gen = Post ($base + '/api/generate') @{ prompt = 'Reply with exactly: OK'; stream = $false; options = @{ num_predict = 48 } } 1800
$alive = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue)
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$pass = ($load.Code -eq 200 -and $gen.Code -eq 200 -and $alive)
$gb = $gen.Body
if ($gb.Length -gt 240) { $gb = $gb.Substring(0, 240) }
$lines = @(
  "EXE_SRC=$exeSrc",
  "EXE_SHA256=$sha",
  "PHI_PATH=$phi",
  "LOAD=$($load.Code)",
  "GEN=$($gen.Code)",
  "GEN_BODY=$gb",
  "PROCESS_SURVIVED=$([int]$alive)",
  "PHI_COLD_PASS=$([int]$pass)"
)
[IO.File]::WriteAllLines((Join-Path $ev 'PHASE0_PHI_COLD.txt'), $lines)
$lines | ForEach-Object { Write-Host $_ }
Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
}
if ($pass) { exit 0 } else { exit 1 }
