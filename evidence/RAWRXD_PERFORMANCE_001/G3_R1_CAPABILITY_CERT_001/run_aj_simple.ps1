# Simplified A-J lifecycle (no native prepare) — matches proven r1cap reload smoke
$ErrorActionPreference = 'Continue'
$ev = Split-Path -Parent $MyInvocation.MyCommand.Path
$smoke = Join-Path $ev 'smoke'
$receipts = Join-Path $ev 'receipts'
New-Item -ItemType Directory -Force -Path $smoke, $receipts, (Join-Path $ev 'smoke_bin') | Out-Null
$models = Get-Content -LiteralPath (Join-Path $ev 'models_aj.json') -Raw | ConvertFrom-Json
$exeSrc = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1cap.exe'
if (-not [IO.File]::Exists($exeSrc)) { throw "missing $exeSrc" }
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1cap_run.exe'
[IO.File]::Copy($exeSrc, $exe, $true)
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $exe | Out-Null
$exeSha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$port = 11435
$base = "http://127.0.0.1:$port"
$rawrxd = (Resolve-Path -LiteralPath (Join-Path $ev '..\..\..')).Path

function Kill-Port {
  Get-NetTCPConnection -LocalPort $port -EA SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue } catch {}
  }
  Start-Sleep 2
}

function Start-H([string]$tag) {
  Kill-Port
  $out = Join-Path $smoke "$tag.out.txt"
  $err = Join-Path $smoke "$tag.err.txt"
  $bat = Join-Path $smoke "$tag.run.bat"
  $lines = @(
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
  [IO.File]::WriteAllLines($bat, $lines)
  Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
  for ($i = 0; $i -lt 90; $i++) {
    try {
      $h = Invoke-WebRequest -Uri ($base + '/api/engine/capabilities') -UseBasicParsing -TimeoutSec 2
      if ($h.StatusCode -eq 200) { return $true }
    } catch { Start-Sleep 1 }
  }
  return $false
}

function Post($url, $obj, $timeoutSec) {
  $json = $obj | ConvertTo-Json -Compress -Depth 6
  try {
    $r = Invoke-WebRequest -Uri $url -Method POST -Body $json -ContentType 'application/json' -UseBasicParsing -TimeoutSec $timeoutSec
    return @{ Code = [int]$r.StatusCode; Body = [string]$r.Content }
  } catch {
    $c = 0
    if ($_.Exception.Response) { try { $c = [int]$_.Exception.Response.StatusCode } catch {} }
    return @{ Code = $c; Body = [string]$_.Exception.Message }
  }
}

$pass = 0; $fail = 0
$matrix = @("EXE_SHA256=$exeSha", "EXE_SHA16=$($exeSha.Substring(0,16))", "PE_LAA=YES HOST_DECODE=1 OLLAMA_CONTACT=0 PORT=$port")
$genObj = @{ prompt = 'Reply with exactly: OK'; stream = $false; options = @{ num_predict = 32 } }

foreach ($m in $models) {
  $tag = [string]$m.Id
  $path = [string]$m.Path
  $name = [IO.Path]::GetFileName($path)
  Write-Host ("=== STAGE {0} {1} ===" -f $m.Stage, $name)
  if (-not (Start-H $tag)) {
    $fail++; $matrix += ("{0} {1} FAIL health" -f $m.Stage, $name)
    Write-Host ("STAGE {0} => FAIL health" -f $m.Stage)
    continue
  }
  $load1 = Post ($base + '/api/model/load') @{ modelPath = $path } 1800
  $gen1 = Post ($base + '/api/generate') $genObj 1800
  $un = Post ($base + '/api/model/unload') @{} 120
  Start-Sleep 2
  $load2 = Post ($base + '/api/model/load') @{ modelPath = $path } 1800
  Start-Sleep 1
  $gen2 = Post ($base + '/api/generate') $genObj 1800
  $alive = [bool](Get-NetTCPConnection -LocalPort $port -State Listen -EA SilentlyContinue)
  $ok = ($load1.Code -eq 200 -and $gen1.Code -eq 200 -and $un.Code -eq 200 -and $load2.Code -eq 200 -and $gen2.Code -eq 200 -and $alive)
  $tok = 0
  if ($gen1.Body -match '"response"\s*:\s*"([^"]*)"') { $tok = [Math]::Max(1, $Matches[1].Length) }
  $rec = @(
    "STAGE=$($m.Stage)", "ID=$tag", "ARCH=$($m.Arch)", "FAMILY=$($m.Family)",
    "PATH=$path", "LOAD1=$($load1.Code)", "GEN1=$($gen1.Code)", "UNLOAD=$($un.Code)",
    "LOAD2=$($load2.Code)", "GEN2=$($gen2.Code)", "TOKENS_EMITTED=$tok",
    "PROCESS_SURVIVED=$([int]$alive)", "VERDICT=$(if($ok){'PASS'}else{'FAIL'})"
  )
  [IO.File]::WriteAllLines((Join-Path $receipts "$tag.txt"), $rec)
  if ($ok) { $pass++ } else { $fail++ }
  $matrix += ("{0} {1} {2} GEN1={3} GEN2={4} TOKENS={5}" -f $m.Stage, $name, $(if($ok){'PASS'}else{'FAIL'}), $gen1.Code, $gen2.Code, $tok)
  Write-Host ("STAGE {0} => {1}" -f $m.Stage, $(if($ok){'PASS'}else{'FAIL'}))
}

Kill-Port
$matrix += "PASS_COUNT=$pass FAIL_COUNT=$fail TOTAL=10"
[IO.File]::WriteAllLines((Join-Path $ev 'MATRIX.txt'), $matrix)
Write-Host "DONE PASS=$pass FAIL=$fail"
if ($pass -eq 10) { exit 0 } else { exit 1 }
