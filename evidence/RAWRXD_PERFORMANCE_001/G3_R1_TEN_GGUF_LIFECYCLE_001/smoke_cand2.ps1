# Exclusive candidate smoke :11442 — only models that might fill 02/08/09 + deepseek
$ErrorActionPreference = 'Continue'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001'
$smoke = Join-Path $ev 'smoke'
$port = 11442
$base = "http://127.0.0.1:$port"
$imm = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_r1soft_IMMUTABLE_3E631BBB7BE707FC.exe'
$exe = Join-Path $ev 'smoke_bin\RawrXD-Win32IDE_cand2.exe'
Copy-Item -LiteralPath $imm -Destination $exe -Force
& 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe' /LARGEADDRESSAWARE $exe | Out-Null
$cands = @(
  [pscustomobject]@{ Id='phi3_q2'; Path='G:\~dev\rawrxd\phi3-mini-Q2_K.gguf' },
  [pscustomobject]@{ Id='llama32_q2'; Path='G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf' },
  [pscustomobject]@{ Id='blob_dde5'; Path='F:\OllamaModels\models\blobs\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff' },
  [pscustomobject]@{ Id='blob_667b'; Path='F:\OllamaModels\models\blobs\sha256-667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29' },
  [pscustomobject]@{ Id='deepseek'; Path='F:\OllamaModels\models\blobs\sha256-59bb50d8116b6a1f9bfbb940d6bb946a05554e591e30c8c2429ed6c854867ecb' }
)
function Kill-Port {
  for ($i=0; $i -lt 3; $i++) {
    Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
      $_.Name -match 'RawrXD' -or ($_.CommandLine -match "port $port|Win32IDE_cand")
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
    Get-NetTCPConnection -LocalPort $port,11435,11441 -EA SilentlyContinue | ForEach-Object {
      Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue
    }
    Start-Sleep 2
    if (@(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' }).Count -eq 0) { break }
  }
}
function Curl-Post([string]$path, [string]$bodyFile, [string]$outFile, [int]$timeoutSec = 3600) {
  $safeDir = Join-Path $env:TEMP 'rawrxd_r1_cand2'
  New-Item -ItemType Directory -Force -Path $safeDir | Out-Null
  if ($bodyFile -eq 'INLINE_EMPTY') {
    $safeBody = Join-Path $safeDir 'empty.json'; [IO.File]::WriteAllText($safeBody, '{}')
  } else {
    $safeBody = Join-Path $safeDir ([IO.Path]::GetFileName($bodyFile))
    Copy-Item -LiteralPath $bodyFile -Destination $safeBody -Force
  }
  $code = & curl.exe -sS -o $outFile -w '%{http_code}' -X POST "$base$path" -H 'Content-Type: application/json' --data-binary "@$safeBody" --max-time $timeoutSec 2>$null
  if (-not $code) { $code = '000' }
  if ($code -is [array]) { $code = [string]$code[-1] }
  $body = ''; if (Test-Path -LiteralPath $outFile) { $body = [IO.File]::ReadAllText($outFile) }
  $codeInt = 0; [void][int]::TryParse(([string]$code).Trim(), [ref]$codeInt)
  if ($codeInt -eq 0 -and $body -match '"success"\s*:\s*true') { $codeInt = 200 }
  if ($codeInt -eq 0 -and $body -match '"done"\s*:\s*true') { $codeInt = 200 }
  return @{ Code = $codeInt; Body = $body }
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('CAND2 exclusive IMMUTABLE=3E631BBB')
foreach ($c in $cands) {
  Kill-Port
  $tag = "c2_$($c.Id)"
  $out = Join-Path $smoke "$tag.out.txt"; $err = Join-Path $smoke "$tag.err.txt"
  Remove-Item $out,$err -Force -EA SilentlyContinue
  $bat = Join-Path $smoke "$tag.run.bat"
  @(
    '@echo off','set RAWRXD_HOST_DECODE=1','set RAWRXD_FORCE_CPU_INFERENCE=1','set DEEP2_MINIMAL_ENHANCE=1',
    'set DEEP2_DUALSTICK_ARM=0','set RAWRXD_NO_VULKAN=1','set DEEP2_MARS=0',
    'set VK_ICD_FILENAMES=C:\rawrxd_blocked_no_vulkan_icd.json',
    " `"$exe`" --headless --local --port $port --dir G:\~dev\rawrxd > `"$out`" 2> `"$err`""
  ) | Set-Content $bat -Encoding ASCII
  Start-Process -FilePath $bat -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden | Out-Null
  $ok=$false; $deadline=(Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    try { $h=Invoke-WebRequest -Uri "$base/api/engine/capabilities" -UseBasicParsing -TimeoutSec 3; if ($h.StatusCode -eq 200) { $ok=$true; break } } catch { Start-Sleep -Milliseconds 400 }
  }
  $n = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' }).Count
  if (-not $ok -or $n -ne 1) { $lines.Add("$($c.Id) FAIL boot ok=$ok n=$n"); Kill-Port; continue }
  $fwd = ($c.Path -replace '\\','/'); $name = [IO.Path]::GetFileName($c.Path)
  $prep = Join-Path $smoke "$tag.prep.json"; $load = Join-Path $smoke "$tag.load.json"; $gen = Join-Path $smoke "$tag.gen.json"
  [IO.File]::WriteAllText($prep, "{`"model`":`"$name`",`"path`":`"$fwd`"}")
  [IO.File]::WriteAllText($load, "{`"modelPath`":`"$fwd`"}")
  [IO.File]::WriteAllText($gen, '{"prompt":"Reply with exactly: OK","stream":false,"options":{"num_predict":8}}')
  [void](Curl-Post '/api/native/runtime/register' $prep (Join-Path $smoke "$tag.reg.json") 180)
  $p1 = Curl-Post '/api/native/generation/prepare' $prep (Join-Path $smoke "$tag.prep.out.json") 180
  $l1 = Curl-Post '/api/model/load' $load (Join-Path $smoke "$tag.load.out.json") 600
  $g1 = Curl-Post '/api/generate' $gen (Join-Path $smoke "$tag.gen1.json") 7200
  $u1 = Curl-Post '/api/model/unload' 'INLINE_EMPTY' (Join-Path $smoke "$tag.un.json") 120
  Start-Sleep 5
  $l2 = Curl-Post '/api/model/load' $load (Join-Path $smoke "$tag.rel.json") 600
  if ($l2.Code -ne 200) { Start-Sleep 3; $l2 = Curl-Post '/api/model/load' $load (Join-Path $smoke "$tag.rel.json") 600 }
  $g2 = Curl-Post '/api/generate' $gen (Join-Path $smoke "$tag.gen2.json") 7200
  $alive = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match 'RawrXD' }).Count
  $tok1=0; if ($g1.Body -match '"done"\s*:\s*true') { $tok1=1 }
  $tok2=0; if ($g2.Body -match '"done"\s*:\s*true') { $tok2=1 }
  $pass = ($p1.Code -eq 200 -and $l1.Code -eq 200 -and $g1.Code -eq 200 -and $tok1 -gt 0 -and $u1.Code -eq 200 -and $l2.Code -eq 200 -and $g2.Code -eq 200 -and $tok2 -gt 0 -and $alive -ge 1)
  $msg = "$($c.Id) $(if($pass){'PASS'}else{'FAIL'}) prep=$($p1.Code) load=$($l1.Code) gen=$($g1.Code) tok=$tok1 un=$($u1.Code) rel=$($l2.Code) g2=$($g2.Code) tok2=$tok2 alive=$alive"
  $lines.Add($msg); Write-Host $msg
  Kill-Port
}
$outPath = Join-Path $smoke 'CAND2_LIFECYCLE_SMOKE.txt'
($lines -join "`r`n") | Set-Content $outPath -Encoding UTF8
Get-Content $outPath
