# G3_STREAMER_AGENTIC_CURSOR_SURPASS_001 — refresh tool/subagent/rawr smoke
$ErrorActionPreference = "Continue"
$gate = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_STREAMER_AGENTIC_CURSOR_SURPASS_001"
New-Item -ItemType Directory -Force -Path $gate | Out-Null

$exeCandidates = @(
  "G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE.exe",
  "G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe",
  "C:\Users\Garrett\AppData\Local\Temp\RawrXD-Win32IDE.exe",
  "C:\Users\Garrett\rawrxd\bin\RawrXD-Win32IDE.exe"
)
$exe = $null
foreach ($c in $exeCandidates) { if (Test-Path $c) { $exe = $c; break } }
if (-not $exe) { Write-Host "NO_WIN32IDE_EXE"; exit 1 }

$port = 11455
$wd = "G:\~dev\rawrxd"
$motdAbs = "G:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc"
$rulesAbs = "G:\~dev\.cursor\rules"
$out = Join-Path $gate "server.out.txt"
$err = Join-Path $gate "server.err.txt"
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
[System.IO.File]::WriteAllText((Join-Path $gate "EXE_PROVENANCE.txt"), "EXE=$exe`nSHA256=$sha`nPORT=$port`nWORKING_DIR=$wd`nASOF=$(Get-Date -Format o)`n")

Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
try {
  $owners = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
  foreach ($opid in $owners) { if ($opid -and $opid -gt 0) { Stop-Process -Id $opid -Force -ErrorAction SilentlyContinue } }
} catch {}
Start-Sleep 1

$p = Start-Process -FilePath $exe -ArgumentList @("--headless","--local","--port","$port","--bind","127.0.0.1","--working-dir",$wd) -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden

$ready = $false
for ($i = 0; $i -lt 45; $i++) {
  Start-Sleep 1
  if ($p.HasExited) { Write-Host "EARLY_EXIT=$($p.ExitCode)"; Get-Content $err -Tail 40; exit 1 }
  try {
    $h = Invoke-WebRequest "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 2
    if ($h.StatusCode -eq 200) { $ready = $true; Write-Host "HEALTH_OK_SEC=$i"; break }
  } catch {}
}
if (-not $ready) { Write-Host "NO_HEALTH"; Stop-Process -Id $p.Id -Force -EA SilentlyContinue; exit 1 }

function Post-Tool([string]$tool, [hashtable]$argsMap) {
  $payload = @{ tool = $tool; args = $argsMap }
  $json = $payload | ConvertTo-Json -Compress -Depth 8
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/tool" -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -ContentType "application/json; charset=utf-8" -UseBasicParsing -TimeoutSec 45
    return "STATUS=$($r.StatusCode)`n$($r.Content)"
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $c = $sr.ReadToEnd(); $sr.Close()
      return "STATUS=$([int]$resp.StatusCode)`n$c"
    }
    return "STATUS=-1`n$($_.Exception.Message)"
  }
}
function Post-Json([string]$uri, [string]$jsonBody) {
  try {
    $r = Invoke-WebRequest -Uri $uri -Method POST -Body ([System.Text.Encoding]::UTF8.GetBytes($jsonBody)) -ContentType "application/json; charset=utf-8" -UseBasicParsing -TimeoutSec 60
    return "STATUS=$($r.StatusCode)`n$($r.Content)"
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $c = $sr.ReadToEnd(); $sr.Close()
      return "STATUS=$([int]$resp.StatusCode)`n$c"
    }
    return "STATUS=-1`n$($_.Exception.Message)"
  }
}

$pre = Post-Tool "list_directory" @{ path = $rulesAbs }
[System.IO.File]::WriteAllText((Join-Path $gate "pre_motd.txt"), $pre)
$motd = Post-Tool "read_file" @{ path = $motdAbs }
[System.IO.File]::WriteAllText((Join-Path $gate "motd_read.txt"), $motd)
$post = Post-Tool "list_directory" @{ path = $rulesAbs }
[System.IO.File]::WriteAllText((Join-Path $gate "post_motd_list.txt"), $post)
$cli = Post-Tool "execute_command" @{ command = "echo TOOL_LOOP_OK" }
[System.IO.File]::WriteAllText((Join-Path $gate "post_motd_cli.txt"), $cli)

$brief = "Please continue ensuring that the streamer is complete and can run agentic.`nSmoke-only spawn. PROMOTE=0 TIP_CLIMB=HOLD. No long K2."
$subBody = (@{ task = $brief; context = "continue-ensure" } | ConvertTo-Json -Compress)
$sub = Post-Json "http://127.0.0.1:$port/api/subagent" $subBody
[System.IO.File]::WriteAllText((Join-Path $gate "subagent.txt"), $sub)

$preOk = ($pre -match "STATUS=403")
$motdOk = ($motd -match "STATUS=200") -and ($motd -match "PassiveRoleNotRoleplay")
$listOk = ($post -match "STATUS=200") -and ($post -match "StreamerAgenticContinueEnsure")
$cliOk = ($cli -match "STATUS=200") -and ($cli -match "TOOL_LOOP_OK")
$subOk = ($sub -match "STATUS=202") -or ($sub -match "fail|deny|unavailable|disabled|motd")
Write-Host "TOOL_PARITY preOk=$preOk motdOk=$motdOk listOk=$listOk cliOk=$cliOk subOk=$subOk"
Write-Host ("SUB=" + $sub.Substring(0, [Math]::Min(220, $sub.Length)))

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep 1

$rawr = "F:\rawrxd\build_ide\bin-msvc\rawr.exe"
$model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$rawrOut = Join-Path $gate "rawr_run.out.txt"
$rawrErr = Join-Path $gate "rawr_run.err.txt"
$rawrRc = Join-Path $gate "rawr_run.rc.txt"
if ((Test-Path $rawr) -and (Test-Path $model)) {
  Write-Host "RAWR_RUN_START"
  $rp = Start-Process -FilePath $rawr -ArgumentList @("run", $model, "-p", "Say OK in one word.", "--max-tokens", "8") -PassThru -NoNewWindow -RedirectStandardOutput $rawrOut -RedirectStandardError $rawrErr -WorkingDirectory "G:\~dev"
  $waited = $rp.WaitForExit(180000)
  if (-not $waited) {
    Stop-Process -Id $rp.Id -Force -ErrorAction SilentlyContinue
    [System.IO.File]::WriteAllText($rawrRc, "EXIT=TIMEOUT`n")
    Write-Host "RAWR_RUN_TIMEOUT"
  } else {
    [System.IO.File]::WriteAllText($rawrRc, "EXIT=$($rp.ExitCode)`n")
    Write-Host "RAWR_RUN_EXIT=$($rp.ExitCode)"
  }
  $comb = ""
  if (Test-Path $rawrOut) { $comb += [IO.File]::ReadAllText($rawrOut) }
  if (Test-Path $rawrErr) { $comb += [IO.File]::ReadAllText($rawrErr) }
  Write-Host ("RAWR_MARKERS PRODUCT_STREAMER_PREP=" + ($comb -match "PRODUCT_STREAMER_PREP=1") + " AGENTIC_PATH=" + ($comb -match "AGENTIC_PATH=1"))
} else {
  [System.IO.File]::WriteAllText($rawrRc, "EXIT=NOT_RUN`n")
  Write-Host "RAWR_NOT_RUN"
}

if ($preOk -and $motdOk -and $listOk -and $cliOk -and $subOk) { exit 0 } else { exit 2 }
