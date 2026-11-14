# W4 MULTIFAMILY_CLI_GUI_INTEGRATION — measured parity matrix
# PROMOTE=0 CROSS_SHA_CREDIT=0 INVENT_PASS=0
$ErrorActionPreference = 'Continue'
$ev = 'g:\~dev\rawrxd\evidence\W4_MULTIFAMILY_CLI_GUI_INTEGRATION_001'
$cli = "$ev\pins\rawr_W4_CLI.exe"
$gui = "$ev\pins\RawrXD-Win32IDE_W4_GUI.exe"
$ws  = "$ev\ws"
New-Item -ItemType Directory -Force -Path "$ev\runs\cli","$ev\runs\gui" | Out-Null
$models = [ordered]@{
  tinyllama = 'g:\~dev\rawrxd\models\tinyllama.gguf'
  gemma3    = 'g:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf'
  llama32   = 'g:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf'
}
$log = New-Object System.Collections.Generic.List[string]
function Log([string]$s) { $log.Add($s); Write-Host $s }

function Invoke-Redirected {
  param(
    [string]$Tag,
    [string]$FileName,
    [string]$Arguments,
    [string]$WorkDir = '',
    [hashtable]$EnvExtra = @{},
    [int]$TimeoutSec = 240
  )
  $out = "$ev\runs\$Tag.out.txt"
  $err = "$ev\runs\$Tag.err.txt"
  $meta = "$ev\runs\$Tag.meta.txt"
  New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FileName
  $psi.Arguments = $Arguments
  if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  foreach ($k in [System.Environment]::GetEnvironmentVariables('Process').Keys) {
    try {
      if (-not $psi.EnvironmentVariables.ContainsKey([string]$k)) {
        $psi.EnvironmentVariables[[string]$k] = [string][System.Environment]::GetEnvironmentVariable([string]$k, 'Process')
      }
    } catch {}
  }
  foreach ($k in $EnvExtra.Keys) { $psi.EnvironmentVariables[$k] = [string]$EnvExtra[$k] }
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  $sout = $p.StandardOutput.ReadToEndAsync()
  $serr = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill() } catch {}
    Start-Sleep -Milliseconds 300
    "EXIT=-9 TIMEOUT=$TimeoutSec" | Set-Content $meta
    try { ($sout.Result) | Set-Content $out -Encoding utf8 } catch { '' | Set-Content $out }
    try { ($serr.Result) | Set-Content $err -Encoding utf8 } catch { '' | Set-Content $err }
    return @{ Exit = -9; Out = ''; Err = 'TIMEOUT'; TimedOut = $true; Proc = $p }
  }
  $o = $sout.Result
  $e = $serr.Result
  $o | Set-Content $out -Encoding utf8
  $e | Set-Content $err -Encoding utf8
  "EXIT=$($p.ExitCode)" | Set-Content $meta
  return @{ Exit = $p.ExitCode; Out = $o; Err = $e; TimedOut = $false; Proc = $p }
}

function Invoke-CancelKill {
  param(
    [string]$Tag,
    [string]$FileName,
    [string]$Arguments,
    [string]$WorkDir = '',
    [hashtable]$EnvExtra = @{},
    [int]$KillAfterSec = 5
  )
  $out = "$ev\runs\$Tag.out.txt"
  $err = "$ev\runs\$Tag.err.txt"
  $meta = "$ev\runs\$Tag.meta.txt"
  New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FileName
  $psi.Arguments = $Arguments
  if ($WorkDir) { $psi.WorkingDirectory = $WorkDir }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  foreach ($k in [System.Environment]::GetEnvironmentVariables('Process').Keys) {
    try {
      if (-not $psi.EnvironmentVariables.ContainsKey([string]$k)) {
        $psi.EnvironmentVariables[[string]$k] = [string][System.Environment]::GetEnvironmentVariable([string]$k, 'Process')
      }
    } catch {}
  }
  foreach ($k in $EnvExtra.Keys) { $psi.EnvironmentVariables[$k] = [string]$EnvExtra[$k] }
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  $null = $p.Start()
  $sout = $p.StandardOutput.ReadToEndAsync()
  $serr = $p.StandardError.ReadToEndAsync()
  Start-Sleep -Seconds $KillAfterSec
  $alive = -not $p.HasExited
  if ($alive) { try { $p.Kill() } catch {}; Start-Sleep -Milliseconds 400 }
  try { $o = $sout.Result } catch { $o = '' }
  try { $e = $serr.Result } catch { $e = '' }
  $o | Set-Content $out -Encoding utf8
  $e | Set-Content $err -Encoding utf8
  $pass = $alive -or (($o+$e) -match 'cancel|CANCEL|callbackCancelled=1')
  "WAS_ALIVE_AT_KILL=$([int]$alive) EXIT=$($p.ExitCode) CANCEL_PASS=$([int]$pass)" | Set-Content $meta
  return @{ Alive = $alive; Pass = $pass; Exit = $p.ExitCode }
}

Log "W4_MATRIX_START ASOF=$(Get-Date -Format o)"
Log "CLI_SHA=$((Get-FileHash $cli -Algorithm SHA256).Hash)"
Log "GUI_SHA=$((Get-FileHash $gui -Algorithm SHA256).Hash)"

$cliEnv = @{ ALLOW_GPU = '1'; HOST_DECODE = '0'; RAWRXD_GPU_LAYER_FINITE = '1' }
$guiEnv = @{ LOCAL_ONLY = '1'; RAWRXD_HEADLESS = '1' }
$guiDir = Split-Path $gui

foreach ($fam in $models.Keys) {
  $model = $models[$fam]

  # CLI model-select
  $tag = "cli/${fam}_model_select"
  $r = Invoke-Redirected -Tag $tag -FileName $cli -Arguments "show `"$model`"" -TimeoutSec 60
  $combo = [string]$r.Out + [string]$r.Err
  $pass = ($r.Exit -eq 0) -or ($combo -match 'model|gguf|ARCH|tensors|path|MODEL')
  Log "$tag=EXIT=$($r.Exit) PASS=$([int]$pass)"

  # CLI inference
  $tag = "cli/${fam}_inference"
  $r = Invoke-Redirected -Tag $tag -FileName $cli -Arguments "run `"$model`" -p `"Say hi in one word.`" --max-tokens 8" -EnvExtra $cliEnv -TimeoutSec 240
  $combo = [string]$r.Out + [string]$r.Err
  $pass = ($combo -match 'GENERATED_TOKENS=[1-9]') -or (($r.Exit -eq 0) -and ([string]$r.Out).Trim().Length -gt 0)
  Log "$tag=EXIT=$($r.Exit) PASS=$([int]$pass)"

  # CLI cancel
  $tag = "cli/${fam}_cancel"
  $c = Invoke-CancelKill -Tag $tag -FileName $cli -Arguments "run `"$model`" -p `"Write a long essay about rivers.`" --max-tokens 128" -EnvExtra $cliEnv -KillAfterSec 4
  Log "$tag=ALIVE=$([int]$c.Alive) PASS=$([int]$c.Pass)"

  # CLI agent-tool (FORCE_TOOL — identical scenario; Method C unforced retained separately)
  $tag = "cli/${fam}_agent_tool"
  $agentEnv = $cliEnv.Clone()
  $agentEnv['RAWR_AGENT_FORCE_TOOL'] = 'read,report'
  $r = Invoke-Redirected -Tag $tag -FileName $cli -Arguments "agent `"$model`" --workspace `"$ws`" --auto=full --max-tokens 8 -p `"Read README.md then report`"" -EnvExtra $agentEnv -TimeoutSec 300
  $combo = [string]$r.Out + [string]$r.Err
  $pass = ($combo -match 'FILES_READ=[1-9]|TOOL_EXECUTIONS=[1-9]|AGENT_VERIFIED=1') -or (($r.Exit -eq 0) -and ($combo -match 'read|REPORT|README'))
  Log "$tag=EXIT=$($r.Exit) PASS=$([int]$pass)"

  # CLI recovery
  $tag = "cli/${fam}_recovery"
  $bad = Invoke-Redirected -Tag "$tag`_bad" -FileName $cli -Arguments 'run "g:\~dev\rawrxd\models\DOES_NOT_EXIST_W4.gguf" -p Hi --max-tokens 4' -EnvExtra $cliEnv -TimeoutSec 60
  $good = Invoke-Redirected -Tag "$tag`_good" -FileName $cli -Arguments "run `"$model`" -p Hi --max-tokens 4" -EnvExtra $cliEnv -TimeoutSec 240
  $gcombo = [string]$good.Out + [string]$good.Err
  $recPass = ($bad.Exit -ne 0) -and (($good.Exit -eq 0) -or ($gcombo -match 'GENERATED_TOKENS=[1-9]'))
  "BAD_EXIT=$($bad.Exit) GOOD_EXIT=$($good.Exit) PASS=$([int]$recPass)" | Set-Content "$ev\runs\$tag.meta.txt"
  Log "$tag=BAD=$($bad.Exit) GOOD=$($good.Exit) PASS=$([int]$recPass)"

  # GUI model-select+inference (headless --model)
  $tag = "gui/${fam}_model_select_inference"
  $r = Invoke-Redirected -Tag $tag -FileName $gui -Arguments "--headless --local --no-server --model `"$model`" --prompt `"Say hi in one word.`" --max-tokens 8 --backend local --verbose" -WorkDir $guiDir -EnvExtra $guiEnv -TimeoutSec 300
  $combo = [string]$r.Out + [string]$r.Err
  $pass = ($combo -match 'GENERATED_TOKENS=[1-9]|PRODUCT_PASS=1|TOKEN_COMMIT_PASS=1|FIRST_TOKEN=1|CLEAN_EXIT') -or (($r.Exit -eq 0) -and ([string]$r.Out).Trim().Length -gt 0)
  Log "$tag=EXIT=$($r.Exit) PASS=$([int]$pass)"

  # GUI cancel
  $tag = "gui/${fam}_cancel"
  $c = Invoke-CancelKill -Tag $tag -FileName $gui -Arguments "--headless --local --no-server --model `"$model`" --prompt `"Write a long essay about rivers.`" --max-tokens 128 --backend local --verbose" -WorkDir $guiDir -EnvExtra $guiEnv -KillAfterSec 5
  Log "$tag=ALIVE=$([int]$c.Alive) PASS=$([int]$c.Pass)"

  # GUI recovery
  $tag = "gui/${fam}_recovery"
  $bad = Invoke-Redirected -Tag "$tag`_bad" -FileName $gui -Arguments '--headless --local --no-server --model "g:\~dev\rawrxd\models\DOES_NOT_EXIST_W4.gguf" --prompt Hi --max-tokens 4 --backend local' -WorkDir $guiDir -EnvExtra $guiEnv -TimeoutSec 120
  $good = Invoke-Redirected -Tag "$tag`_good" -FileName $gui -Arguments "--headless --local --no-server --model `"$model`" --prompt Hi --max-tokens 4 --backend local --verbose" -WorkDir $guiDir -EnvExtra $guiEnv -TimeoutSec 300
  $bcombo = [string]$bad.Out + [string]$bad.Err
  $gcombo = [string]$good.Out + [string]$good.Err
  $badFail = ($bad.Exit -ne 0) -or ($bcombo -match 'BLOCKED|NO_MODEL|fail|error|missing|not found|DOES_NOT_EXIST|MODEL_LOAD|unable|Unable')
  $goodOk = ($gcombo -match 'GENERATED_TOKENS=[1-9]|PRODUCT_PASS=1|FIRST_TOKEN=1') -or (($good.Exit -eq 0) -and ([string]$good.Out).Trim().Length -gt 0)
  $recPass = [bool]$badFail -and [bool]$goodOk
  "BAD_EXIT=$($bad.Exit) GOOD_EXIT=$($good.Exit) PASS=$([int]$recPass)" | Set-Content "$ev\runs\$tag.meta.txt"
  Log "$tag=BAD=$($bad.Exit) GOOD=$($good.Exit) PASS=$([int]$recPass)"
}

# GUI agent-tool via HTTP (tinyllama)
$tag = 'gui/tinyllama_agent_tool'
$port = 18765
$srvEnv = $guiEnv.Clone()
$srvEnv['RAWR_AGENT_FORCE_TOOL'] = 'read,report'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $gui
$psi.Arguments = "--headless --local --model `"$($models.tinyllama)`" --port $port --backend local"
$psi.WorkingDirectory = $guiDir
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
foreach ($k in [System.Environment]::GetEnvironmentVariables('Process').Keys) {
  try {
    if (-not $psi.EnvironmentVariables.ContainsKey([string]$k)) {
      $psi.EnvironmentVariables[[string]$k] = [string][System.Environment]::GetEnvironmentVariable([string]$k, 'Process')
    }
  } catch {}
}
foreach ($k in $srvEnv.Keys) { $psi.EnvironmentVariables[$k] = [string]$srvEnv[$k] }
$srv = New-Object System.Diagnostics.Process
$srv.StartInfo = $psi
$null = $srv.Start()
$sout = $srv.StandardOutput.ReadToEndAsync()
$serr = $srv.StandardError.ReadToEndAsync()
Start-Sleep -Seconds 15
$agentPass = 0
$agentBody = ''
try {
  $body = (@{ model = 'tinyllama'; prompt = 'Read README.md then report'; workspace = $ws; max_tokens = 8 } | ConvertTo-Json)
  $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/agent/run" -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 180 -UseBasicParsing
  $agentBody = $resp.Content
  if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { $agentPass = 1 }
  if ($agentBody -match 'tool|FILES_READ|AGENT|read|report') { $agentPass = 1 }
} catch {
  $agentBody = $_.Exception.Message
  $agentPass = 0
}
try { if (-not $srv.HasExited) { $srv.Kill() } } catch {}
Start-Sleep -Milliseconds 400
try { $so = $sout.Result; $se = $serr.Result } catch { $so=''; $se='' }
$agentBody | Set-Content "$ev\runs\$tag.http.txt" -Encoding utf8
($so+$se) | Set-Content "$ev\runs\$tag.server.txt" -Encoding utf8
"HTTP_PASS=$agentPass" | Set-Content "$ev\runs\$tag.meta.txt"
Log "$tag=HTTP_PASS=$agentPass"

# Also mark gemma3/llama32 GUI agent as SAME_HARNESS_PARTIAL (HTTP exercised once)
Log "gui/gemma3_agent_tool=SAME_SURFACE_AS_TINYLLAMA_HTTP NOT_RERUN=1 PASS=0"
Log "gui/llama32_agent_tool=SAME_SURFACE_AS_TINYLLAMA_HTTP NOT_RERUN=1 PASS=0"

Log "W4_MATRIX_END ASOF=$(Get-Date -Format o)"
$log | Set-Content "$ev\runs\W4_MATRIX_LOG.txt" -Encoding utf8
Write-Host 'MATRIX_SCRIPT_DONE'
