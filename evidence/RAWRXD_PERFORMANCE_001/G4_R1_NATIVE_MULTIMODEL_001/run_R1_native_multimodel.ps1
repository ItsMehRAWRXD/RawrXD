# R1 native multi-model E2E: 10 GGUFs, cold-startâ†’loadâ†’genâ†’unloadâ†’reloadâ†’gen, Ollama=0
param(
  [string]$ExePath = "$env:TEMP\G4_LOCALSERVER_PRODUCT_001\RawrXD-Win32IDE.exe",
  [int]$Port = 11435,
  [int]$MaxTokens = 8,
  [int]$LoadTimeoutSec = 1800,
  [int]$GenTimeoutSec = 900,
  [string]$Prompt = "Reply with the single word READY"
)

$ErrorActionPreference = "Stop"
$ev = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G4_R1_NATIVE_MULTIMODEL_001"
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$receipt = Join-Path $ev "RECEIPT.txt"
$matrix = Join-Path $ev "MATRIX.csv"
$lines = [System.Collections.Generic.List[string]]::new()
function Emit([string]$s) { $lines.Add($s); Write-Host $s }

$models = @(
  @{ Id='01_tinyllama'; Path='G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf' },
  @{ Id='02_phi3_mini'; Path='F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf' },
  @{ Id='03_nemotron4b'; Path='F:\OllamaModels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf' },
  @{ Id='04_dsr1_qwen8b'; Path='F:\OllamaModels\DeepSeek-R1-0528-Qwen3-8B-GGUF\DeepSeek-R1-0528-Qwen3-8B-Q4_K_M.gguf' },
  @{ Id='05_gemma4_e4b'; Path='F:\OllamaModels\gemma-4-E4B-it-GGUF\gemma-4-E4B-it-Q4_K_M.gguf' },
  @{ Id='06_phi3_medium'; Path='F:\OllamaModels\Phi-3-medium-128k-instruct-14B-Q4_K_M\Phi-3-medium-128k-instruct-Q4_K_M.gguf' },
  @{ Id='07_codestral22b'; Path='F:\OllamaModels\rawrxd_test_models\Codestral-22B-v0.1-Q4_K_M.gguf' },
  @{ Id='08_qwen25coder14b'; Path='F:\OllamaModels\Qwen2.5-Coder-14B-Instruct-Q8_0\qwen2.5-coder-14b-instruct-q8_0.gguf' },
  @{ Id='09_glm47flash'; Path='F:\OllamaModels\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf' },
  @{ Id='10_gemma4_31b'; Path='F:\OllamaModels\gemma-4-31B-it-GGUF\gemma-4-31B-it-Q4_K_M.gguf' }
)

function Invoke-Http([string]$Method, [string]$Url, [string]$Body = "", [int]$TimeoutSec = 60) {
  $outBody = Join-Path $env:TEMP ("r1_body_" + [guid]::NewGuid().ToString('N') + ".txt")
  $args = @("-sS","--max-time","$TimeoutSec","-o",$outBody,"-w","%{http_code}","-X",$Method)
  if ($Body) { $args += @("-H","Content-Type: application/json","--data-binary",$Body) }
  $args += $Url
  $code = 0
  try { $code = [int](& curl.exe @args) } catch { $code = 0 }
  $text = ""
  if (Test-Path $outBody) { $text = Get-Content -LiteralPath $outBody -Raw -ErrorAction SilentlyContinue; Remove-Item $outBody -Force -ErrorAction SilentlyContinue }
  return @{ Code = $code; Body = $text }
}

function Stop-PortOwner([int]$P) {
  Get-NetTCPConnection -LocalPort $P -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
  }
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

Emit "GATE=G4_R1_NATIVE_MULTIMODEL_001"
Emit "ASOF=$(Get-Date -Format o)"
Emit "EXE=$ExePath"
Emit "PORT=$Port"
Emit "MAX_TOKENS=$MaxTokens"
Emit "PROMPT=$Prompt"
Emit "OLLAMA_POLICY=ZERO_CONTACT"
Emit "PROMOTE=0"
Emit "TIP_CLIMB=HOLD"
Emit "MODEL_COUNT=$($models.Count)"

"Id,Path,Bytes,ColdStart,Listen,Load1,Gen1,Bytes1,Unload1,Load2,Gen2,Bytes2,Unload2,AliveEnd,Contact11434,ExitCode,Verdict" | Set-Content -LiteralPath $matrix -Encoding UTF8

$pass = 0
$fail = 0
$av = 0
$total11434 = 0

foreach ($m in $models) {
  $id = $m.Id
  $path = ($m.Path -replace '\\','/')
  $bytes = 0
  if (Test-Path -LiteralPath $path) { $bytes = (Get-Item -LiteralPath $path).Length }
  Emit ""
  Emit "==== MODEL=$id ===="
  Emit "PATH=$path"
  Emit "BYTES=$bytes"

  $row = [ordered]@{
    Id=$id; Path=$path; Bytes=$bytes
    ColdStart=0; Listen=0; Load1=0; Gen1=0; Bytes1=0; Unload1=0
    Load2=0; Gen2=0; Bytes2=0; Unload2=0
    AliveEnd=0; Contact11434=0; ExitCode=-1; Verdict='FAIL'
  }

  if ($bytes -lt 1MB) {
    Emit "SKIP=missing_or_tiny"
    $row.Verdict = 'SKIP_MISSING'
    $fail++
    "$($row.Id),$($row.Path),$($row.Bytes),$($row.ColdStart),$($row.Listen),$($row.Load1),$($row.Gen1),$($row.Bytes1),$($row.Unload1),$($row.Load2),$($row.Gen2),$($row.Bytes2),$($row.Unload2),$($row.AliveEnd),$($row.Contact11434),$($row.ExitCode),$($row.Verdict)" |
      Add-Content -LiteralPath $matrix
    continue
  }

  Stop-PortOwner $Port
  $work = Join-Path $env:TEMP ("R1_" + $id)
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $stdout = Join-Path $ev "$id.stdout.txt"
  $stderr = Join-Path $ev "$id.stderr.txt"
  Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $p = Start-Process -FilePath $ExePath -ArgumentList @(
      '--headless','--local','--port',"$Port","--max-tokens","$MaxTokens",
      '--dir','G:\~dev\rawrxd'
    ) -WorkingDirectory $work -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $row.ColdStart = 1
  Emit "PID=$($p.Id)"

  $deadline = (Get-Date).AddSeconds(120)
  $listen = $false
  while ((Get-Date) -lt $deadline) {
    if ($p.HasExited) { break }
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -EA SilentlyContinue | Where-Object OwningProcess -eq $p.Id
    if ($c) { $listen = $true; break }
    Start-Sleep -Milliseconds 200
  }
  $row.Listen = [int]$listen
  Emit "LISTEN=$([int]$listen)"
  if (-not $listen) {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
    $row.ExitCode = if ($p.HasExited) { $p.ExitCode } else { -1 }
    if ($row.ExitCode -eq -1073741819 -or $row.ExitCode -eq -1073740940) { $av++; $row.Verdict='FAIL_AV' }
    $fail++
    "$($row.Id),$($row.Path),$($row.Bytes),$($row.ColdStart),$($row.Listen),$($row.Load1),$($row.Gen1),$($row.Bytes1),$($row.Unload1),$($row.Load2),$($row.Gen2),$($row.Bytes2),$($row.Unload2),$($row.AliveEnd),$($row.Contact11434),$($row.ExitCode),$($row.Verdict)" |
      Add-Content -LiteralPath $matrix
    continue
  }

  # wait ready (capabilities 2xx)
  $readyDeadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $readyDeadline) {
    if ($p.HasExited) { break }
    $cap = Invoke-Http 'GET' "http://127.0.0.1:$Port/api/engine/capabilities" '' 10
    if ($cap.Code -ge 200 -and $cap.Code -lt 300) { break }
    Start-Sleep -Milliseconds 300
  }

  function Do-Cycle([string]$tag, [ref]$loadCode, [ref]$genCode, [ref]$genBytes, [ref]$unloadCode) {
    $loadBody = (@{ modelPath = $path } | ConvertTo-Json -Compress)
    $lr = Invoke-Http 'POST' "http://127.0.0.1:$Port/api/model/load" $loadBody $LoadTimeoutSec
    $loadCode.Value = $lr.Code
    Emit ("{0}_LOAD_STATUS={1}" -f $tag, $lr.Code)
    if ($lr.Code -lt 200 -or $lr.Code -ge 300) {
      Emit ("{0}_LOAD_BODY={1}" -f $tag, ($lr.Body.Substring(0, [Math]::Min(300, $lr.Body.Length))))
      $genCode.Value = 0; $genBytes.Value = 0; $unloadCode.Value = 0
      return
    }
    $chatBody = (@{ prompt = $Prompt; message = $Prompt; max_tokens = $MaxTokens } | ConvertTo-Json -Compress)
    $gr = Invoke-Http 'POST' "http://127.0.0.1:$Port/api/chat" $chatBody $GenTimeoutSec
    $genCode.Value = $gr.Code
    $genBytes.Value = if ($gr.Body) { $gr.Body.Length } else { 0 }
    Emit ("{0}_GEN_STATUS={1} BYTES={2}" -f $tag, $gr.Code, $genBytes.Value)
    if ($gr.Body) {
      $snippet = $gr.Body.Substring(0, [Math]::Min(180, $gr.Body.Length)) -replace "`r|`n"," "
      Emit ("{0}_GEN_SNIP={1}" -f $tag, $snippet)
      Set-Content -LiteralPath (Join-Path $ev "$id.$tag.gen.json") -Value $gr.Body -Encoding UTF8
    }
    $ur = Invoke-Http 'POST' "http://127.0.0.1:$Port/api/model/unload" '{}' 60
    $unloadCode.Value = $ur.Code
    Emit ("{0}_UNLOAD_STATUS={1}" -f $tag, $ur.Code)
  }

  $l1=0;$g1=0;$b1=0;$u1=0
  Do-Cycle 'C1' ([ref]$l1) ([ref]$g1) ([ref]$b1) ([ref]$u1)
  $row.Load1=$l1; $row.Gen1=$g1; $row.Bytes1=$b1; $row.Unload1=$u1

  $l2=0;$g2=0;$b2=0;$u2=0
  if (-not $p.HasExited -and $l1 -ge 200 -and $l1 -lt 300) {
    Do-Cycle 'C2' ([ref]$l2) ([ref]$g2) ([ref]$b2) ([ref]$u2)
  }
  $row.Load2=$l2; $row.Gen2=$g2; $row.Bytes2=$b2; $row.Unload2=$u2

  $owned11434 = @(Get-NetTCPConnection -OwningProcess $p.Id -EA SilentlyContinue |
    Where-Object { $_.RemotePort -eq 11434 -or $_.LocalPort -eq 11434 })
  $row.Contact11434 = $owned11434.Count
  $total11434 += $owned11434.Count
  $row.AliveEnd = [int](-not $p.HasExited)

  if (-not $p.HasExited) {
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    Start-Sleep -Seconds 1
  }
  try { $p.Refresh() } catch {}
  $row.ExitCode = if ($null -ne $p.ExitCode) { $p.ExitCode } else { 0 }
  # STATUS_ACCESS_VIOLATION / heap corruption
  if ($row.ExitCode -eq -1073741819 -or $row.ExitCode -eq -1073740940) {
    $av++
    $row.Verdict = 'FAIL_AV'
  } elseif ($row.Listen -eq 1 -and
            $row.Load1 -ge 200 -and $row.Load1 -lt 300 -and
            $row.Gen1 -ge 200 -and $row.Gen1 -lt 300 -and $row.Bytes1 -gt 0 -and
            $row.Unload1 -ge 200 -and $row.Unload1 -lt 300 -and
            $row.Load2 -ge 200 -and $row.Load2 -lt 300 -and
            $row.Gen2 -ge 200 -and $row.Gen2 -lt 300 -and $row.Bytes2 -gt 0 -and
            $row.Unload2 -ge 200 -and $row.Unload2 -lt 300 -and
            $row.Contact11434 -eq 0) {
    $row.Verdict = 'PASS'
    $pass++
  } else {
    $row.Verdict = 'FAIL'
    $fail++
  }
  Emit "VERDICT_$id=$($row.Verdict) EXIT=$($row.ExitCode) CONTACT11434=$($row.Contact11434)"

  "$($row.Id),$($row.Path),$($row.Bytes),$($row.ColdStart),$($row.Listen),$($row.Load1),$($row.Gen1),$($row.Bytes1),$($row.Unload1),$($row.Load2),$($row.Gen2),$($row.Bytes2),$($row.Unload2),$($row.AliveEnd),$($row.Contact11434),$($row.ExitCode),$($row.Verdict)" |
    Add-Content -LiteralPath $matrix
}

Stop-PortOwner $Port

Emit ""
Emit "PASS_COUNT=$pass"
Emit "FAIL_COUNT=$fail"
Emit "AV_COUNT=$av"
Emit "OLLAMA_11434_CONTACT_TOTAL=$total11434"
$gate = ($pass -eq $models.Count) -and ($av -eq 0) -and ($total11434 -eq 0)
Emit ("G4_R1_NATIVE_MULTIMODEL_GATE=" + ($(if ($gate) {'PASS'} else {'FAIL'})))
Emit "R01_REOPENED=0"
Emit "R02_REOPENED=0"
Emit "PROMOTE=0"
Emit "TIP_CLIMB=HOLD"
Emit "MATRIX=$matrix"
Emit "RECEIPT=$receipt"
$lines | Set-Content -LiteralPath $receipt -Encoding UTF8
if (-not $gate) { exit 2 }
exit 0

