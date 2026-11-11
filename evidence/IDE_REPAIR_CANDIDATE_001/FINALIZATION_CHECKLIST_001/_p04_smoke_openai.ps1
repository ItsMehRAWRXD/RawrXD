$ErrorActionPreference = "Continue"
$ev = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001"
$exe = "F:\rawrxd\build_deep2_openai_001\bin\deep2_openai_server.exe"
$model = "F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$stdout = "$ev\_p04_openai_serve_stdout2.txt"
$stderr = "$ev\_p04_openai_serve_stderr2.txt"
$pidfile = "$ev\_p04_openai_serve_pid2.txt"
Remove-Item $stdout,$stderr,$pidfile -ErrorAction SilentlyContinue

$p = Start-Process -FilePath $exe -ArgumentList @("--model",$model,"--port","11436") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
Set-Content $pidfile "PID=$($p.Id)`nPATH=$exe"
Write-Host "STARTED_PID=$($p.Id)"

$listenLine = $false
$healthOk = $false
$healthCode = 0
$healthBody = ""
$netstatHit = ""
$deadline = (Get-Date).AddMinutes(4)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { Write-Host "EARLY_EXIT=$($p.ExitCode)"; break }
  if (Test-Path $stderr) {
    $all = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
    if ($all -match "Server listening on|D2LOAD_S08_LISTEN_PASS") {
      $listenLine = $true
      Write-Host "STDERR_LISTEN_MARKER=1"
      Start-Sleep -Seconds 1
      $netstatHit = (netstat -ano | Select-String "11436" | Out-String).Trim()
      Write-Host "NETSTAT=$netstatHit"
      try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:11436/health" -UseBasicParsing -TimeoutSec 8
        $healthCode = [int]$resp.StatusCode
        $healthBody = [string]$resp.Content
        $healthOk = ($healthCode -eq 200)
        Write-Host "HEALTH_CODE=$healthCode BODY=$healthBody"
      } catch {
        Write-Host "HEALTH_ERR=$($_.Exception.Message)"
      }
      break
    }
  }
  Start-Sleep -Seconds 2
}

$modelsBody = ""
$modelsCode = 0
if ($healthOk) {
  try {
    $m = Invoke-WebRequest -Uri "http://127.0.0.1:11436/v1/models" -UseBasicParsing -TimeoutSec 8
    $modelsCode = [int]$m.StatusCode
    $modelsBody = [string]$m.Content
    Write-Host "MODELS_CODE=$modelsCode BODY=$modelsBody"
  } catch { Write-Host "MODELS_ERR=$($_.Exception.Message)" }
}

if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}
Write-Host "STOPPED_PID=$($p.Id) EXITED=$($p.HasExited)"
@(
  "LISTEN_STDERR_MARKER=$listenLine",
  "NETSTAT=$netstatHit",
  "HEALTH_OK=$healthOk",
  "HEALTH_CODE=$healthCode",
  "HEALTH_BODY=$healthBody",
  "MODELS_CODE=$modelsCode",
  "MODELS_BODY=$modelsBody",
  "PID=$($p.Id)",
  "EXE=$exe",
  "SHA256=FA42C75BA6762BF0C0248D23718D4535E028B3010B5F9CFD3BA52FE02CBAA97B",
  "PROMOTE=0",
  "GENERATION_NOT_CLAIMED=1"
) | Set-Content "$ev\_p04_openai_smoke2.txt"
Get-Content "$ev\_p04_openai_smoke2.txt"
