# Swarm Path A retry on frozen candidate after RUNTIME_READY (swarm-first)
$ErrorActionPreference = "Continue"
$Seal = "G:\~dev\rawrxd\evidence\AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001"
$Logs = Join-Path $Seal "logs\swarm_retry"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = "G:\~dev\rawrxd\evidence\TIP_CANDIDATE_AGENT_RUN_005\bin\RawrXD-Win32IDE.exe"
$ExpectCand = "8DC1406A0118AC6A2F6A1E991378A2730AAC07D5593BA3C9BF5E8852E468235B"
$Port = 18998
$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectCand) { throw "CANDIDATE_SHA_DRIFT $sha" }
"SHA=$sha" | Set-Content (Join-Path $Logs "exe_sha.txt")

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

$key = "swarmretry-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_WEIGHT_BUDGET_MIB = "E8B0M"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"

$stdout = Join-Path $Logs "srv_out.txt"
$stderr = Join-Path $Logs "srv_err.txt"
$p = Start-Process -FilePath $CandExe -WorkingDirectory (Split-Path $CandExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -WindowStyle Hidden

$ready = $false
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { break }
  if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { $ready = $true; break }
  Start-Sleep -Milliseconds 300
}
"PID=$($p.Id) PORT_READY=$ready EXITED=$($p.HasExited)" | Tee-Object -FilePath (Join-Path $Logs "srv_meta.txt")
if (-not $ready) { throw "NOT_READY" }

$auth = "http://127.0.0.1:$Port"
(@{ modelPath = $Model } | ConvertTo-Json -Compress) | Set-Content (Join-Path $Logs "req_load.json") -NoNewline
$loadOut = Join-Path $Logs "load.body.txt"
$cLoad = & curl.exe -sS -o $loadOut -w "%{http_code}" -X POST "http://127.0.0.1:$Port/api/model/load" `
  -H "Content-Type: application/json" -H "Origin: $auth" -H "X-Api-Key: $key" `
  --data-binary "@$(Join-Path $Logs 'req_load.json')" --max-time 300
"LOAD_HTTP=$cLoad" | Tee-Object -FilePath (Join-Path $Logs "load.meta.txt")

$rr = $false
for ($i = 0; $i -lt 90; $i++) {
  if ($p.HasExited) { break }
  $err = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
  if ($err -match "RUNTIME_READY\s*=\s*1") { $rr = $true; break }
  Start-Sleep 1
}
"RUNTIME_READY=$([int]$rr)" | Tee-Object -FilePath (Join-Path $Logs "runtime_ready.txt")

$swarmReq = Join-Path $Logs "req_swarm.json"
[System.IO.File]::WriteAllText($swarmReq, '{"n":2,"input":"int main(){ return 0; }\n","cleanup":true}')
$swarmBody = Join-Path $Logs "swarm.body.txt"
$swarmHdr = Join-Path $Logs "swarm.hdr.txt"
$swarmCurlErr = Join-Path $Logs "swarm.curl_err.txt"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "curl.exe"
$psi.Arguments = "-sS -D `"$swarmHdr`" -o `"$swarmBody`" -w `"%{http_code}`" -X POST `"http://127.0.0.1:$Port/api/swarm/orch`" -H `"Content-Type: application/json`" -H `"Origin: $auth`" -H `"X-Api-Key: $key`" --data-binary `"@$swarmReq`" --max-time 420"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$cp = [System.Diagnostics.Process]::Start($psi)
$stdoutCurl = $cp.StandardOutput.ReadToEnd()
$stderrCurl = $cp.StandardError.ReadToEnd()
$cp.WaitForExit(420000) | Out-Null
$cOrch = $stdoutCurl.Trim()
$stderrCurl | Set-Content $swarmCurlErr
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
$bodyPreview = ""
if (Test-Path $swarmBody) {
  $raw = Get-Content $swarmBody -Raw -ErrorAction SilentlyContinue
  if ($raw) { $bodyPreview = $raw.Substring(0, [Math]::Min(800, $raw.Length)) }
}
$noEngine = [int]([bool]($bodyPreview -match "No Inference Engine"))
$noModel = [int]([bool]($bodyPreview -match "No model loaded"))
@"
ORCH_HTTP=$cOrch
ALIVE=$([int]$alive)
NO_INFERENCE_ENGINE=$noEngine
NO_MODEL_LOADED=$noModel
CURL_ERR=$stderrCurl
BODY_PREVIEW=$bodyPreview
"@ | Set-Content (Join-Path $Logs "swarm.meta.txt")
Write-Output "SWARM_HTTP=$cOrch ALIVE=$alive NO_ENGINE=$noEngine NO_MODEL=$noModel"
Write-Output $bodyPreview

if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep 1
