# Fresh process, STREAMABLE wait, n=2 only (no prior n=1)
$ErrorActionPreference = "Continue"
$Logs = "G:\~dev\rawrxd\evidence\AGENT_RUN_LOOP_CANDIDATE_8DC1406A_001\logs\swarm_n2_fresh"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = "G:\~dev\rawrxd\evidence\TIP_CANDIDATE_AGENT_RUN_005\bin\RawrXD-Win32IDE.exe"
$Expect = "8DC1406A0118AC6A2F6A1E991378A2730AAC07D5593BA3C9BF5E8852E468235B"
$Port = 19002
$Model = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
if ($sha -ne $Expect) { throw "SHA_DRIFT" }

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 3
$key = "swn2-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$env:RAWRXD_HOSTED_API_KEY = $key
$env:RAWRXD_HOSTED_API_SCOPES = "read,inference,models,github,admin,*"
$env:RAWRXD_HEADLESS = "1"
$env:LOCAL_ONLY = "1"
$env:RAWRXD_WEIGHT_BUDGET_MIB = "E8B0M"
$env:RAWRXD_MODELS = "G:\~dev\rawrxd\models"
$p = Start-Process -FilePath $CandExe -WorkingDirectory (Split-Path $CandExe) `
  -ArgumentList @("--headless","--local","--port","$Port","--bind","127.0.0.1","--dir","G:\~dev\rawrxd") `
  -RedirectStandardOutput "$Logs\out.txt" -RedirectStandardError "$Logs\err.txt" `
  -PassThru -WindowStyle Hidden
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { break }
  if (netstat -ano | Select-String ":$Port\s+.*LISTENING") { break }
  Start-Sleep -Milliseconds 300
}
$auth = "http://127.0.0.1:$Port"
[System.IO.File]::WriteAllText("$Logs\load.json", (@{ modelPath = $Model } | ConvertTo-Json -Compress))
$cLoad = & curl.exe -sS -o "$Logs\load.body" -w "%{http_code}" -X POST "$auth/api/model/load" `
  -H "Content-Type: application/json" -H "Origin: $auth" -H "X-Api-Key: $key" `
  --data-binary "@$Logs\load.json" --max-time 300
for ($i = 0; $i -lt 120; $i++) {
  if ($p.HasExited) { break }
  $e = Get-Content "$Logs\err.txt" -Raw -ErrorAction SilentlyContinue
  if ($e -match "OPEN_SEMANTIC=STREAMABLE" -and $e -match "PRODUCT_OPEN SESSION_EXIT ok=1") { break }
  Start-Sleep 1
}
Start-Sleep 3
[System.IO.File]::WriteAllText("$Logs\n2.json", '{"n":2,"input":"int main(){ return 0; }\n","cleanup":true}')
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "curl.exe"
$psi.Arguments = "-sS -D `"$Logs\n2.hdr`" -o `"$Logs\n2.body`" -w `"%{http_code}`" -X POST `"$auth/api/swarm/orch`" -H `"Content-Type: application/json`" -H `"Origin: $auth`" -H `"X-Api-Key: $key`" --data-binary `"@$Logs\n2.json`" --max-time 420"
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$cp = [System.Diagnostics.Process]::Start($psi)
$so = $cp.StandardOutput.ReadToEnd()
$se = $cp.StandardError.ReadToEnd()
[void]$cp.WaitForExit(420000)
$se | Set-Content "$Logs\n2.err"
$c2 = $so.Trim()
$alive = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
$b = ""; if (Test-Path "$Logs\n2.body") { $b = Get-Content "$Logs\n2.body" -Raw -EA SilentlyContinue }
$noEng = [int]([bool]($b -match "No Inference Engine"))
$noModel = [int]([bool]($b -match "No model loaded"))
@"
LOAD=$cLoad
N2_HTTP=$c2
ALIVE=$([int]$alive)
NO_INFERENCE_ENGINE=$noEng
NO_MODEL_LOADED=$noModel
CURL_ERR=$se
BODY=$b
"@ | Set-Content "$Logs\meta.txt"
Write-Output "N2=$c2 ALIVE=$alive NO_ENGINE=$noEng NO_MODEL=$noModel LEN=$($b.Length)"
if ($b) { Write-Output $b.Substring(0, [Math]::Min(600, $b.Length)) }
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
