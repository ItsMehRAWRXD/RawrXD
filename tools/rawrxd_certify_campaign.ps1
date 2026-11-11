# Reproducible multi-task autonomous repair campaign.
param(
    [Parameter(Mandatory=$true)][string]$Model,
    [Parameter(Mandatory=$true)][string]$LoopExe,
    [string]$Root = "F:\RawrXD\certification_campaign",
    [int]$Count = 10,
    [int]$MaxSteps = 12,
    [int]$MaxNew = 200,
    [int]$TimeoutSec = 3600,
    [switch]$Cpu
)
$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "deep2_autonomous_repair.ps1"
if (-not (Test-Path -LiteralPath $script)) { throw "repair harness missing: $script" }
if (-not (Test-Path -LiteralPath $LoopExe)) { throw "loop executable missing: $LoopExe" }
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$defects = @("sign_flip", "off_by_one", "wrong_operator")
$results = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $Count; ++$i) {
    $id = "task_{0:D3}" -f ($i + 1)
    $work = Join-Path $Root (Join-Path $id "workspace")
    $evidence = Join-Path $Root (Join-Path $id "evidence")
    $defect = $defects[$i % $defects.Count]
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $exitCode = 0
    try {
        $common = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script,
            '-Model',$Model,'-LoopExe',$LoopExe,'-Workdir',$work,'-Evidence',$evidence,
            '-Defect',$defect,'-MaxSteps',"$MaxSteps",'-MaxNew',"$MaxNew",'-TimeoutSec',"$TimeoutSec")
        if ($Cpu) { & powershell.exe @common -Cpu }
        else { & powershell.exe @common }
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 2
    }
    $sw.Stop()
    $receiptPath = Join-Path $evidence "AUTONOMOUS_REPAIR_RECEIPT.txt"
    $pass = (Test-Path -LiteralPath $receiptPath) -and ((Get-Content -Raw -LiteralPath $receiptPath) -match "FINAL_VERDICT=PASS") -and ($exitCode -eq 0)
    $results.Add([pscustomobject]@{
        id = $id; defect = $defect; pass = $pass; exit_code = $exitCode
        elapsed_ms = $sw.ElapsedMilliseconds; receipt = $receiptPath
    })
}
$passed = @($results | Where-Object pass).Count
$report = [pscustomobject]@{
    schema = "RAWRXD_CERTIFICATION_CAMPAIGN_V1"; model = $Model; count = $Count
    passed = $passed; failed = $Count - $passed; pass_rate = if ($Count) { $passed / $Count } else { 0 }
    results = $results; completed_utc = [DateTime]::UtcNow.ToString("o")
}
$out = Join-Path $Root "campaign_receipt.json"
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding utf8
Write-Host ("CAMPAIGN_RECEIPT path={0} passed={1} failed={2} pass_rate={3:P1}" -f $out,$passed,($Count-$passed),$report.pass_rate)
if ($passed -ne $Count) { exit 1 }
exit 0
