$Script:ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Script:RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:BinDir = Join-Path $RepoRoot 'bin'
$Script:LogDir = Join-Path $RepoRoot 'logs'
$Script:VictimAsm = Join-Path $RepoRoot 'src\debugger\Victim.asm'
$Script:VictimObj = Join-Path $BinDir 'Victim.obj'
$Script:VictimExe = Join-Path $BinDir 'Victim.exe'
$Script:VictimBuildScript = Join-Path $RepoRoot 'build_victim_auto.bat'
$Script:BeaconExe = Join-Path $BinDir 'BeaconDebugger.exe'
$Script:BuildScript = Join-Path $RepoRoot 'FinalBuild_Mingw.bat'
$Script:CmdExe = 'C:\Windows\System32\cmd.exe'
$Script:NodeExe = 'C:\Program Files\nodejs\node.exe'

$Script:Ml64Exe = 'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe'
$Script:LinkExe = 'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe'
$Script:ToolBinDir = 'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64'
$Script:MsvcLibX64 = 'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64'
$Script:SdkLibUmX64 = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64'

${env:PATH} = "$ToolBinDir;$(${env:PATH})"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args,
        [string]$WorkingDirectory = $RepoRoot
    )

    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    Write-Host "$Exe $($Args -join ' ')" -ForegroundColor DarkGray

    Push-Location $WorkingDirectory
    try {
        & $Exe @Args
        if ($LASTEXITCODE -ne 0) {
            throw "$Name failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Send-DapRequest {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$Seq,
        [Parameter(Mandatory = $true)][string]$Command,
        [hashtable]$Arguments = @{}
    )

$Script:payloadObj = [ordered]@{
        seq = $Seq
        type = 'request'
        command = $Command
        arguments = $Arguments
    }

$Script:json = $payloadObj | ConvertTo-Json -Compress -Depth 20
$Script:payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$Script:header = "Content-Length: $($payloadBytes.Length)`r`n`r`n"
$Script:headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)

$Script:stream = $Process.StandardInput.BaseStream
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    $stream.Write($payloadBytes, 0, $payloadBytes.Length)
    $stream.Flush()
}

function Read-DapMessage {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [int]$TimeoutMs = 10000
    )

$Script:reader = $Process.StandardOutput
$Script:watch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($reader.Peek() -lt 0) {
        if ($watch.ElapsedMilliseconds -gt $TimeoutMs) {
            throw "Timed out waiting for DAP header"
        }
    }

$Script:contentLength = 0
    while ($true) {
$Script:line = $reader.ReadLine()
        if ($null -eq $line) {
            throw 'DAP stdout closed while reading header'
        }
        if ($line.Length -eq 0) {
            break
        }
        if ($line.StartsWith('Content-Length:', [System.StringComparison]::OrdinalIgnoreCase)) {
$Script:contentLength = [int]($line.Substring(15).Trim())
        }
    }

    if ($contentLength -le 0) {
        throw 'Invalid Content-Length in DAP header'
    }

$Script:buffer = New-Object char[] $contentLength
$Script:offset = 0
    while ($offset -lt $contentLength) {
$Script:read = $reader.Read($buffer, $offset, $contentLength - $offset)
        if ($read -le 0) {
            throw 'DAP stdout closed while reading body'
        }
        $offset += $read
    }

$Script:json = -join $buffer
    return ($json | ConvertFrom-Json)
}

function Wait-ForDapArtifacts {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedResponseCommand,
        [int]$ExpectedRequestSeq,
        [string]$ExpectedEvent,
        [int]$TimeoutMs = 15000
    )

$Script:response = $null
$Script:eventMsg = $null
$Script:watch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
$Script:msg = Read-DapMessage -Process $Process -TimeoutMs ($TimeoutMs - [int]$watch.ElapsedMilliseconds)

        if ($msg.type -eq 'response' -and $msg.request_seq -eq $ExpectedRequestSeq -and $msg.command -eq $ExpectedResponseCommand) {
$Script:response = $msg
        }
        elseif ($ExpectedEvent -and $msg.type -eq 'event' -and $msg.event -eq $ExpectedEvent) {
$Script:eventMsg = $msg
        }

        if ($response -and (($ExpectedEvent -and $eventMsg) -or (-not $ExpectedEvent))) {
            return @{
                Response = $response
                Event = $eventMsg
            }
        }
    }

    throw "Timed out waiting for DAP response/event for command '$ExpectedResponseCommand'"
}

Invoke-Step -Name 'Build BeaconDebugger (MinGW)' -Exe $CmdExe -Args @('/c', $BuildScript)

if (-not (Test-Path $BeaconExe)) {
    throw "Expected BeaconDebugger binary missing: $BeaconExe"
}

$Script:victimBuildSucceeded = $true
try {
    Invoke-Step -Name 'Build Victim.exe (Batch)' -Exe $CmdExe -Args @('/c', $VictimBuildScript)
}
catch {
$Script:victimBuildSucceeded = $false
    Write-Host "WARN: Victim build failed; validation will continue with fallback target if available." -ForegroundColor Yellow
}

$Script:LaunchTarget = $VictimExe
if (-not (Test-Path $LaunchTarget)) {
$Script:fallbackExe = Join-Path $RepoRoot 'Quick.exe'
    if (-not (Test-Path $fallbackExe)) {
        throw "No launch target available. Missing: $VictimExe and $fallbackExe"
    }

    Write-Host "WARN: Victim.exe not found; using fallback launch target: $fallbackExe" -ForegroundColor Yellow
$Script:LaunchTarget = $fallbackExe
}

Write-Host "`n=== DAP Live Validation ===" -ForegroundColor Cyan
$Script:dapLog = Join-Path $LogDir 'beacon_auto_validation.log'
$Script:liveDriver = Join-Path $RepoRoot 'dap-live-beacon-test.js'
if (-not (Test-Path $liveDriver)) {
    throw "Missing live DAP driver: $liveDriver"
}

if (-not (Test-Path $NodeExe)) {
    throw "Missing Node runtime: $NodeExe"
}

Invoke-Step -Name 'DAP Live Validation (Node Driver)' -Exe $NodeExe -Args @($liveDriver, $BeaconExe, $LaunchTarget, $VictimAsm, $dapLog)

Write-Host "PASS: automated PowerShell validation succeeded" -ForegroundColor Green
Write-Host "Built: $BeaconExe" -ForegroundColor Green
Write-Host "Launch target: $LaunchTarget" -ForegroundColor Green
