#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackageDirectory,
      [Parameter(Mandatory = $true)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a new evidence directory.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$root = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start(); $port = $listener.LocalEndpoint.Port; $listener.Stop()
$stdout = Join-Path $root 'fixture.stdout.log'
$stderr = Join-Path $root 'fixture.stderr.log'
$python = (Get-Command py.exe -ErrorAction Stop).Source
$server = Start-Process -FilePath $python -ArgumentList @(
    ('"' + (Join-Path $PSScriptRoot 'agent_protocol_fixture.py') + '"'), '--port', $port) `
    -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
$priorEndpoint = $env:RAWRXD_OLLAMA_ENDPOINT
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; ++$attempt) {
        if ($server.HasExited) { throw 'Protocol fixture server failed to start.' }
        if ((Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue) -match 'READY') { $ready = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw 'Protocol fixture did not become ready.' }
    $env:RAWRXD_OLLAMA_ENDPOINT = 'http://127.0.0.1:' + $port
    & (Join-Path $PSScriptRoot 'Test-AgentWorkflow.ps1') -PackageDirectory $PackageDirectory `
        -EvidenceDirectory (Join-Path $root 'run') -Model 'fixture-protocol' -ProtocolFixture
    if ($LASTEXITCODE -ne 0) { throw 'Protocol regression failed.' }
} finally {
    $env:RAWRXD_OLLAMA_ENDPOINT = $priorEndpoint
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
