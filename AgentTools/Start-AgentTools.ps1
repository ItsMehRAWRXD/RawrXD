param([int] $Port = 8765)
$scriptPath = Join-Path $PSScriptRoot 'AgentToolsServer.ps1'
Start-Process -FilePath "pwsh" -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"$scriptPath",'-Port',"$Port") -WindowStyle Minimized
Write-Host "Started AgentTools server on port $Port (new window/process)."
