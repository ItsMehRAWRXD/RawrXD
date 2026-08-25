# RawrXD OMEGA-1 Manifest Generator (Minimal)
param(
    [string]$BinaryPath = "",
    [string]$OutputPath = ""
)
$manifest = @{
    SchemaVersion = '1.0.0-OMEGA'
    Timestamp = [DateTime]::UtcNow.ToString('o')
    BinaryPath = $BinaryPath
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "OMEGA-1 manifest generated: $OutputPath"
