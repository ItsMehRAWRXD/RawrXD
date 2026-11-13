# Install-RawrDevPath.ps1
# Adds build_ninja\bin to the *User* PATH for local CLI discovery.
# Does not install system-wide services, MSI, or winget packages.
# PROMOTE=0 — developer convenience only.

[CmdletBinding()]
param(
    [string]$RepoRoot = "",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
$bin = (Join-Path $RepoRoot "build_ninja\bin")
if (-not (Test-Path -LiteralPath $bin)) {
    Write-Error "Missing $bin — build rawr.exe first (see INSTALL.md)."
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($null -eq $userPath) { $userPath = "" }
$parts = @($userPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" })

if ($Remove) {
    $new = @($parts | Where-Object { $_.TrimEnd("\") -ne $bin.TrimEnd("\") })
    [Environment]::SetEnvironmentVariable("Path", ($new -join ";"), "User")
    Write-Host "REMOVED_FROM_USER_PATH=$bin"
    exit 0
}

$already = $parts | Where-Object { $_.TrimEnd("\") -eq $bin.TrimEnd("\") }
if ($already) {
    Write-Host "ALREADY_ON_USER_PATH=$bin"
} else {
    $parts += $bin
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
    Write-Host "ADDED_TO_USER_PATH=$bin"
}

$env:Path = "$bin;" + $env:Path
Write-Host "SESSION_PATH_PREPEND=1"
Write-Host "Verify: rawr   (new shells pick up User PATH; this session prepended)"
Write-Host "PROMOTE=0 CERTIFIED=0"
