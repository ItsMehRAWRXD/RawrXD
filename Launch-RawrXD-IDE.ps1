#!/usr/bin/env pwsh
# RawrXD IDE Launcher
# Minimal launcher for the RawrXD PowerShell IDE

param(
    [string]$WorkspacePath = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    Write-Host "Starting RawrXD IDE..." -ForegroundColor Green
    
    # Import RawrXD engine
    . "$ScriptDir\RawrXD.ps1"
    
    # Launch simple IDE first
    & "$ScriptDir\RawrXD-IDE-Simple.ps1"
}
catch {
    Write-Error "Failed to start RawrXD IDE: $_"
    exit 1
}