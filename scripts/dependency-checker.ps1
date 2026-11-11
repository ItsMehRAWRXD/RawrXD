# RawrXD Dependency Checker
# Checks and validates all dependencies

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Check", "Install", "List", "Export")]
    [string]$Action = "Check",
    
    [ValidateSet("Build", "Runtime", "Development", "All")]
    [string]$Category = "All",
    
    [string]$ExportPath = "",
    [switch]$AutoInstall,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

$script:Dependencies = @{
    Build = @(
        @{ Name = "CMake"; Command = "cmake"; MinVersion = "3.16.0"; Required = $true; InstallHelp = "https://cmake.org/download/" },
        @{ Name = "Git"; Command = "git"; MinVersion = "2.25.0"; Required = $true; InstallHelp = "https://git-scm.com/download/win" },
        @{ Name = "Ninja"; Command = "ninja"; MinVersion = "1.10.0"; Required = $false; InstallHelp = "pip install ninja" },
        @{ Name = "Visual Studio"; Command = "cl"; MinVersion = "16.0"; Required = $true; InstallHelp = "https://visualstudio.microsoft.com/downloads/" }
    )
    Runtime = @(
        @{ Name = "CUDA"; Command = "nvcc"; MinVersion = "11.0"; Required = $false; InstallHelp = "https://developer.nvidia.com/cuda-downloads" },
        @{ Name = "Vulkan"; Command = "vulkaninfo"; MinVersion = "1.2.0"; Required = $false; InstallHelp = "https://vulkan.lunarg.com/sdk/home" },
        @{ Name = "Python"; Command = "python"; MinVersion = "3.8.0"; Required = $true; InstallHelp = "https://www.python.org/downloads/" }
    )
    Development = @(
        @{ Name = "Docker"; Command = "docker"; MinVersion = "20.10.0"; Required = $false; InstallHelp = "https://docs.docker.com/desktop/install/windows/" },
        @{ Name = "Node.js"; Command = "node"; MinVersion = "16.0.0"; Required = $false; InstallHelp = "https://nodejs.org/" },
        @{ Name = "PowerShell"; Command = "powershell"; MinVersion = "5.1"; Required = $true; InstallHelp = "https://docs.microsoft.com/powershell/" }
    )
}

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    Checked = @()
    Missing = @()
    Outdated = @()
    Installed = @()
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Get-CommandVersion {
    param([string]$Command)
    
    try {
        $versionOutput = $null
        
        switch ($Command) {
            "cmake" { $versionOutput = & cmake --version 2>$null | Select-Object -First 1 }
            "git" { $versionOutput = & git --version 2>$null }
            "python" { $versionOutput = & python --version 2>$null }
            "node" { $versionOutput = & node --version 2>$null }
            "docker" { $versionOutput = & docker --version 2>$null }
            "nvcc" { $versionOutput = & nvcc --version 2>$null | Select-String "release" }
            "ninja" { $versionOutput = & ninja --version 2>$null }
            "powershell" { return $PSVersionTable.PSVersion.ToString() }
            "cl" { 
                $versionOutput = & cl 2>&1 | Select-Object -First 1
                if ($versionOutput -match "Version (\d+\.\d+)") {
                    return $matches[1]
                }
            }
            "vulkaninfo" { 
                $versionOutput = & vulkaninfo --summary 2>$null | Select-String "Vulkan Instance Version"
                if ($versionOutput -match "(\d+\.\d+\.\d+)") {
                    return $matches[1]
                }
            }
        }
        
        if ($versionOutput -match "(\d+\.\d+(\.\d+)?)") {
            return $matches[1]
        }
    }
    catch {
        return $null
    }
    
    return $null
}

function Compare-Versions {
    param([string]$Current, [string]$Required)
    
    if (-not $Current -or -not $Required) {
        return $false
    }
    
    try {
        $currentVersion = [System.Version]$Current
        $requiredVersion = [System.Version]$Required
        return $currentVersion -ge $requiredVersion
    }
    catch {
        # Fallback to string comparison
        return $Current -ge $Required
    }
}

function Test-Dependency {
    param([hashtable]$Dependency)
    
    $result = [PSCustomObject]@{
        Name = $Dependency.Name
        Command = $Dependency.Command
        Required = $Dependency.Required
        MinVersion = $Dependency.MinVersion
        CurrentVersion = $null
        Status = "NotInstalled"
        InstallHelp = $Dependency.InstallHelp
    }
    
    $commandPath = Get-Command $Dependency.Command -ErrorAction SilentlyContinue
    
    if ($commandPath) {
        $result.CurrentVersion = Get-CommandVersion -Command $Dependency.Command
        
        if ($result.CurrentVersion) {
            $versionOk = Compare-Versions -Current $result.CurrentVersion -Required $Dependency.MinVersion
            if ($versionOk) {
                $result.Status = "Installed"
            } else {
                $result.Status = "Outdated"
            }
        } else {
            $result.Status = "Installed"
        }
    }
    
    return $result
}

function Invoke-DependencyCheck {
    Write-Status "Checking dependencies..."
    
    $categoriesToCheck = if ($Category -eq "All") { @("Build", "Runtime", "Development") } else { @($Category) }
    
    foreach ($cat in $categoriesToCheck) {
        Write-Host ""
        Write-Host "[$cat Dependencies]" -ForegroundColor Cyan
        Write-Host "-------------------" -ForegroundColor Cyan
        
        foreach ($dep in $script:Dependencies[$cat]) {
            $result = Test-Dependency -Dependency $dep
            $script:Results.Checked += $result
            
            switch ($result.Status) {
                "Installed" {
                    $script:Results.Installed += $result
                    Write-Success "$($result.Name) $($result.CurrentVersion)"
                }
                "Outdated" {
                    $script:Results.Outdated += $result
                    Write-Warning "$($result.Name) $($result.CurrentVersion) (requires $($result.MinVersion)+)"
                }
                "NotInstalled" {
                    if ($result.Required) {
                        $script:Results.Missing += $result
                        Write-Error "$($result.Name) - REQUIRED but not installed"
                    } else {
                        Write-Warning "$($result.Name) - Optional, not installed"
                    }
                }
            }
        }
    }
}

function Invoke-DependencyInstall {
    Write-Status "Installing missing dependencies..."
    
    foreach ($dep in $script:Results.Missing) {
        if ($dep.Required) {
            Write-Status "Attempting to install $($dep.Name)..."
            
            switch ($dep.Name) {
                "Git" {
                    Write-Warning "Please install Git manually from: $($dep.InstallHelp)"
                }
                "CMake" {
                    Write-Warning "Please install CMake manually from: $($dep.InstallHelp)"
                }
                "Python" {
                    Write-Warning "Please install Python manually from: $($dep.InstallHelp)"
                }
                "Ninja" {
                    try {
                        pip install ninja
                        Write-Success "Ninja installed via pip"
                    }
                    catch {
                        Write-Error "Failed to install Ninja"
                    }
                }
                default {
                    Write-Warning "Please install $($dep.Name) manually from: $($dep.InstallHelp)"
                }
            }
        }
    }
}

function Show-DependencyList {
    Write-Host ""
    Write-Host "RawrXD Dependencies" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($cat in $script:Dependencies.Keys) {
        Write-Host "[$cat]" -ForegroundColor Yellow
        foreach ($dep in $script:Dependencies[$cat]) {
            $required = if ($dep.Required) { "(REQUIRED)" } else { "(optional)" }
            Write-Host "  • $($dep.Name) $required - min version: $($dep.MinVersion)"
        }
        Write-Host ""
    }
}

function Export-DependencyReport {
    if (-not $ExportPath) {
        $ExportPath = "dependencies-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    
    $report = @{
        Timestamp = $script:Results.Timestamp
        Summary = @{
            TotalChecked = $script:Results.Checked.Count
            Installed = $script:Results.Installed.Count
            Outdated = $script:Results.Outdated.Count
            Missing = $script:Results.Missing.Count
        }
        Details = $script:Results.Checked
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File $ExportPath
    Write-Success "Dependency report exported to: $ExportPath"
}

function Show-Summary {
    Write-Host ""
    Write-Host "Dependency Check Summary" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host "Total Checked: $($script:Results.Checked.Count)"
    Write-Host "Installed: $($script:Results.Installed.Count)" -ForegroundColor Green
    Write-Host "Outdated: $($script:Results.Outdated.Count)" -ForegroundColor Yellow
    Write-Host "Missing: $($script:Results.Missing.Count)" -ForegroundColor Red
    
    if ($script:Results.Missing.Count -gt 0) {
        Write-Host ""
        Write-Error "Missing required dependencies. Please install them before proceeding."
        exit 1
    }
    
    if ($script:Results.Outdated.Count -gt 0) {
        Write-Host ""
        Write-Warning "Some dependencies are outdated. Consider updating for best compatibility."
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Dependency Checker" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "Check" {
            Invoke-DependencyCheck
            Show-Summary
        }
        "Install" {
            Invoke-DependencyCheck
            Invoke-DependencyInstall
        }
        "List" {
            Show-DependencyList
        }
        "Export" {
            Invoke-DependencyCheck
            Export-DependencyReport
        }
    }
    
    Write-Host ""
}

Main
