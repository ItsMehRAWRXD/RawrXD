<#
.SYNOPSIS
    RawrXD Development Environment Setup Script
    
.DESCRIPTION
    Configures a complete development environment for RawrXD Sovereign Inferencer.
    Installs dependencies, configures build tools, and validates the environment.
    
.PARAMETER InstallPath
    Root installation path for RawrXD dependencies
    
.PARAMETER SkipVS
    Skip Visual Studio detection/installation
    
.PARAMETER SkipVulkan
    Skip Vulkan SDK installation
    
.PARAMETER Force
    Force reinstallation of existing components
    
.EXAMPLE
    .\setup_dev_environment.ps1 -InstallPath "D:\RawrXD-Deps"
    
.EXAMPLE
    .\setup_dev_environment.ps1 -SkipVS -SkipVulkan
#>

[CmdletBinding()]
param(
    [string]$InstallPath = "D:\RawrXD-Deps",
    [switch]$SkipVS,
    [switch]$SkipVulkan,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Configuration
$script:Config = @{
    Version = "1.0.0"
    MinVSVersion = "17.0"
    MinCMakeVersion = "3.20.0"
    MinPythonVersion = "3.9.0"
    VulkanSDKVersion = "1.3.275.0"
}

# Logging
function Write-Status {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-AdminRights {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandExists {
    param([string]$Command)
    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

function Get-VSInstallPath {
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    
    if (Test-Path $vsWhere) {
        $installPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installPath) {
            return $installPath
        }
    }
    
    # Check common locations
    $possiblePaths = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional",
        "C:\Program Files\Microsoft Visual Studio\2022\Community",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools",
        "D:\VS2022Enterprise"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\VC\Tools\MSVC") {
            return $path
        }
    }
    
    return $null
}

function Test-CMakeVersion {
    if (-not (Test-CommandExists "cmake")) {
        return $false
    }
    
    $version = & cmake --version | Select-Object -First 1
    $versionMatch = $version -match '(\d+\.\d+\.\d+)'
    if ($versionMatch) {
        $installedVersion = [Version]$matches[1]
        $requiredVersion = [Version]$script:Config.MinCMakeVersion
        return $installedVersion -ge $requiredVersion
    }
    return $false
}

function Test-PythonVersion {
    if (-not (Test-CommandExists "python")) {
        return $false
    }
    
    $version = & python --version 2>&1
    $versionMatch = $version -match 'Python (\d+\.\d+\.\d+)'
    if ($versionMatch) {
        $installedVersion = [Version]$matches[1]
        $requiredVersion = [Version]$script:Config.MinPythonVersion
        return $installedVersion -ge $requiredVersion
    }
    return $false
}

function Test-VulkanSDK {
    $vulkanSdk = $env:VULKAN_SDK
    if (-not $vulkanSdk) {
        return $false
    }
    return Test-Path "$vulkanSdk\Bin\vulkan-1.dll"
}

function Install-CMake {
    Write-Status "Installing CMake..." "Warning"
    
    $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v3.28.1/cmake-3.28.1-windows-x86_64.msi"
    $cmakeInstaller = "$env:TEMP\cmake-installer.msi"
    
    try {
        Invoke-WebRequest -Uri $cmakeUrl -OutFile $cmakeInstaller -UseBasicParsing
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", $cmakeInstaller, "/quiet", "/norestart" -Wait
        Remove-Item $cmakeInstaller -ErrorAction SilentlyContinue
        
        # Refresh PATH
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Status "CMake installed successfully" "Success"
        return $true
    }
    catch {
        Write-Status "Failed to install CMake: $_" "Error"
        return $false
    }
}

function Install-Python {
    Write-Status "Installing Python..." "Warning"
    
    $pythonUrl = "https://www.python.org/ftp/python/3.11.7/python-3.11.7-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    
    try {
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
        Remove-Item $pythonInstaller -ErrorAction SilentlyContinue
        
        # Refresh PATH
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        
        Write-Status "Python installed successfully" "Success"
        return $true
    }
    catch {
        Write-Status "Failed to install Python: $_" "Error"
        return $false
    }
}

function Install-VulkanSDK {
    Write-Status "Installing Vulkan SDK..." "Warning"
    
    $vulkanUrl = "https://sdk.lunarg.com/sdk/download/$($script:Config.VulkanSDKVersion)/windows/VulkanSDK-$($script:Config.VulkanSDKVersion)-Installer.exe"
    $vulkanInstaller = "$env:TEMP\vulkan-installer.exe"
    
    try {
        Invoke-WebRequest -Uri $vulkanUrl -OutFile $vulkanInstaller -UseBasicParsing
        Start-Process -FilePath $vulkanInstaller -ArgumentList "/S" -Wait
        Remove-Item $vulkanInstaller -ErrorAction SilentlyContinue
        
        Write-Status "Vulkan SDK installed successfully" "Success"
        return $true
    }
    catch {
        Write-Status "Failed to install Vulkan SDK: $_" "Error"
        return $false
    }
}

function New-DevelopmentShortcuts {
    param([string]$RawrXDPath)
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = "$desktopPath\RawrXD Developer Prompt.lnk"
    
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-NoExit -Command `"cd '$RawrXDPath'; .\scripts\enter_dev_shell.ps1`""
    $Shortcut.WorkingDirectory = $RawrXDPath
    $Shortcut.Description = "RawrXD Development Environment"
    $Shortcut.IconLocation = "$RawrXDPath\RawrXD.ico,0"
    $Shortcut.Save()
    
    Write-Status "Created desktop shortcut: RawrXD Developer Prompt" "Success"
}

# Main execution
Write-Status "RawrXD Development Environment Setup v$($script:Config.Version)" "Info"
Write-Status "==============================================" "Info"

if (-not (Test-AdminRights)) {
    Write-Status "This script requires administrator privileges. Please run as administrator." "Error"
    exit 1
}

$results = @{
    VS = $false
    CMake = $false
    Python = $false
    Vulkan = $false
}

# Check Visual Studio
if (-not $SkipVS) {
    Write-Status "Checking Visual Studio installation..." "Info"
    $vsPath = Get-VSInstallPath
    if ($vsPath) {
        Write-Status "Found Visual Studio at: $vsPath" "Success"
        $results.VS = $true
    }
    else {
        Write-Status "Visual Studio not found. Please install Visual Studio 2022 with C++ workload." "Warning"
        Write-Status "Download from: https://visualstudio.microsoft.com/downloads/" "Info"
    }
}

# Check CMake
Write-Status "Checking CMake..." "Info"
if (Test-CMakeVersion) {
    Write-Status "CMake $(& cmake --version | Select-Object -First 1) found" "Success"
    $results.CMake = $true
}
else {
    Write-Status "CMake not found or version too old" "Warning"
    if ($Force -or (Read-Host "Install CMake? (Y/N)").ToUpper() -eq 'Y') {
        $results.CMake = Install-CMake
    }
}

# Check Python
Write-Status "Checking Python..." "Info"
if (Test-PythonVersion) {
    Write-Status "Python $(& python --version 2>&1) found" "Success"
    $results.Python = $true
}
else {
    Write-Status "Python not found or version too old" "Warning"
    if ($Force -or (Read-Host "Install Python? (Y/N)").ToUpper() -eq 'Y') {
        $results.Python = Install-Python
    }
}

# Check Vulkan SDK
if (-not $SkipVulkan) {
    Write-Status "Checking Vulkan SDK..." "Info"
    if (Test-VulkanSDK) {
        Write-Status "Vulkan SDK found at: $env:VULKAN_SDK" "Success"
        $results.Vulkan = $true
    }
    else {
        Write-Status "Vulkan SDK not found" "Warning"
        if ($Force -or (Read-Host "Install Vulkan SDK? (Y/N)").ToUpper() -eq 'Y') {
            $results.Vulkan = Install-VulkanSDK
        }
    }
}

# Summary
Write-Status "" "Info"
Write-Status "Setup Summary:" "Info"
Write-Status "  Visual Studio: $(if ($results.VS) { 'OK' } else { 'MISSING' })" $(if ($results.VS) { "Success" } else { "Warning" })
Write-Status "  CMake: $(if ($results.CMake) { 'OK' } else { 'MISSING' })" $(if ($results.CMake) { "Success" } else { "Warning" })
Write-Status "  Python: $(if ($results.Python) { 'OK' } else { 'MISSING' })" $(if ($results.Python) { "Success" } else { "Warning" })
Write-Status "  Vulkan SDK: $(if ($results.Vulkan) { 'OK' } else { 'SKIPPED/MISSING' })" $(if ($results.Vulkan) { "Success" } else { "Warning" })

# Create shortcuts
$rawrXDPath = Split-Path -Parent $PSScriptRoot
if (Test-Path "$rawrXDPath\CMakeLists.txt") {
    New-DevelopmentShortcuts -RawrXDPath $rawrXDPath
}

Write-Status "" "Info"
Write-Status "Setup complete! Run 'RawrXD Developer Prompt' from your desktop to start." "Success"
