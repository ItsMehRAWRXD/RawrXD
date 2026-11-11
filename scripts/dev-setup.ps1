# RawrXD Development Environment Setup Script
# Sets up a complete development environment for RawrXD

param(
    [switch]$SkipVSBuildTools,
    [switch]$SkipCUDA,
    [switch]$SkipDocker,
    [switch]$Minimal,
    [string]$InstallPath = "C:\RawrXD-Dev"
)

$ErrorActionPreference = "Stop"

# Colors
$Colors = @{
    Success = "Green"
    Error = "Red"
    Warning = "Yellow"
    Info = "Cyan"
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor $Colors.Info
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor $Colors.Success
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor $Colors.Error
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor $Colors.Warning
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Status "Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:PATH += ";C:\ProgramData\chocolatey\bin"
        Write-Success "Chocolatey installed"
    } else {
        Write-Success "Chocolatey already installed"
    }
}

function Install-BuildTools {
    if ($SkipVSBuildTools) {
        Write-Warning "Skipping VS Build Tools installation"
        return
    }

    Write-Status "Installing Visual Studio Build Tools..."
    
    $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
    $vsInstallerPath = "$env:TEMP\vs_buildtools.exe"
    
    # Download installer
    Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstallerPath
    
    # Install with required components
    $installArgs = @(
        "--quiet",
        "--wait",
        "--add", "Microsoft.VisualStudio.Workload.VCTools",
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
        "--add", "Microsoft.VisualStudio.Component.CMake",
        "--add", "Microsoft.VisualStudio.Component.Git"
    )
    
    Start-Process -FilePath $vsInstallerPath -ArgumentList $installArgs -Wait
    Remove-Item $vsInstallerPath -ErrorAction SilentlyContinue
    
    Write-Success "Visual Studio Build Tools installed"
}

function Install-CMake {
    Write-Status "Installing CMake..."
    
    if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
        choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' -y
        refreshenv
        Write-Success "CMake installed"
    } else {
        $version = cmake --version | Select-Object -First 1
        Write-Success "CMake already installed: $version"
    }
}

function Install-Git {
    Write-Status "Installing Git..."
    
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        choco install git -y
        refreshenv
        Write-Success "Git installed"
    } else {
        $version = git --version
        Write-Success "Git already installed: $version"
    }
}

function Install-Python {
    Write-Status "Installing Python..."
    
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        choco install python -y
        refreshenv
        Write-Success "Python installed"
    } else {
        $version = python --version
        Write-Success "Python already installed: $version"
    }
    
    # Install Python packages
    Write-Status "Installing Python packages..."
    python -m pip install --upgrade pip
    python -m pip install conan numpy pyyaml requests
    Write-Success "Python packages installed"
}

function Install-CUDA {
    if ($SkipCUDA) {
        Write-Warning "Skipping CUDA installation"
        return
    }

    Write-Status "Checking for NVIDIA GPU..."
    
    $gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -like "*NVIDIA*" }
    
    if (-not $gpu) {
        Write-Warning "No NVIDIA GPU detected. Skipping CUDA installation."
        return
    }
    
    Write-Success "NVIDIA GPU detected: $($gpu.Name)"
    
    if (-not (Test-Path "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA")) {
        Write-Status "Installing CUDA Toolkit..."
        Write-Warning "Please download and install CUDA 11.8 or later from https://developer.nvidia.com/cuda-downloads"
        Write-Warning "After installation, run this script again with -SkipCUDA to continue."
        Start-Process "https://developer.nvidia.com/cuda-downloads"
        return
    } else {
        Write-Success "CUDA already installed"
    }
}

function Install-Docker {
    if ($SkipDocker -or $Minimal) {
        Write-Warning "Skipping Docker installation"
        return
    }

    Write-Status "Installing Docker Desktop..."
    
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        choco install docker-desktop -y
        Write-Success "Docker Desktop installed"
        Write-Warning "Please restart your computer to complete Docker installation"
    } else {
        $version = docker --version
        Write-Success "Docker already installed: $version"
    }
}

function Install-Vulkan {
    Write-Status "Checking for Vulkan SDK..."
    
    $vulkanSdk = Get-ChildItem "C:\VulkanSDK" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    
    if (-not $vulkanSdk) {
        Write-Warning "Vulkan SDK not found. Installing..."
        $vulkanUrl = "https://sdk.lunarg.com/sdk/download/latest/windows/vulkan-sdk.exe"
        $vulkanInstaller = "$env:TEMP\vulkan-sdk.exe"
        
        Invoke-WebRequest -Uri $vulkanUrl -OutFile $vulkanInstaller
        Start-Process -FilePath $vulkanInstaller -ArgumentList "/S" -Wait
        Remove-Item $vulkanInstaller -ErrorAction SilentlyContinue
        
        Write-Success "Vulkan SDK installed"
    } else {
        Write-Success "Vulkan SDK found: $($vulkanSdk.Name)"
    }
}

function Setup-Repository {
    Write-Status "Setting up RawrXD repository..."
    
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    
    $repoPath = "$InstallPath\rawrxd"
    
    if (-not (Test-Path "$repoPath\.git")) {
        Write-Status "Cloning RawrXD repository..."
        git clone https://github.com/ItsMehRAWRXD/RawrXD.git $repoPath
        Write-Success "Repository cloned to $repoPath"
    } else {
        Write-Success "Repository already exists at $repoPath"
    }
    
    Set-Location $repoPath
    
    # Initialize submodules
    Write-Status "Initializing git submodules..."
    git submodule update --init --recursive
    Write-Success "Submodules initialized"
    
    # Create build directory
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" -Force | Out-Null
        Write-Success "Build directory created"
    }
}

function Configure-Build {
    Write-Status "Configuring build environment..."
    
    Set-Location "$InstallPath\rawrxd\build"
    
    # Configure with CMake
    $cmakeArgs = @(
        "..",
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
    )
    
    if (-not $SkipCUDA) {
        $cmakeArgs += "-DGGML_CUDA=ON"
    }
    
    if (-not $Minimal) {
        $cmakeArgs += "-DGGML_VULKAN=ON"
    }
    
    & cmake @cmakeArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Build configured successfully"
    } else {
        Write-Error "Build configuration failed"
        exit 1
    }
}

function Create-Shortcuts {
    Write-Status "Creating shortcuts..."
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $repoPath = "$InstallPath\rawrxd"
    
    # Create VS Code workspace shortcut
    $wshell = New-Object -ComObject WScript.Shell
    $shortcut = $wshell.CreateShortcut("$desktopPath\RawrXD Development.lnk")
    $shortcut.TargetPath = "code"
    $shortcut.Arguments = "$repoPath"
    $shortcut.WorkingDirectory = $repoPath
    $shortcut.IconLocation = "$repoPath\RawrXD.ico,0"
    $shortcut.Save()
    
    Write-Success "Shortcuts created on Desktop"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Development Environment Setup Complete!" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Path: $InstallPath\rawrxd"
    Write-Host "Build Directory: $InstallPath\rawrxd\build"
    Write-Host ""
    Write-Host "Next Steps:"
    Write-Host "  1. cd $InstallPath\rawrxd\build"
    Write-Host "  2. cmake --build . --parallel `$env:NUMBER_OF_PROCESSORS"
    Write-Host "  3. ctest --output-on-failure"
    Write-Host ""
    Write-Host "Documentation:"
    Write-Host "  - README.md"
    Write-Host "  - docs/BUILD.md"
    Write-Host "  - docs/API_REFERENCE.md"
    Write-Host ""
}

# Main execution
function Main {
    Write-Host "RawrXD Development Environment Setup" -ForegroundColor Cyan
    Write-Host "====================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Admin)) {
        Write-Error "This script must be run as Administrator"
        Write-Host "Please run PowerShell as Administrator and try again."
        exit 1
    }
    
    try {
        Install-Chocolatey
        Install-BuildTools
        Install-CMake
        Install-Git
        Install-Python
        Install-CUDA
        Install-Docker
        Install-Vulkan
        Setup-Repository
        Configure-Build
        Create-Shortcuts
        Show-Summary
        
        Write-Success "Setup completed successfully!"
    }
    catch {
        Write-Error "Setup failed: $_"
        exit 1
    }
}

Main
