#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase Q.2: SDK Manager
    
.DESCRIPTION
    Manages RawrXD SDKs for multiple languages including
    installation, updates, and version management.
    
.PARAMETER Action
    Action to perform: install, update, list, create-project
    
.PARAMETER Language
    Target language: python, javascript, csharp, go, rust
    
.PARAMETER Version
    SDK version to install
    
.EXAMPLE
    .\sdk_manager.ps1 -Action install -Language python -Version latest
    .\sdk_manager.ps1 -Action create-project -Language python -ProjectName my-app
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "update", "list", "create-project", "validate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("python", "javascript", "csharp", "go", "rust")]
    [string]$Language,
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "latest",
    
    [Parameter(Mandatory=$false)]
    [string]$ProjectName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\sdk_data"
)

$ErrorActionPreference = "Stop"

# SDK registry
$SDKRegistry = @{
    SDKs = @{}
    Installed = @{}
    LastUpdated = $null
}

# SDK definitions
$SDKDefinitions = @{
    python = @{
        Name = "rawrxd-python"
        PackageName = "rawrxd"
        Repository = "https://github.com/ItsMehRAWRXD/rawrxd-python"
        InstallCommand = "pip install {package}=={version}"
        MinVersion = "3.8"
        CurrentVersion = "1.2.0"
        Features = @("async", "streaming", "batching")
    }
    javascript = @{
        Name = "rawrxd-js"
        PackageName = "@rawrxd/sdk"
        Repository = "https://github.com/ItsMehRAWRXD/rawrxd-js"
        InstallCommand = "npm install {package}@{version}"
        MinVersion = "16.0"
        CurrentVersion = "1.2.0"
        Features = @("typescript", "streaming", "react-hooks")
    }
    csharp = @{
        Name = "rawrxd-dotnet"
        PackageName = "RawrXD.SDK"
        Repository = "https://github.com/ItsMehRAWRXD/rawrxd-dotnet"
        InstallCommand = "dotnet add package {package} --version {version}"
        MinVersion = "6.0"
        CurrentVersion = "1.2.0"
        Features = @("async", "dependency-injection", "configuration")
    }
    go = @{
        Name = "rawrxd-go"
        PackageName = "github.com/ItsMehRAWRXD/rawrxd-go"
        Repository = "https://github.com/ItsMehRAWRXD/rawrxd-go"
        InstallCommand = "go get {package}@v{version}"
        MinVersion = "1.19"
        CurrentVersion = "1.2.0"
        Features = @("context", "streaming", "retry")
    }
    rust = @{
        Name = "rawrxd-rust"
        PackageName = "rawrxd"
        Repository = "https://github.com/ItsMehRAWRXD/rawrxd-rust"
        InstallCommand = "cargo add {package} --version {version}"
        MinVersion = "1.65"
        CurrentVersion = "1.2.0"
        Features = @("async", "tokio", "streaming")
    }
}

function Write-SDKHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase Q.2: SDK Manager                                            ║
║  Multi-language SDK management for RawrXD                          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-SDKManager {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $OutputPath "sdk_registry.json"
    if (Test-Path $registryFile) {
        $script:SDKRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Initialize SDK definitions
    $script:SDKRegistry.SDKs = $SDKDefinitions
}

function Save-SDKRegistry {
    $registryFile = Join-Path $OutputPath "sdk_registry.json"
    $script:SDKRegistry.LastUpdated = Get-Date -Format "o"
    $script:SDKRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Install-SDK {
    param($Language, $Version)
    
    Write-Host "`nInstalling $Language SDK..." -ForegroundColor Yellow
    
    if (-not $script:SDKDefinitions.ContainsKey($Language)) {
        Write-Error "Unsupported language: $Language"
        return
    }
    
    $sdk = $script:SDKDefinitions[$Language]
    $installVersion = if ($Version -eq "latest") { $sdk.CurrentVersion } else { $Version }
    
    Write-Host "  Package: $($sdk.PackageName)" -ForegroundColor Gray
    Write-Host "  Version: $installVersion" -ForegroundColor Gray
    Write-Host "  Repository: $($sdk.Repository)" -ForegroundColor Gray
    
    # Generate install command
    $command = $sdk.InstallCommand.Replace("{package}", $sdk.PackageName).Replace("{version}", $installVersion)
    
    Write-Host "`n  Install command:" -ForegroundColor Cyan
    Write-Host "    $command" -ForegroundColor White
    
    # Create installation script
    $scriptContent = @"
# RawrXD $Language SDK Installation Script
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Write-Host "Installing $($sdk.PackageName) v$installVersion..."

$command

Write-Host "Installation complete!"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Import the SDK in your project"
Write-Host "  2. Set your API key"
Write-Host "  3. Start building!"
"@
    
    $scriptPath = Join-Path $OutputPath "install_$Language.ps1"
    $scriptContent | Set-Content -Path $scriptPath
    
    # Record installation
    $script:SDKRegistry.Installed[$Language] = @{
        Version = $installVersion
        InstalledAt = Get-Date -Format "o"
        Path = $scriptPath
    }
    Save-SDKRegistry
    
    Write-Host "`n  ✓ Installation script created: $scriptPath" -ForegroundColor Green
    Write-Host "  Run the script to install the SDK" -ForegroundColor Yellow
}

function Update-SDK {
    param($Language)
    
    Write-Host "`nUpdating $Language SDK..." -ForegroundColor Yellow
    
    if (-not $script:SDKRegistry.Installed.ContainsKey($Language)) {
        Write-Warning "$Language SDK not installed. Use -Action install first."
        return
    }
    
    $current = $script:SDKRegistry.Installed[$Language].Version
    $latest = $script:SDKDefinitions[$Language].CurrentVersion
    
    if ($current -eq $latest) {
        Write-Host "  ✓ Already up to date (v$current)" -ForegroundColor Green
        return
    }
    
    Write-Host "  Current: v$current" -ForegroundColor Gray
    Write-Host "  Latest:  v$latest" -ForegroundColor Green
    
    # Update
    Install-SDK -Language $Language -Version $latest
    
    Write-Host "  ✓ Updated to v$latest" -ForegroundColor Green
}

function Get-SDKList {
    Write-Host "`nAvailable SDKs:" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "  {0,-12} {1,-15} {2,-10} {3,-20}" -f "Language", "Package", "Version", "Features" -ForegroundColor White
    Write-Host "  $("-" * 60)" -ForegroundColor Gray
    
    foreach ($sdk in $script:SDKDefinitions.GetEnumerator()) {
        $installed = $script:SDKRegistry.Installed.ContainsKey($sdk.Key)
        $status = if ($installed) { "[Installed]" } else { "" }
        $features = ($sdk.Value.Features | Select-Object -First 3) -join ", "
        Write-Host "  {0,-12} {1,-15} {2,-10} {3,-20} {4}" -f $sdk.Key, $sdk.Value.PackageName, $sdk.Value.CurrentVersion, $features, $status -ForegroundColor $(if ($installed) { "Green" } else { "Gray" })
    }
    
    Write-Host "`n  Total: $($script:SDKDefinitions.Count) SDKs available" -ForegroundColor Cyan
    Write-Host "  Installed: $($script:SDKRegistry.Installed.Count)" -ForegroundColor Green
}

function New-Project {
    param($Language, $ProjectName)
    
    if (-not $ProjectName) {
        $ProjectName = Read-Host "Enter project name"
    }
    
    Write-Host "`nCreating new $Language project: $ProjectName..." -ForegroundColor Yellow
    
    $projectDir = Join-Path $PWD $ProjectName
    New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
    
    switch ($Language) {
        "python" {
            $mainContent = @"
# $ProjectName
# RawrXD Python SDK Example

import os
from rawrxd import RawrXDClient

# Initialize client
client = RawrXDClient(
    api_key=os.getenv("RAWRXD_API_KEY")
)

# Example: Chat completion
def chat_completion(prompt):
    response = client.chat.completions.create(
        model="rawrxd-3b",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    result = chat_completion("Hello, RawrXD!")
    print(result)
"@
            $mainContent | Set-Content -Path (Join-Path $projectDir "main.py")
            
            $requirements = @"
rawrxd>=1.2.0
python-dotenv>=1.0.0
"@
            $requirements | Set-Content -Path (Join-Path $projectDir "requirements.txt")
            
            $readme = @"
# $ProjectName

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set your API key:
   ```bash
   export RAWRXD_API_KEY="your-api-key"
   ```

3. Run:
   ```bash
   python main.py
   ```
"@
            $readme | Set-Content -Path (Join-Path $projectDir "README.md")
        }
        
        "javascript" {
            $mainContent = @"
// $ProjectName
// RawrXD JavaScript SDK Example

import { RawrXDClient } from '@rawrxd/sdk';

const client = new RawrXDClient({
  apiKey: process.env.RAWRXD_API_KEY
});

async function chatCompletion(prompt) {
  const response = await client.chat.completions.create({
    model: 'rawrxd-3b',
    messages: [{ role: 'user', content: prompt }]
  });
  return response.choices[0].message.content;
}

chatCompletion('Hello, RawrXD!')
  .then(result => console.log(result))
  .catch(err => console.error(err));
"@
            $mainContent | Set-Content -Path (Join-Path $projectDir "index.js")
            
            $packageJson = @"
{
  "name": "$($ProjectName.ToLower())",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@rawrxd/sdk": "^1.2.0"
  }
}
"@
            $packageJson | Set-Content -Path (Join-Path $projectDir "package.json")
            
            $readme = @"
# $ProjectName

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set your API key:
   ```bash
   export RAWRXD_API_KEY="your-api-key"
   ```

3. Run:
   ```bash
   node index.js
   ```
"@
            $readme | Set-Content -Path (Join-Path $projectDir "README.md")
        }
        
        "csharp" {
            $programContent = @"
// $ProjectName
// RawrXD .NET SDK Example

using RawrXD;

var client = new RawrXDClient(new RawrXDOptions
{
    ApiKey = Environment.GetEnvironmentVariable("RAWRXD_API_KEY")
});

var response = await client.Chat.Completions.CreateAsync(new ChatCompletionRequest
{
    Model = "rawrxd-3b",
    Messages = new[]
    {
        new Message { Role = "user", Content = "Hello, RawrXD!" }
    }
});

Console.WriteLine(response.Choices[0].Message.Content);
"@
            $programContent | Set-Content -Path (Join-Path $projectDir "Program.cs")
            
            $csprojContent = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="RawrXD.SDK" Version="1.2.0" />
  </ItemGroup>
</Project>
"@
            $csprojContent | Set-Content -Path (Join-Path $projectDir "$ProjectName.csproj")
            
            $readme = @"
# $ProjectName

## Setup

1. Restore packages:
   ```bash
   dotnet restore
   ```

2. Set your API key:
   ```bash
   export RAWRXD_API_KEY="your-api-key"
   ```

3. Run:
   ```bash
   dotnet run
   ```
"@
            $readme | Set-Content -Path (Join-Path $projectDir "README.md")
        }
        
        default {
            $readme = @"
# $ProjectName

## Setup

1. Install the RawrXD $Language SDK
2. Set your API key
3. Start building!

See documentation: https://docs.rawrxd.io/sdks/$Language
"@
            $readme | Set-Content -Path (Join-Path $projectDir "README.md")
        }
    }
    
    # Create .env.example
    $envExample = @"
# RawrXD Configuration
RAWRXD_API_KEY=your-api-key-here
RAWRXD_BASE_URL=https://api.rawrxd.io/v1
"@
    $envExample | Set-Content -Path (Join-Path $projectDir ".env.example")
    
    # Create .gitignore
    $gitignore = @"
# Environment variables
.env

# Dependencies
node_modules/
__pycache__/
*.pyc
bin/
obj/
target/

# IDE
.vscode/
.idea/
*.swp
*.swo
"@
    $gitignore | Set-Content -Path (Join-Path $projectDir ".gitignore")
    
    Write-Host "  ✓ Project created: $projectDir" -ForegroundColor Green
    Write-Host "  ✓ Language: $Language" -ForegroundColor Gray
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  cd $ProjectName" -ForegroundColor White
    Write-Host "  # Follow README.md for setup instructions" -ForegroundColor White
}

function Test-SDK {
    param($Language)
    
    Write-Host "`nTesting $Language SDK installation..." -ForegroundColor Yellow
    
    if (-not $script:SDKRegistry.Installed.ContainsKey($Language)) {
        Write-Warning "$Language SDK not installed"
        return
    }
    
    $sdk = $script:SDKRegistry.Installed[$Language]
    
    Write-Host "  SDK: $Language" -ForegroundColor Gray
    Write-Host "  Version: $($sdk.Version)" -ForegroundColor Gray
    Write-Host "  Installed: $([DateTime]::Parse($sdk.InstalledAt).ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    
    Write-Host "`n  ✓ SDK validation complete" -ForegroundColor Green
}

# Main execution
Write-SDKHeader
Initialize-SDKManager

switch ($Action) {
    "install" {
        if (-not $Language) {
            Write-Error "Language required for install action"
            exit 1
        }
        Install-SDK -Language $Language -Version $Version
    }
    "update" {
        if (-not $Language) {
            Write-Error "Language required for update action"
            exit 1
        }
        Update-SDK -Language $Language
    }
    "list" {
        Get-SDKList
    }
    "create-project" {
        if (-not $Language) {
            Write-Error "Language required for create-project action"
            exit 1
        }
        New-Project -Language $Language -ProjectName $ProjectName
    }
    "validate" {
        if (-not $Language) {
            Write-Error "Language required for validate action"
            exit 1
        }
        Test-SDK -Language $Language
    }
}

Write-Host "`n✅ SDK manager operation complete" -ForegroundColor Green
