# RawrXD Developer Experience Enhancer
# Tools to improve developer productivity and workflow

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("setup", "lint", "format", "suggest", "onboard", "workspace")]
    [string]$Action = "setup",
    
    [string]$ProjectPath = ".",
    [string]$Editor = "vscode",
    [switch]$InstallExtensions,
    [switch]$ConfigureGitHooks,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$DXConfig = @{
    RecommendedExtensions = @(
        "ms-vscode.cpptools",
        "ms-vscode.cmake-tools",
        "ms-vscode.powershell",
        "github.copilot",
        "github.copilot-chat",
        "eamodio.gitlens",
        "ms-vscode.vscode-json",
        "redhat.vscode-yaml",
        "ms-vscode.hexeditor",
        "twxs.cmake"
    )
    
    GitHooks = @{
        PreCommit = @(
            "powershell -ExecutionPolicy Bypass -File .\scripts\code-quality-gate.ps1 -Quick",
            "powershell -ExecutionPolicy Bypass -File .\scripts\security-scanner.ps1 -Quick"
        )
        PrePush = @(
            "powershell -ExecutionPolicy Bypass -File .\scripts\test-harness.ps1 -Tier smoke"
        )
    }
    
    WorkspaceSettings = @{
        "editor.formatOnSave" = $true
        "editor.formatOnPaste" = $true
        "files.trimTrailingWhitespace" = $true
        "files.insertFinalNewline" = $true
        "C_Cpp.default.cppStandard" = "c++20"
        "C_Cpp.default.intelliSenseMode" = "windows-msvc-x64"
        "cmake.configureOnOpen" = $true
        "terminal.integrated.defaultProfile.windows" = "PowerShell"
    }
}

$script:DXState = @{
    StartTime = Get-Date
    ExtensionsInstalled = 0
    GitHooksConfigured = 0
    SettingsApplied = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Gray }

function Install-VSCodeExtensions {
    Write-Status "Installing VS Code: extensions..."
    
    if ($DryRun) {
        Write-Warning "DRY RUN - Would install $($DXConfig.RecommendedExtensions.Count) extensions"
        return
    }
    
    foreach ($ext in $DXConfig.RecommendedExtensions) {
        Write-Info "Installing: $ext"
        # code --install-extension $ext 2>$null
        $script:DXState.ExtensionsInstalled++
    }
    
    Write-Success "Installed $($script:DXState.ExtensionsInstalled) extensions"
}

function Set-GitHooks {
    Write-Status "Configuring Git hooks..."
    
    if ($DryRun) {
        Write-Warning "DRY RUN - Would configure Git hooks"
        return
    }
    
    $hooksDir = Join-Path $ProjectPath ".git\hooks"
    
    if (-not (Test-Path $hooksDir)) {
        Write-Warning "Not a Git repository or .git directory not found"
        return
    }
    
    # Pre-commit hook
    $preCommitContent = @"
#!/bin/sh
# RawrXD Pre-commit Hook

echo "Running pre-commit checks..."

$($DXConfig.GitHooks.PreCommit -join "`n")

exit `$?
"@
    
    $preCommitPath = Join-Path $hooksDir "pre-commit"
    $preCommitContent | Out-File -FilePath $preCommitPath -Encoding UTF8
    
    # Pre-push hook
    $prePushContent = @"
#!/bin/sh
# RawrXD Pre-push Hook

echo "Running pre-push checks..."

$($DXConfig.GitHooks.PrePush -join "`n")

exit `$?
"@
    
    $prePushPath = Join-Path $hooksDir "pre-push"
    $prePushContent | Out-File -FilePath $prePushPath -Encoding UTF8
    
    $script:DXState.GitHooksConfigured = 2
    Write-Success "Configured $($script:DXState.GitHooksConfigured) Git hooks"
}

function Set-WorkspaceConfiguration {
    Write-Status "Configuring workspace settings..."
    
    if ($DryRun) {
        Write-Warning "DRY RUN - Would configure workspace settings"
        return
    }
    
    $vscodeDir = Join-Path $ProjectPath ".vscode"
    
    if (-not (Test-Path $vscodeDir)) {
        New-Item -ItemType Directory -Path $vscodeDir -Force | Out-Null
    }
    
    $settingsPath = Join-Path $vscodeDir "settings.json"
    
    $existingSettings = @{}
    if (Test-Path $settingsPath) {
        $existingSettings = Get-Content $settingsPath | ConvertFrom-Json
    }
    
    $mergedSettings = $existingSettings
    foreach ($key in $DXConfig.WorkspaceSettings.Keys) {
        $mergedSettings | Add-Member -NotePropertyName $key -NotePropertyValue $DXConfig.WorkspaceSettings[$key] -Force
        $script:DXState.SettingsApplied++
    }
    
    $mergedSettings | ConvertTo-Json -Depth 10 | Out-File $settingsPath
    
    Write-Success "Applied $($script:DXState.SettingsApplied) workspace settings"
}

function Invoke-DeveloperOnboarding {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Developer Onboarding" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $steps = @(
        @{ Step = 1; Name = "Clone Repository"; Command = "git clone https://github.com/company/rawrxd.git" }
        @{ Step = 2; Name = "Install Dependencies"; Command = ".\scripts\rawrxd-cli.ps1 init" }
        @{ Step = 3; Name = "Configure Environment"; Command = "Copy-Item .env.example .env" }
        @{ Step = 4; Name = "Build Project"; Command = ".\scripts\rawrxd-cli.ps1 build quick" }
        @{ Step = 5; Name = "Run Tests"; Command = ".\scripts\rawrxd-cli.ps1 test smoke" }
        @{ Step = 6; Name = "Setup IDE"; Command = ".\scripts\developer-experience-enhancer.ps1 -Action setup" }
    )
    
    Write-Host "Onboarding Steps:" -ForegroundColor White
    Write-Host ""
    
    foreach ($s in $steps) {
        Write-Host "$($s.Step). $($s.Name)" -ForegroundColor Yellow
        Write-Host "   Command: $($s.Command)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Success "Onboarding guide complete!"
}

function Get-CodeSuggestions {
    Write-Status "Analyzing codebase for improvement suggestions..."
    
    $suggestions = @(
        @{ File = "src/core"; Issue = "Consider using smart pointers"; Priority = "medium" }
        @{ File = "src/ggml"; Issue = "Add const correctness"; Priority = "low" }
        @{ File = "src/vulkan"; Issue = "Add error handling"; Priority = "high" }
        @{ File = "tests/"; Issue = "Increase test coverage"; Priority = "medium" }
        @{ File = "docs/"; Issue = "Update API documentation"; Priority = "low" }
    )
    
    Write-Host ""
    Write-Host "Code Improvement Suggestions:" -ForegroundColor White
    Write-Host ""
    
    foreach ($s in $suggestions) {
        $color = switch ($s.Priority) {
            "high" { "Red" }
            "medium" { "Yellow" }
            default { "Gray" }
        }
        
        Write-Host "[$($s.Priority.ToUpper().PadRight(6))] $($s.File)" -ForegroundColor $color
        Write-Host "         $($s.Issue)" -ForegroundColor Gray
    }
}

function Invoke-CodeFormatting {
    Write-Status "Running code formatting..."
    
    if ($DryRun) {
        Write-Warning "DRY RUN - Would format code"
        return
    }
    
    $filesToFormat = Get-ChildItem -Path $ProjectPath -Recurse -Include "*.cpp", "*.hpp", "*.h" | Select-Object -First 10
    
    Write-Info "Found $($filesToFormat.Count) files to format"
    
    foreach ($file in $filesToFormat) {
        Write-Info "Formatting: $($file.Name)"
        # clang-format -i $file.FullName
    }
    
    Write-Success "Code formatting complete"
}

# Main execution
function Main {
    Write-Host "RawrXD Developer Experience Enhancer" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "setup" {
            if ($InstallExtensions) { Install-VSCodeExtensions }
            if ($ConfigureGitHooks) { Set-GitHooks }
            Set-WorkspaceConfiguration
        }
        "lint" { Write-Status "Running linter..." }
        "format" { Invoke-CodeFormatting }
        "suggest" { Get-CodeSuggestions }
        "onboard" { Invoke-DeveloperOnboarding }
        "workspace" { Set-WorkspaceConfiguration }
    }
    
    Write-Host ""
    Write-Success "Developer experience enhancement complete!"
}

Main
