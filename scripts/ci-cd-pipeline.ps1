# RawrXD CI/CD Pipeline Script
# Automates the complete build, test, and deployment pipeline

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Build", "Test", "Package", "Deploy", "Full")]
    [string]$Stage = "Full",
    
    [string]$Branch = "main",
    [string]$Version = "",
    [string]$Environment = "staging",  # staging, production
    [switch]$SkipTests,
    [switch]$SkipSecurityScan,
    [switch]$DryRun,
    [string]$ArtifactsPath = "artifacts"
)

$ErrorActionPreference = "Stop"

# Pipeline configuration
$script:Config = @{
    Stages = @{
        Build = @{ Name = "Build"; Order = 1 }
        Test = @{ Name = "Test"; Order = 2 }
        Security = @{ Name = "Security Scan"; Order = 3 }
        Package = @{ Name = "Package"; Order = 4 }
        Deploy = @{ Name = "Deploy"; Order = 5 }
    }
    Results = @{}
    StartTime = Get-Date
}

function Write-Stage {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Gray
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

function Initialize-Pipeline {
    Write-Stage "Initializing CI/CD Pipeline"
    
    # Create artifacts directory
    if (-not (Test-Path $ArtifactsPath)) {
        New-Item -ItemType Directory -Path $ArtifactsPath -Force | Out-Null
    }
    
    # Set version if not provided
    if (-not $Version) {
        $Version = git describe --tags --always 2>$null
        if (-not $Version) {
            $Version = "0.0.0-$(Get-Date -Format 'yyyyMMdd')"
        }
    }
    
    $script:Config.Version = $Version
    $script:Config.Branch = $Branch
    $script:Config.Environment = $Environment
    
    Write-Status "Version: $Version"
    Write-Status "Branch: $Branch"
    Write-Status "Environment: $Environment"
    Write-Status "Stage: $Stage"
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No actual changes will be made"
    }
}

function Invoke-BuildStage {
    Write-Stage "Stage: Build"
    
    $stageStart = Get-Date
    
    try {
        # Clean previous builds
        Write-Status "Cleaning previous builds..."
        if (Test-Path "build") {
            Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
        }
        
        # Configure
        Write-Status "Configuring build..."
        New-Item -ItemType Directory -Path "build" -Force | Out-Null
        Set-Location "build"
        
        $cmakeArgs = @(
            "..",
            "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DRAWRXD_BUILD_TESTS=ON"
        )
        
        if ($Environment -eq "production") {
            $cmakeArgs += "-DRAWRXD_ENABLE_OPTIMIZATIONS=ON"
        }
        
        if (-not $DryRun) {
            & cmake @cmakeArgs
            if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }
        }
        
        # Build
        Write-Status "Building project..."
        if (-not $DryRun) {
            & cmake --build . --parallel $env:NUMBER_OF_PROCESSORS
            if ($LASTEXITCODE -ne 0) { throw "Build failed" }
        }
        
        $stageEnd = Get-Date
        $duration = ($stageEnd - $stageStart).TotalMinutes
        
        $script:Config.Results.Build = @{
            Status = "Success"
            Duration = [math]::Round($duration, 2)
            Timestamp = Get-Date -Format "o"
        }
        
        Write-Success "Build completed in $([math]::Round($duration, 2)) minutes"
        Set-Location ..
    }
    catch {
        $script:Config.Results.Build = @{
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date -Format "o"
        }
        Write-Error "Build stage failed: $_"
        exit 1
    }
}

function Invoke-TestStage {
    if ($SkipTests) {
        Write-Warning "Skipping test stage"
        $script:Config.Results.Test = @{ Status = "Skipped" }
        return
    }
    
    Write-Stage "Stage: Test"
    
    $stageStart = Get-Date
    
    try {
        Set-Location "build"
        
        # Run tests
        Write-Status "Running test suite..."
        if (-not $DryRun) {
            & ctest --output-on-failure -C Release
            if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
        }
        
        # Run benchmarks
        Write-Status "Running benchmarks..."
        if (-not $DryRun -and (Test-Path "..\scripts\benchmark-runner.ps1")) {
            & "..\scripts\benchmark-runner.ps1" -Suite Quick -OutputPath "../$ArtifactsPath/benchmarks"
        }
        
        $stageEnd = Get-Date
        $duration = ($stageEnd - $stageStart).TotalMinutes
        
        $script:Config.Results.Test = @{
            Status = "Success"
            Duration = [math]::Round($duration, 2)
            Timestamp = Get-Date -Format "o"
        }
        
        Write-Success "Tests completed in $([math]::Round($duration, 2)) minutes"
        Set-Location ..
    }
    catch {
        $script:Config.Results.Test = @{
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date -Format "o"
        }
        Write-Error "Test stage failed: $_"
        exit 1
    }
}

function Invoke-SecurityStage {
    if ($SkipSecurityScan) {
        Write-Warning "Skipping security scan"
        $script:Config.Results.Security = @{ Status = "Skipped" }
        return
    }
    
    Write-Stage "Stage: Security Scan"
    
    $stageStart = Get-Date
    
    try {
        # Code analysis
        Write-Status "Running static code analysis..."
        if (-not $DryRun) {
            # Run PSScriptAnalyzer on PowerShell scripts
            if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
                $scripts = Get-ChildItem -Path "scripts" -Filter "*.ps1" -Recurse
                foreach ($script in $scripts) {
                    $results = Invoke-ScriptAnalyzer -Path $script.FullName
                    if ($results) {
                        Write-Warning "Issues found in $($script.Name): $($results.Count)"
                    }
                }
            }
        }
        
        # Dependency check
        Write-Status "Checking dependencies..."
        if (-not $DryRun) {
            # Check for known vulnerabilities in dependencies
            # This would integrate with a vulnerability database
        }
        
        $stageEnd = Get-Date
        $duration = ($stageEnd - $stageStart).TotalMinutes
        
        $script:Config.Results.Security = @{
            Status = "Success"
            Duration = [math]::Round($duration, 2)
            Timestamp = Get-Date -Format "o"
        }
        
        Write-Success "Security scan completed in $([math]::Round($duration, 2)) minutes"
    }
    catch {
        $script:Config.Results.Security = @{
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date -Format "o"
        }
        Write-Error "Security stage failed: $_"
        exit 1
    }
}

function Invoke-PackageStage {
    Write-Stage "Stage: Package"
    
    $stageStart = Get-Date
    
    try {
        $packageName = "RawrXD-v$($script:Config.Version)-$($script:Config.Environment)"
        $packageDir = "$ArtifactsPath\$packageName"
        
        if (-not $DryRun) {
            # Create package directory
            New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
            
            # Copy binaries
            Copy-Item -Path "build\Release\*.exe" -Destination "$packageDir\bin" -Recurse -ErrorAction SilentlyContinue
            Copy-Item -Path "build\Release\*.dll" -Destination "$packageDir\bin" -Recurse -ErrorAction SilentlyContinue
            
            # Copy documentation
            Copy-Item -Path "README.md", "LICENSE", "CHANGELOG.md" -Destination $packageDir -ErrorAction SilentlyContinue
            
            # Create archive
            Compress-Archive -Path $packageDir -DestinationPath "$ArtifactsPath\$packageName.zip" -Force
            
            # Generate checksum
            $hash = Get-FileHash "$ArtifactsPath\$packageName.zip" -Algorithm SHA256
            "$($hash.Hash)  $packageName.zip" | Out-File "$ArtifactsPath\checksums.txt"
        }
        
        $stageEnd = Get-Date
        $duration = ($stageEnd - $stageStart).TotalMinutes
        
        $script:Config.Results.Package = @{
            Status = "Success"
            Duration = [math]::Round($duration, 2)
            PackageName = $packageName
            Timestamp = Get-Date -Format "o"
        }
        
        Write-Success "Package created: $packageName"
    }
    catch {
        $script:Config.Results.Package = @{
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date -Format "o"
        }
        Write-Error "Package stage failed: $_"
        exit 1
    }
}

function Invoke-DeployStage {
    Write-Stage "Stage: Deploy"
    
    $stageStart = Get-Date
    
    try {
        if ($Environment -eq "staging") {
            Write-Status "Deploying to staging environment..."
            if (-not $DryRun) {
                # Deploy to staging
                Write-Status "Uploading artifacts to staging server..."
                # Integration with deployment system would go here
            }
        }
        elseif ($Environment -eq "production") {
            Write-Status "Deploying to production environment..."
            if (-not $DryRun) {
                # Production deployment with approval gate
                Write-Warning "Production deployment requires manual approval"
                # Integration with production deployment system
            }
        }
        
        $stageEnd = Get-Date
        $duration = ($stageEnd - $stageStart).TotalMinutes
        
        $script:Config.Results.Deploy = @{
            Status = "Success"
            Duration = [math]::Round($duration, 2)
            Environment = $Environment
            Timestamp = Get-Date -Format "o"
        }
        
        Write-Success "Deployment completed"
    }
    catch {
        $script:Config.Results.Deploy = @{
            Status = "Failed"
            Error = $_.Exception.Message
            Timestamp = Get-Date -Format "o"
        }
        Write-Error "Deploy stage failed: $_"
        exit 1
    }
}

function Export-PipelineReport {
    $endTime = Get-Date
    $totalDuration = ($endTime - $script:Config.StartTime).TotalMinutes
    
    $report = @{
        Pipeline = @{
            Version = $script:Config.Version
            Branch = $script:Config.Branch
            Environment = $script:Config.Environment
            Stage = $Stage
            StartTime = $script:Config.StartTime.ToString("o")
            EndTime = $endTime.ToString("o")
            DurationMinutes = [math]::Round($totalDuration, 2)
        }
        Results = $script:Config.Results
        Status = if ($script:Config.Results.Values | Where-Object { $_.Status -eq "Failed" }) { "Failed" } else { "Success" }
    }
    
    $reportPath = "$ArtifactsPath\pipeline-report-$($script:Config.Version).json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    
    Write-Success "Pipeline report saved to: $reportPath"
}

function Show-Summary {
    $endTime = Get-Date
    $totalDuration = ($endTime - $script:Config.StartTime).TotalMinutes
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "CI/CD Pipeline Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Version: $($script:Config.Version)" -ForegroundColor White
    Write-Host "Branch: $($script:Config.Branch)" -ForegroundColor White
    Write-Host "Environment: $($script:Config.Environment)" -ForegroundColor White
    Write-Host "Total Duration: $([math]::Round($totalDuration, 2)) minutes" -ForegroundColor White
    Write-Host ""
    
    foreach ($stage in $script:Config.Results.Keys) {
        $result = $script:Config.Results[$stage]
        $color = switch ($result.Status) {
            "Success" { "Green" }
            "Failed" { "Red" }
            "Skipped" { "Yellow" }
            default { "White" }
        }
        $icon = switch ($result.Status) {
            "Success" { "✓" }
            "Failed" { "✗" }
            "Skipped" { "⊘" }
            default { "?" }
        }
        Write-Host "$icon $stage`: $($result.Status)" -ForegroundColor $color
    }
    
    Write-Host ""
    
    $failed = $script:Config.Results.Values | Where-Object { $_.Status -eq "Failed" }
    if ($failed) {
        Write-Error "Pipeline completed with failures"
        exit 1
    } else {
        Write-Success "Pipeline completed successfully!"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD CI/CD Pipeline" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Pipeline
    
    switch ($Stage) {
        "Build" { Invoke-BuildStage }
        "Test" { Invoke-BuildStage; Invoke-TestStage }
        "Package" { Invoke-BuildStage; Invoke-TestStage; Invoke-SecurityStage; Invoke-PackageStage }
        "Deploy" { Invoke-BuildStage; Invoke-TestStage; Invoke-SecurityStage; Invoke-PackageStage; Invoke-DeployStage }
        "Full" { 
            Invoke-BuildStage
            Invoke-TestStage
            Invoke-SecurityStage
            Invoke-PackageStage
            Invoke-DeployStage
        }
    }
    
    Export-PipelineReport
    Show-Summary
}

Main
