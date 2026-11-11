# RawrXD Workflow Automation
# Automate common development and deployment workflows

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("DevSetup", "BuildTest", "DeployStaging", "DeployProduction", "Release", "Backup", "Restore", "Clean", "Update")]
    [string]$Workflow = "DevSetup",
    
    [string]$Environment = "development",
    [string]$Version = "",
    [switch]$SkipTests,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Workflow steps tracking
$script:StepsCompleted = 0
$script:StepsFailed = 0
$script:StartTime = Get-Date

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

function Write-Step {
    param(
        [int]$Step,
        [int]$Total,
        [string]$Message
    )
    Write-Host "`n[$Step/$Total] $Message" -ForegroundColor White -BackgroundColor DarkBlue
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    
    Write-Status "Executing: $Name"
    
    if ($DryRun) {
        Write-Warning "[DRY RUN] Would execute: $Name"
        return $true
    }
    
    try {
        & $Action
        $script:StepsCompleted++
        Write-Success "$Name completed"
        return $true
    }
    catch {
        $script:StepsFailed++
        Write-Error "$Name failed: $_"
        return $false
    }
}

function Invoke-DevSetupWorkflow {
    $totalSteps = 6
    $currentStep = 0
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Development Setup Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Step 1: Check prerequisites
    $currentStep++
    Write-Step $currentStep $totalSteps "Checking Prerequisites"
    Invoke-Step "Prerequisites Check" {
        # Check PowerShell version
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            throw "PowerShell 5.1 or higher required"
        }
        
        # Check for required tools
        $tools = @("git", "cmake", "python")
        foreach ($tool in $tools) {
            if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
                throw "Required tool not found: $tool"
            }
        }
        
        Write-Status "All prerequisites met"
    }
    
    # Step 2: Clone/update repository
    $currentStep++
    Write-Step $currentStep $totalSteps "Setting up Repository"
    Invoke-Step "Repository Setup" {
        if (-not (Test-Path ".git")) {
            throw "Not a git repository. Please clone first."
        }
        
        git fetch origin
        git pull origin main
        Write-Status "Repository updated"
    }
    
    # Step 3: Install dependencies
    $currentStep++
    Write-Step $currentStep $totalSteps "Installing Dependencies"
    Invoke-Step "Dependency Installation" {
        if (Test-Path "requirements.txt") {
            pip install -r requirements.txt
        }
        
        if (Test-Path "package.json") {
            npm install
        }
        
        Write-Status "Dependencies installed"
    }
    
    # Step 4: Configure environment
    $currentStep++
    Write-Step $currentStep $totalSteps "Configuring Environment"
    Invoke-Step "Environment Configuration" {
        if (-not (Test-Path ".env")) {
            Copy-Item ".env.example" ".env" -ErrorAction SilentlyContinue
            Write-Warning "Please configure .env file with your settings"
        }
        
        # Create necessary directories
        $dirs = @("logs", "temp", "data", "models")
        foreach ($dir in $dirs) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir | Out-Null
            }
        }
        
        Write-Status "Environment configured"
    }
    
    # Step 5: Build project
    $currentStep++
    Write-Step $currentStep $totalSteps "Building Project"
    Invoke-Step "Project Build" {
        if (Test-Path "build.ps1") {
            .\build.ps1
        } elseif (Test-Path "CMakeLists.txt") {
            cmake -B build
            cmake --build build
        } else {
            Write-Warning "No build script found, skipping build"
        }
    }
    
    # Step 6: Run initial tests
    if (-not $SkipTests) {
        $currentStep++
        Write-Step $currentStep $totalSteps "Running Tests"
        Invoke-Step "Test Execution" {
            if (Test-Path "run_tests.ps1") {
                .\run_tests.ps1 -Quick
            } else {
                Write-Warning "No test script found, skipping tests"
            }
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Development Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}

function Invoke-BuildTestWorkflow {
    $totalSteps = 5
    $currentStep = 0
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Build & Test Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Step 1: Clean previous builds
    $currentStep++
    Write-Step $currentStep $totalSteps "Cleaning Previous Builds"
    Invoke-Step "Clean Build" {
        if (Test-Path "build") {
            Remove-Item "build" -Recurse -Force
        }
        if (Test-Path "dist") {
            Remove-Item "dist" -Recurse -Force
        }
        Write-Status "Build directories cleaned"
    }
    
    # Step 2: Update dependencies
    $currentStep++
    Write-Step $currentStep $totalSteps "Updating Dependencies"
    Invoke-Step "Dependency Update" {
        git submodule update --init --recursive
        
        if (Test-Path "requirements.txt") {
            pip install -r requirements.txt --upgrade
        }
        
        Write-Status "Dependencies updated"
    }
    
    # Step 3: Build
    $currentStep++
    Write-Step $currentStep $totalSteps "Building"
    Invoke-Step "Build" {
        if (Test-Path "build.ps1") {
            .\build.ps1 -Release
        } elseif (Test-Path "CMakeLists.txt") {
            cmake -B build -DCMAKE_BUILD_TYPE=Release
            cmake --build build --config Release
        } else {
            throw "No build system found"
        }
    }
    
    # Step 4: Run tests
    if (-not $SkipTests) {
        $currentStep++
        Write-Step $currentStep $totalSteps "Running Tests"
        Invoke-Step "Test Execution" {
            if (Test-Path "run_tests.ps1") {
                .\run_tests.ps1
            } else {
                Write-Warning "No test script found"
            }
        }
    }
    
    # Step 5: Security scan
    $currentStep++
    Write-Step $currentStep $totalSteps "Security Scan"
    Invoke-Step "Security Scan" {
        if (Test-Path "security-audit.ps1") {
            .\security-audit.ps1 -ScanType Quick
        } else {
            Write-Warning "Security audit script not found"
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Build & Test Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}

function Invoke-DeployStagingWorkflow {
    $totalSteps = 6
    $currentStep = 0
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Staging Deployment Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Step 1: Pre-deployment checks
    $currentStep++
    Write-Step $currentStep $totalSteps "Pre-deployment Checks"
    Invoke-Step "Pre-deployment Validation" {
        # Check if on correct branch
        $branch = git rev-parse --abbrev-ref HEAD
        if ($branch -ne "develop") {
            throw "Must be on 'develop' branch for staging deployment (currently on '$branch')"
        }
        
        # Check for uncommitted changes
        $status = git status --porcelain
        if ($status) {
            throw "Uncommitted changes found. Please commit or stash first."
        }
        
        Write-Status "Pre-deployment checks passed"
    }
    
    # Step 2: Build release
    $currentStep++
    Write-Step $currentStep $totalSteps "Building Release"
    Invoke-Step "Release Build" {
        if (Test-Path "build-release.ps1") {
            .\build-release.ps1
        } else {
            throw "Release build script not found"
        }
    }
    
    # Step 3: Run full test suite
    if (-not $SkipTests) {
        $currentStep++
        Write-Step $currentStep $totalSteps "Running Full Test Suite"
        Invoke-Step "Full Test Suite" {
            if (Test-Path "run_tests.ps1") {
                .\run_tests.ps1 -Full
            }
        }
    }
    
    # Step 4: Create deployment package
    $currentStep++
    Write-Step $currentStep $totalSteps "Creating Deployment Package"
    Invoke-Step "Package Creation" {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $packageName = "rawrxd_staging_$timestamp.zip"
        
        if (Test-Path "dist") {
            Compress-Archive -Path "dist\*" -DestinationPath $packageName
            Write-Status "Package created: $packageName"
        } else {
            throw "Build output not found"
        }
    }
    
    # Step 5: Deploy to staging
    $currentStep++
    Write-Step $currentStep $totalSteps "Deploying to Staging"
    Invoke-Step "Staging Deployment" {
        if (Test-Path "deploy.ps1") {
            .\deploy.ps1 -Environment staging
        } else {
            Write-Warning "Deploy script not found, manual deployment required"
        }
    }
    
    # Step 6: Post-deployment verification
    $currentStep++
    Write-Step $currentStep $totalSteps "Post-deployment Verification"
    Invoke-Step "Deployment Verification" {
        if (Test-Path "health-checker.ps1") {
            .\health-checker.ps1 -Environment staging
        } else {
            Write-Warning "Health check script not found"
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Staging Deployment Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}

function Invoke-DeployProductionWorkflow {
    $totalSteps = 8
    $currentStep = 0
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Production Deployment Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to deploy to PRODUCTION? (type 'yes' to confirm)"
        if ($confirm -ne "yes") {
            Write-Status "Deployment cancelled"
            return
        }
    }
    
    # Step 1: Pre-deployment checks
    $currentStep++
    Write-Step $currentStep $totalSteps "Pre-deployment Checks"
    Invoke-Step "Pre-deployment Validation" {
        $branch = git rev-parse --abbrev-ref HEAD
        if ($branch -ne "main") {
            throw "Must be on 'main' branch for production deployment"
        }
        
        $status = git status --porcelain
        if ($status) {
            throw "Uncommitted changes found"
        }
        
        Write-Status "Pre-deployment checks passed"
    }
    
    # Step 2: Create release tag
    $currentStep++
    Write-Step $currentStep $totalSteps "Creating Release Tag"
    Invoke-Step "Release Tagging" {
        if (-not $Version) {
            $Version = Read-Host "Enter version number (e.g., 3.2.0)"
        }
        
        git tag -a "v$Version" -m "Release v$Version"
        git push origin "v$Version"
        Write-Status "Release tag v$Version created"
    }
    
    # Step 3: Build production release
    $currentStep++
    Write-Step $currentStep $totalSteps "Building Production Release"
    Invoke-Step "Production Build" {
        if (Test-Path "build-release.ps1") {
            .\build-release.ps1 -Production
        }
    }
    
    # Step 4: Full security audit
    $currentStep++
    Write-Step $currentStep $totalSteps "Security Audit"
    Invoke-Step "Security Audit" {
        if (Test-Path "security-audit.ps1") {
            .\security-audit.ps1 -ScanType Full -FailOnIssues
        }
    }
    
    # Step 5: Run all tests
    if (-not $SkipTests) {
        $currentStep++
        Write-Step $currentStep $totalSteps "Running All Tests"
        Invoke-Step "Complete Test Suite" {
            if (Test-Path "run_all_tests.ps1") {
                .\run_all_tests.ps1
            }
        }
    }
    
    # Step 6: Create deployment package
    $currentStep++
    Write-Step $currentStep $totalSteps "Creating Deployment Package"
    Invoke-Step "Package Creation" {
        if (Test-Path "create-release-package.ps1") {
            .\create-release-package.ps1 -Version $Version
        }
    }
    
    # Step 7: Deploy to production
    $currentStep++
    Write-Step $currentStep $totalSteps "Deploying to Production"
    Invoke-Step "Production Deployment" {
        if (Test-Path "deploy.ps1") {
            .\deploy.ps1 -Environment production -Version $Version
        }
    }
    
    # Step 8: Post-deployment verification
    $currentStep++
    Write-Step $currentStep $totalSteps "Post-deployment Verification"
    Invoke-Step "Production Verification" {
        if (Test-Path "health-checker.ps1") {
            .\health-checker.ps1 -Environment production
        }
        
        # Smoke tests
        if (Test-Path "smoke_test.ps1") {
            .\smoke_test.ps1 -Environment production
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Production Deployment Complete!" -ForegroundColor Green
    Write-Host "Version v$Version is now live" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}

function Invoke-BackupWorkflow {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = "backup_$timestamp"
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Backup Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Invoke-Step "Create Backup" {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
        
        # Backup configuration
        if (Test-Path "config") {
            Copy-Item "config" "$backupDir\" -Recurse
        }
        
        # Backup data
        if (Test-Path "data") {
            Copy-Item "data" "$backupDir\" -Recurse
        }
        
        # Backup logs (last 7 days)
        if (Test-Path "logs") {
            $cutoff = (Get-Date).AddDays(-7)
            Get-ChildItem "logs" | Where-Object { $_.LastWriteTime -gt $cutoff } | 
                Copy-Item -Destination "$backupDir\logs\" -Force
        }
        
        # Create archive
        $archiveName = "$backupDir.zip"
        Compress-Archive -Path $backupDir -DestinationPath $archiveName
        Remove-Item $backupDir -Recurse -Force
        
        Write-Success "Backup created: $archiveName"
    }
}

function Invoke-CleanWorkflow {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Clean Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if (-not $Force) {
        $confirm = Read-Host "This will remove build artifacts and temporary files. Continue? (y/N)"
        if ($confirm -ne "y") {
            return
        }
    }
    
    Invoke-Step "Clean Project" {
        # Remove build directories
        $dirs = @("build", "dist", "__pycache__", "node_modules", ".pytest_cache")
        foreach ($dir in $dirs) {
            if (Test-Path $dir) {
                Remove-Item $dir -Recurse -Force
                Write-Status "Removed: $dir"
            }
        }
        
        # Clean temporary files
        Get-ChildItem -Filter "*.tmp" -Recurse | Remove-Item -Force
        Get-ChildItem -Filter "*.log.old" -Recurse | Remove-Item -Force
        
        # Clean old backups (keep last 10)
        Get-ChildItem "backup_*.zip" | Sort-Object LastWriteTime -Descending | 
            Select-Object -Skip 10 | Remove-Item -Force
        
        Write-Success "Project cleaned"
    }
}

function Invoke-UpdateWorkflow {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Update Workflow" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Invoke-Step "Update Project" {
        # Pull latest changes
        git fetch origin
        $behind = git rev-list HEAD..origin/main --count
        
        if ($behind -gt 0) {
            Write-Status "$behind commits behind. Updating..."
            git pull origin main
            
            # Update submodules
            git submodule update --init --recursive
            
            # Update dependencies
            if (Test-Path "requirements.txt") {
                pip install -r requirements.txt --upgrade
            }
            
            if (Test-Path "package.json") {
                npm update
            }
            
            Write-Success "Project updated"
        } else {
            Write-Status "Already up to date"
        }
    }
}

function Show-Summary {
    $duration = (Get-Date) - $script:StartTime
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Workflow Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Workflow: $Workflow" -ForegroundColor White
    Write-Host "Environment: $Environment" -ForegroundColor White
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Steps Completed: $script:StepsCompleted" -ForegroundColor Green
    
    if ($script:StepsFailed -gt 0) {
        Write-Host "Steps Failed: $script:StepsFailed" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "Status: SUCCESS" -ForegroundColor Green
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Workflow Automation" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No changes will be made"
        Write-Host ""
    }
    
    switch ($Workflow) {
        "DevSetup" { Invoke-DevSetupWorkflow }
        "BuildTest" { Invoke-BuildTestWorkflow }
        "DeployStaging" { Invoke-DeployStagingWorkflow }
        "DeployProduction" { Invoke-DeployProductionWorkflow }
        "Backup" { Invoke-BackupWorkflow }
        "Clean" { Invoke-CleanWorkflow }
        "Update" { Invoke-UpdateWorkflow }
    }
    
    Show-Summary
}

Main
