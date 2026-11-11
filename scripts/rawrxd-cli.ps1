# RawrXD Unified CLI
# Central command-line interface for all RawrXD tooling

param(
    [Parameter(Mandatory=$false, Position=0)]
    [ValidateSet("build", "test", "deploy", "analyze", "monitor", "docs", "model", "quality", "health", "clean", "init", "help")]
    [string]$Command = "help",
    
    [Parameter(Mandatory=$false, Position=1)]
    [string]$SubCommand,
    
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

$RawrXDVersion = "3.2.0"
$ScriptsDir = $PSScriptRoot

function Write-Header { 
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    RawrXD CLI v$RawrXDVersion                    ║" -ForegroundColor Cyan
    Write-Host "║           Vision & Generation System Command Line            ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Show-Help {
    Write-Header
    
    Write-Host "USAGE:" -ForegroundColor White
    Write-Host "  rawrxd-cli.ps1 <command> [subcommand] [options]" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "COMMANDS:" -ForegroundColor White
    Write-Host ""
    
    $commands = @{
        "build" = @{
            Description = "Build management and orchestration"
            SubCommands = @("full", "quick", "clean", "release", "debug")
            Examples = @(
                "rawrxd-cli.ps1 build full                    # Full build with all targets"
                "rawrxd-cli.ps1 build quick                   # Quick incremental build"
                "rawrxd-cli.ps1 build release -Version 3.2.0  # Release build"
            )
        }
        "test" = @{
            Description = "Test execution and reporting"
            SubCommands = @("all", "unit", "integration", "performance", "smoke")
            Examples = @(
                "rawrxd-cli.ps1 test smoke                    # Quick smoke tests"
                "rawrxd-cli.ps1 test all -Coverage            # All tests with coverage"
                "rawrxd-cli.ps1 test unit -Filter Core        # Unit tests matching 'Core'"
            )
        }
        "deploy" = @{
            Description = "Deployment management"
            SubCommands = @("staging", "production", "canary", "blue-green")
            Examples = @(
                "rawrxd-cli.ps1 deploy staging              # Deploy to staging"
                "rawrxd-cli.ps1 deploy production -Strategy blue-green"
            )
        }
        "analyze" = @{
            Description = "Code analysis and reporting"
            SubCommands = @("unlinked", "complexity", "dependencies", "coverage")
            Examples = @(
                "rawrxd-cli.ps1 analyze unlinked            # Analyze unlinked files"
                "rawrxd-cli.ps1 analyze complexity          # Complexity analysis"
            )
        }
        "monitor" = @{
            Description = "System monitoring and health checks"
            SubCommands = @("start", "status", "alerts", "metrics")
            Examples = @(
                "rawrxd-cli.ps1 monitor start               # Start continuous monitoring"
                "rawrxd-cli.ps1 monitor status                # Show current status"
            )
        }
        "docs" = @{
            Description = "Documentation generation"
            SubCommands = @("generate", "serve", "api", "architecture")
            Examples = @(
                "rawrxd-cli.ps1 docs generate               # Generate all documentation"
                "rawrxd-cli.ps1 docs serve -Port 8080       # Serve docs locally"
            )
        }
        "model" = @{
            Description = "Model registry management"
            SubCommands = @("list", "add", "remove", "download", "verify")
            Examples = @(
                "rawrxd-cli.ps1 model list                  # List registered models"
                "rawrxd-cli.ps1 model add -Path model.gguf  # Add model to registry"
            )
        }
        "quality" = @{
            Description = "Code quality gates"
            SubCommands = @("check", "fix", "report")
            Examples = @(
                "rawrxd-cli.ps1 quality check               # Run quality checks"
                "rawrxd-cli.ps1 quality check -Mode ci      # CI mode checks"
            )
        }
        "health" = @{
            Description = "Workspace health monitoring"
            SubCommands = @("check", "cleanup", "repair")
            Examples = @(
                "rawrxd-cli.ps1 health check                # Check workspace health"
                "rawrxd-cli.ps1 health cleanup              # Clean up temp files"
            )
        }
        "clean" = @{
            Description = "Clean build artifacts and caches"
            SubCommands = @("all", "build", "cache", "logs")
            Examples = @(
                "rawrxd-cli.ps1 clean all                   # Clean everything"
                "rawrxd-cli.ps1 clean build                 # Clean build directory"
            )
        }
        "init" = @{
            Description = "Initialize development environment"
            SubCommands = @("dev", "ci", "production")
            Examples = @(
                "rawrxd-cli.ps1 init dev                    # Setup dev environment"
            )
        }
    }
    
    foreach ($cmd in $commands.GetEnumerator() | Sort-Object Key) {
        Write-Host "  $($cmd.Key.PadRight(12))" -ForegroundColor Yellow -NoNewline
        Write-Host $cmd.Value.Description -ForegroundColor White
        
        if ($cmd.Value.SubCommands.Count -gt 0) {
            Write-Host "    Subcommands: $($cmd.Value.SubCommands -join ', ')" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor White
    Write-Host ""
    
    foreach ($cmd in $commands.GetEnumerator() | Sort-Object Key) {
        if ($cmd.Value.Examples) {
            foreach ($example in $cmd.Value.Examples) {
                Write-Host "  $example" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }
    
    Write-Host "For detailed help on a command, use:" -ForegroundColor White
    Write-Host "  rawrxd-cli.ps1 <command> --help" -ForegroundColor Gray
    Write-Host ""
}

function Invoke-BuildCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\build-orchestrator.ps1"
    
    switch ($SubCmd) {
        "full" { 
            Write-Status "Starting full build..."
            & $scriptPath -BuildType full -ParallelJobs 8 @Args
        }
        "quick" { 
            Write-Status "Starting quick build..."
            & $scriptPath -BuildType quick @Args
        }
        "clean" { 
            Write-Status "Cleaning build artifacts..."
            if (Test-Path "D:\rawrxd\build") {
                Remove-Item "D:\rawrxd\build" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Success "Build directory cleaned"
        }
        "release" { 
            Write-Status "Starting release build..."
            & $scriptPath -BuildType release -SkipTests:$false @Args
        }
        "debug" { 
            Write-Status "Starting debug build..."
            & $scriptPath -BuildType debug @Args
        }
        default {
            & $scriptPath @Args
        }
    }
}

function Invoke-TestCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\test-harness.ps1"
    
    switch ($SubCmd) {
        "all" { & $scriptPath -TestSuite all @Args }
        "unit" { & $scriptPath -TestSuite unit @Args }
        "integration" { & $scriptPath -TestSuite integration @Args }
        "performance" { & $scriptPath -TestSuite performance @Args }
        "smoke" { & $scriptPath -TestSuite smoke @Args }
        default { & $scriptPath -TestSuite smoke @Args }
    }
}

function Invoke-DeployCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\deployment-orchestrator.ps1"
    
    if ($SubCmd) {
        & $scriptPath -Environment $SubCmd @Args
    } else {
        & $scriptPath @Args
    }
}

function Invoke-AnalyzeCommand {
    param([string]$SubCmd, [array]$Args)
    
    switch ($SubCmd) {
        "unlinked" {
            $scriptPath = "$ScriptsDir\analyze-unlinked-files.ps1"
            & $scriptPath -GenerateReport @Args
        }
        "complexity" {
            Write-Status "Running complexity analysis..."
            # Would call complexity analyzer
        }
        "dependencies" {
            Write-Status "Analyzing dependencies..."
            # Would call dependency analyzer
        }
        "coverage" {
            Write-Status "Analyzing code coverage..."
            # Would call coverage analyzer
        }
        default {
            # Run all analyses
            Write-Status "Running comprehensive analysis..."
        }
    }
}

function Invoke-MonitorCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\workspace-health-monitor.ps1"
    
    switch ($SubCmd) {
        "start" { & $scriptPath -Continuous @Args }
        "status" { & $scriptPath @Args }
        "alerts" { 
            Write-Status "Showing recent alerts..."
            # Would show alerts from log
        }
        "metrics" {
            Write-Status "Exporting metrics..."
            & $scriptPath -ExportMetrics @Args
        }
        default { & $scriptPath @Args }
    }
}

function Invoke-DocsCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\documentation-generator.ps1"
    
    switch ($SubCmd) {
        "generate" { 
            & $scriptPath -IncludeApiDocs -IncludeArchitecture @Args
        }
        "serve" { 
            & $scriptPath -Serve @Args
        }
        "api" { 
            & $scriptPath -IncludeApiDocs @Args
        }
        "architecture" { 
            & $scriptPath -IncludeArchitecture @Args
        }
        default { 
            & $scriptPath -IncludeApiDocs -IncludeArchitecture @Args
        }
    }
}

function Invoke-ModelCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\model-registry-cli.ps1"
    
    if ($SubCmd) {
        & $scriptPath -Command $SubCmd @Args
    } else {
        & $scriptPath -Command list @Args
    }
}

function Invoke-QualityCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\code-quality-gate.ps1"
    
    switch ($SubCmd) {
        "check" { & $scriptPath -Mode quick @Args }
        "fix" { & $scriptPath -Mode quick -Fix @Args }
        "report" { & $scriptPath -Mode full -ReportFormat html @Args }
        default { & $scriptPath @Args }
    }
}

function Invoke-HealthCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\workspace-health-monitor.ps1"
    
    switch ($SubCmd) {
        "check" { & $scriptPath @Args }
        "cleanup" { 
            Write-Status "Running cleanup..."
            # Would trigger cleanup
        }
        "repair" {
            Write-Status "Running repair..."
            # Would trigger repair
        }
        default { & $scriptPath @Args }
    }
}

function Invoke-CleanCommand {
    param([string]$SubCmd, [array]$Args)
    
    switch ($SubCmd) {
        "all" {
            Write-Status "Cleaning all artifacts..."
            $paths = @("build", "output", "logs", ".buildcache", "test-reports")
            foreach ($path in $paths) {
                $fullPath = "D:\rawrxd\$path"
                if (Test-Path $fullPath) {
                    Remove-Item $fullPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Cleaned: $fullPath"
                }
            }
            Write-Success "All artifacts cleaned"
        }
        "build" {
            Write-Status "Cleaning build directory..."
            if (Test-Path "D:\rawrxd\build") {
                Remove-Item "D:\rawrxd\build" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Success "Build directory cleaned"
        }
        "cache" {
            Write-Status "Cleaning cache..."
            if (Test-Path "D:\rawrxd\.buildcache") {
                Remove-Item "D:\rawrxd\.buildcache" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Success "Cache cleaned"
        }
        "logs" {
            Write-Status "Cleaning logs..."
            if (Test-Path "D:\rawrxd\logs") {
                Get-ChildItem "D:\rawrxd\logs" -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force
            }
            Write-Success "Old logs cleaned"
        }
        default {
            Invoke-CleanCommand -SubCmd "all" -Args $Args
        }
    }
}

function Invoke-InitCommand {
    param([string]$SubCmd, [array]$Args)
    
    $scriptPath = "$ScriptsDir\dev-setup.ps1"
    
    switch ($SubCmd) {
        "dev" { 
            Write-Status "Setting up development environment..."
            & $scriptPath -InstallBuildTools -InstallGit -InstallCMake @Args
        }
        "ci" {
            Write-Status "Setting up CI environment..."
            # CI-specific setup
        }
        "production" {
            Write-Status "Setting up production environment..."
            # Production-specific setup
        }
        default {
            & $scriptPath @Args
        }
    }
}

# Main execution
function Main {
    if ($Command -eq "help" -or $Command -eq "--help" -or $Command -eq "-h") {
        Show-Help
        return
    }
    
    Write-Header
    
    # Check if subcommand is actually a help flag
    if ($SubCommand -eq "--help" -or $SubCommand -eq "-h") {
        Write-Host "Help for '$Command' command:" -ForegroundColor White
        Write-Host ""
        
        # Show specific help for command
        $scriptPath = "$ScriptsDir\$Command*.ps1" | Get-Item -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($scriptPath) {
            & $scriptPath.FullName -Help 2>$null || Write-Host "Run the script with -Help for details" -ForegroundColor Gray
        }
        return
    }
    
    # Execute command
    switch ($Command) {
        "build" { Invoke-BuildCommand -SubCmd $SubCommand -Args $Arguments }
        "test" { Invoke-TestCommand -SubCmd $SubCommand -Args $Arguments }
        "deploy" { Invoke-DeployCommand -SubCmd $SubCommand -Args $Arguments }
        "analyze" { Invoke-AnalyzeCommand -SubCmd $SubCommand -Args $Arguments }
        "monitor" { Invoke-MonitorCommand -SubCmd $SubCommand -Args $Arguments }
        "docs" { Invoke-DocsCommand -SubCmd $SubCommand -Args $Arguments }
        "model" { Invoke-ModelCommand -SubCmd $SubCommand -Args $Arguments }
        "quality" { Invoke-QualityCommand -SubCmd $SubCommand -Args $Arguments }
        "health" { Invoke-HealthCommand -SubCmd $SubCommand -Args $Arguments }
        "clean" { Invoke-CleanCommand -SubCmd $SubCommand -Args $Arguments }
        "init" { Invoke-InitCommand -SubCmd $SubCommand -Args $Arguments }
        default { Show-Help }
    }
    
    Write-Host ""
    Write-Success "Command '$Command' completed!"
}

Main
