# RawrXD Scripts & Utilities

This directory contains automation scripts and utilities for the RawrXD Vision & Generation System.

## Quick Reference

| Script | Purpose | Usage |
|--------|---------|-------|
| `dev-setup.ps1` | Development environment setup | `.\dev-setup.ps1` |
| `build-release.ps1` | Release build automation | `.\build-release.ps1` |
| `benchmark-runner.ps1` | Performance benchmarking | `.\benchmark-runner.ps1` |
| `ci-cd-pipeline.ps1` | CI/CD pipeline automation | `.\ci-cd-pipeline.ps1` |
| `model-manager.ps1` | Model download & management | `.\model-manager.ps1` |
| `log-analyzer.ps1` | Log file analysis | `.\log-analyzer.ps1` |
| `diagnostics.ps1` | System health diagnostics | `.\diagnostics.ps1` |
| `docker-manager.ps1` | Docker container management | `.\docker-manager.ps1` |
| `api-tester.ps1` | API endpoint testing | `.\api-tester.ps1` |
| `config-manager.ps1` | Configuration management | `.\config-manager.ps1` |
| `security-audit.ps1` | Security scanning & audit | `.\security-audit.ps1` |
| `performance-profiler.ps1` | Performance profiling | `.\performance-profiler.ps1` |
| `update-checker.ps1` | Update management | `.\update-checker.ps1` |
| `cloud-deploy.ps1` | Cloud deployment (AWS/Azure/GCP/K8s) | `.\cloud-deploy.ps1` |
| `backup-manager.ps1` | Backup & restore management | `.\backup-manager.ps1` |
| `license-manager.ps1` | License activation & management | `.\license-manager.ps1` |
| `test-runner.ps1` | Unified test execution | `.\test-runner.ps1` |
| `monitor-dashboard.ps1` | Real-time monitoring dashboard | `.\monitor-dashboard.ps1` |
| `data-migrator.ps1` | Data migration & conversion | `.\data-migrator.ps1` |
| `notification-sender.ps1` | Multi-channel notifications | `.\notification-sender.ps1` |
| `report-generator.ps1` | Report generation | `.\report-generator.ps1` |
| `scheduler.ps1` | Task scheduling | `.\scheduler.ps1` |
| `health-checker.ps1` | System health monitoring | `.\health-checker.ps1` |
| `dependency-checker.ps1` | Dependency validation | `.\dependency-checker.ps1` |

## Development Setup

### `dev-setup.ps1`

Sets up a complete development environment for RawrXD.

**Features:**
- Installs Chocolatey package manager
- Installs Visual Studio Build Tools
- Installs CMake, Git, Python
- Installs CUDA Toolkit (optional)
- Installs Docker Desktop (optional)
- Installs Vulkan SDK
- Clones and configures the repository
- Creates desktop shortcuts

**Usage:**
```powershell
# Full setup (requires Administrator)
.\dev-setup.ps1

# Minimal setup without Docker/CUDA
.\dev-setup.ps1 -Minimal -SkipCUDA -SkipDocker

# Custom installation path
.\dev-setup.ps1 -InstallPath "D:\Development\RawrXD"
```

## Build Automation

### `build-release.ps1`

Creates optimized release builds for distribution.

**Features:**
- Multiple build configurations (Release, RelWithDebInfo, MinSizeRel)
- Optional CUDA support
- Optional Vulkan support
- Optional AVX-512 support
- Static linking option
- Automatic binary signing
- Package generation with checksums

**Usage:**
```powershell
# Standard release build
.\build-release.ps1

# With CUDA and Vulkan
.\build-release.ps1 -EnableCUDA -EnableVulkan

# Static linked build with packaging
.\build-release.ps1 -StaticLink -Package -Version "3.2.0"

# Full production build
.\build-release.ps1 -BuildType Release -EnableCUDA -EnableVulkan -Package -SignBinaries
```

## Performance Testing

### `benchmark-runner.ps1`

Comprehensive performance benchmarking suite.

**Benchmark Suites:**
- `Quick` - Fast smoke tests (2-3 minutes)
- `Standard` - Standard benchmarks (10-15 minutes)
- `Extended` - Comprehensive testing (30-60 minutes)
- `Stress` - Long-running stress tests (1-2 hours)

**Usage:**
```powershell
# Quick benchmark
.\benchmark-runner.ps1 -Suite Quick

# Standard suite with specific model
.\benchmark-runner.ps1 -Suite Standard -ModelPath "models\llama-2-7b.Q4_K_M.gguf"

# Extended suite with baseline comparison
.\benchmark-runner.ps1 -Suite Extended -CompareBaseline -BaselinePath "benchmarks\baseline.json"

# Stress test on specific device
.\benchmark-runner.ps1 -Suite Stress -Device cuda
```

## CI/CD Pipeline

### `ci-cd-pipeline.ps1`

Complete CI/CD pipeline automation.

**Pipeline Stages:**
1. **Build** - Configure and compile
2. **Test** - Run test suite and benchmarks
3. **Security** - Static analysis and vulnerability scanning
4. **Package** - Create distribution packages
5. **Deploy** - Deploy to staging/production

**Usage:**
```powershell
# Full pipeline
.\ci-cd-pipeline.ps1 -Stage Full -Environment staging

# Build only
.\ci-cd-pipeline.ps1 -Stage Build

# Build and test
.\ci-cd-pipeline.ps1 -Stage Test

# Production deployment (with approval gates)
.\ci-cd-pipeline.ps1 -Stage Deploy -Environment production

# Dry run (no actual changes)
.\ci-cd-pipeline.ps1 -Stage Full -DryRun
```

## Model Management

### `model-manager.ps1`

Manages GGUF model downloads, validation, and configuration.

**Registry Models:**
- `llama-2-7b` - General purpose chat model
- `llama-2-13b` - Higher quality chat model
- `codellama-7b` - Code completion and generation
- `mistral-7b` - High performance general model
- `mixtral-8x7b` - Mixture of Experts model
- `phi-2` - Compact but powerful model

**Usage:**
```powershell
# List available and installed models
.\model-manager.ps1 -Action List

# Download from registry
.\model-manager.ps1 -Action Download -ModelName "llama-2-7b"

# Download custom model
.\model-manager.ps1 -Action Download -ModelUrl "https://example.com/model.gguf" -ModelName "custom"

# Validate installed models
.\model-manager.ps1 -Action Validate

# Get model information
.\model-manager.ps1 -Action Info -ModelName "llama-2-7b"

# Remove model
.\model-manager.ps1 -Action Remove -ModelName "old-model" -Force

# Export configuration
.\model-manager.ps1 -Action Configure
```

## Log Analysis

### `log-analyzer.ps1`

Analyzes log files for errors, patterns, and performance metrics.

**Analysis Types:**
- `Errors` - Error and warning detection
- `Performance` - Performance metrics extraction
- `Security` - Security event detection
- `All` - Complete analysis

**Usage:**
```powershell
# Analyze all logs
.\log-analyzer.ps1 -AnalysisType All

# Check for errors only
.\log-analyzer.ps1 -AnalysisType Errors

# Real-time monitoring
.\log-analyzer.ps1 -RealTime

# Export results
.\log-analyzer.ps1 -AnalysisType Performance -ExportJson

# Analyze specific log file
.\log-analyzer.ps1 -LogPath "logs\rawrxd.log" -AnalysisType Errors
```

## System Diagnostics

### `diagnostics.ps1`

Comprehensive system health and diagnostics checker.

**Scan Types:**
- `Quick` - Essential checks (disk, memory, services)
- `Full` - Complete system scan
- `Performance` - Performance-focused checks
- `Network` - Network configuration
- `Hardware` - Hardware health check

**Usage:**
```powershell
# Quick diagnostic
.\diagnostics.ps1 -ScanType Quick

# Full system scan
.\diagnostics.ps1 -ScanType Full

# Performance check
.\diagnostics.ps1 -ScanType Performance

# Auto-fix issues
.\diagnostics.ps1 -ScanType Quick -FixIssues

# Export report
.\diagnostics.ps1 -ScanType Full -ExportReport
```

## Docker Management

### `docker-manager.ps1`

Manages Docker containers, images, and deployments.

**Actions:**
- `Up` - Start containers
- `Down` - Stop containers
- `Build` - Build images
- `Logs` - View logs
- `Shell` - Enter container shell
- `Clean` - Clean up environment
- `Status` - Show status
- `Update` - Update containers
- `Scale` - Scale services

**Usage:**
```powershell
# Start all containers
.\docker-manager.ps1 -Action Up -Detach

# View logs
.\docker-manager.ps1 -Action Logs -Service rawrxd

# Enter container shell
.\docker-manager.ps1 -Action Shell -Service rawrxd

# Scale service
.\docker-manager.ps1 -Action Scale -Service rawrxd-worker -ScaleCount 4

# Clean up everything
.\docker-manager.ps1 -Action Clean -RemoveImages

# Production deployment
.\docker-manager.ps1 -Action Up -Environment production -Detach
```

## API Testing

### `api-tester.ps1`

Comprehensive API endpoint testing and validation.

**Test Suites:**
- `All` - Run all tests
- `Health` - Health endpoint tests
- `Models` - Model API tests
- `Generate` - Generation API tests
- `System` - System API tests
- `Custom` - Custom endpoint test

**Usage:**
```powershell
# Run all tests
.\api-tester.ps1 -BaseUrl "http://localhost:8080"

# Test with API key
.\api-tester.ps1 -ApiKey "your-api-key" -TestSuite All

# Test specific suite
.\api-tester.ps1 -TestSuite Health

# Custom endpoint test
.\api-tester.ps1 -TestSuite Custom -CustomEndpoint "/api/v1/custom" -CustomMethod POST -CustomBody '{"test": true}'

# Export HTML report
.\api-tester.ps1 -TestSuite All -OutputFormat Html -OutputPath "test-results"
```

## Configuration Management

### `config-manager.ps1`

Manages configuration files, environment variables, and settings.

**Actions:**
- `Show` - Display configuration
- `Edit` - Modify configuration
- `Validate` - Validate configuration
- `Backup` - Backup configuration
- `Restore` - Restore from backup
- `Reset` - Reset to defaults

**Usage:**
```powershell
# Show current configuration
.\config-manager.ps1 -Action Show

# Show specific key
.\config-manager.ps1 -Action Show -Key "server.port"

# Edit configuration
.\config-manager.ps1 -Action Edit -Key "server.port" -Value 8081

# Validate configuration
.\config-manager.ps1 -Action Validate

# Backup configuration
.\config-manager.ps1 -Action Backup

# Restore configuration
.\config-manager.ps1 -Action Restore -Key "backups/config/config-backup-20240115-120000.json"

# Reset to defaults
.\config-manager.ps1 -Action Reset -Force
```

## Security Audit

### `security-audit.ps1`

Comprehensive security scanning and vulnerability assessment.

**Scan Types:**
- `Quick` - Fast security check (secrets, config)
- `Full` - Complete security audit
- `Code` - Code vulnerability scan
- `Dependencies` - Dependency vulnerability check
- `Configuration` - Configuration security scan
- `Secrets` - Secret detection only

**Usage:**
```powershell
# Quick security scan
.\security-audit.ps1 -ScanType Quick

# Full security audit
.\security-audit.ps1 -ScanType Full -ExportReport

# Auto-fix issues
.\security-audit.ps1 -ScanType Full -FixIssues

# Export and fail on issues (CI/CD)
.\security-audit.ps1 -ScanType Full -ExportReport -FailOnIssues
```

## Performance Profiling

### `performance-profiler.ps1`

CPU, memory, and GPU profiling for performance analysis.

**Profile Types:**
- `CPU` - CPU usage profiling
- `Memory` - Memory usage profiling
- `GPU` - GPU utilization profiling
- `IO` - I/O operations profiling
- `Network` - Network usage profiling
- `All` - Complete system profiling

**Usage:**
```powershell
# Profile all metrics for 60 seconds
.\performance-profiler.ps1 -ProfileType All -Duration 60

# Real-time CPU profiling
.\performance-profiler.ps1 -ProfileType CPU -RealTime

# Memory profiling with custom interval
.\performance-profiler.ps1 -ProfileType Memory -Duration 300 -Interval 5

# Profile specific process
.\performance-profiler.ps1 -ProfileType All -ProcessName "rawrxd"
```

## Update Management

### `update-checker.ps1`

Checks for updates and manages version upgrades.

**Actions:**
- `Check` - Check for available updates
- `Download` - Download latest version
- `Install` - Download and install update
- `List` - Show version history
- `Rollback` - Rollback to previous version

**Channels:**
- `stable` - Stable releases
- `beta` - Beta/pre-release versions
- `nightly` - Nightly builds

**Usage:**
```powershell
# Check for updates
.\update-checker.ps1 -Action Check

# Check beta channel
.\update-checker.ps1 -Action Check -Channel beta

# Download update
.\update-checker.ps1 -Action Download

# Install with backup
.\update-checker.ps1 -Action Install -Backup

# Force reinstall
.\update-checker.ps1 -Action Install -Force

# View version history
.\update-checker.ps1 -Action List
```

## Cloud Deployment

### `cloud-deploy.ps1`

Deploys RawrXD to cloud providers (AWS, Azure, GCP, Kubernetes, Docker).

**Providers:**
- `AWS` - Amazon Web Services (CloudFormation)
- `Azure` - Microsoft Azure (ARM templates)
- `GCP` - Google Cloud Platform (Deployment Manager)
- `Kubernetes` - K8s cluster deployment
- `Docker` - Docker Compose deployment

**Usage:**
```powershell
# Deploy to AWS
.\cloud-deploy.ps1 -Provider AWS -Environment production -Region us-east-1

# Deploy to Azure
.\cloud-deploy.ps1 -Provider Azure -Environment staging -Region eastus

# Deploy to Kubernetes
.\cloud-deploy.ps1 -Provider Kubernetes -Environment production

# Dry run (no actual deployment)
.\cloud-deploy.ps1 -Provider AWS -DryRun
```

## Backup Management

### `backup-manager.ps1`

Comprehensive backup and restore management.

**Actions:**
- `Create` - Create new backup
- `Restore` - Restore from backup
- `List` - List available backups
- `Delete` - Delete backup
- `Schedule` - Schedule automatic backups
- `Verify` - Verify backup integrity

**Destinations:**
- `local` - Local filesystem
- `s3` - Amazon S3
- `azure` - Azure Blob Storage
- `gcs` - Google Cloud Storage

**Usage:**
```powershell
# Create compressed backup
.\backup-manager.ps1 -Action Create -Sources @("models", "config") -Compress

# Restore from backup
.\backup-manager.ps1 -Action Restore -BackupName "backup-20240115-120000"

# List backups
.\backup-manager.ps1 -Action List

# Schedule daily backups
.\backup-manager.ps1 -Action Schedule -Sources @("models", "config")

# Upload to S3
.\backup-manager.ps1 -Action Create -Destination s3 -Compress
```

## License Management

### `license-manager.ps1`

Manages license keys, activation, and compliance.

**Actions:**
- `Show` - Display license information
- `Activate` - Activate license key
- `Deactivate` - Deactivate license
- `Validate` - Validate current license
- `Generate` - Generate new license (admin only)
- `List` - Show license usage

**License Types:**
- `Community` - Free, single user/device
- `Personal` - Individual use, up to 3 devices
- `Professional` - Small teams, up to 10 devices
- `Enterprise` - Unlimited users/devices

**Usage:**
```powershell
# Show current license
.\license-manager.ps1 -Action Show

# Activate license
.\license-manager.ps1 -Action Activate -LicenseKey "XXXX-XXXX-XXXX-XXXX"

# Offline activation
.\license-manager.ps1 -Action Activate -LicenseKey "XXXX-XXXX-XXXX-XXXX" -Offline

# Deactivate license
.\license-manager.ps1 -Action Deactivate

# Validate license
.\license-manager.ps1 -Action Validate
```

## Test Runner

### `test-runner.ps1`

Unified test execution for PowerShell, C++, and Python tests.

**Test Suites:**
- `All` - Run all tests
- `Unit` - Unit tests only
- `Integration` - Integration tests
- `E2E` - End-to-end tests
- `Performance` - Performance tests
- `Security` - Security tests
- `Smoke` - Smoke tests

**Features:**
- Multi-language support (PowerShell, C++, Python)
- Parallel execution
- Code coverage reporting
- HTML/JUnit/TRX report formats
- Baseline comparison

**Usage:**
```powershell
# Run all tests
.\test-runner.ps1 -TestSuite All

# Run with coverage
.\test-runner.ps1 -TestSuite All -Coverage

# Parallel execution
.\test-runner.ps1 -TestSuite Unit -Parallel -ParallelWorkers 8

# Fail fast mode
.\test-runner.ps1 -TestSuite All -FailFast

# Compare with baseline
.\test-runner.ps1 -TestSuite All -BaselinePath "baseline-results.json"

# Export HTML report
.\test-runner.ps1 -TestSuite All -ReportFormat html -OutputPath "test-reports"
```

## Monitoring Dashboard

### `monitor-dashboard.ps1`

Real-time web-based monitoring dashboard.

**Features:**
- Live CPU, memory, GPU metrics
- Request queue monitoring
- Log streaming
- Auto-refresh (configurable interval)
- Dark theme UI

**Usage:**
```powershell
# Start dashboard on default port
.\monitor-dashboard.ps1

# Custom port and bind address
.\monitor-dashboard.ps1 -Port 8080 -BindAddress "0.0.0.0"

# Auto-open browser
.\monitor-dashboard.ps1 -OpenBrowser

# Custom refresh interval
.\monitor-dashboard.ps1 -RefreshInterval 10
```

**Access:** Open http://localhost:9090/ in your browser

## Data Migration

### `data-migrator.ps1`

Migrates data between versions and formats.

**Actions:**
- `Export` - Export data to various formats
- `Import` - Import data from backup
- `Convert` - Convert between formats
- `Backup` - Create data backup
- `Validate` - Validate data integrity

**Formats:**
- `JSON` - JavaScript Object Notation
- `CSV` - Comma-separated values
- `XML` - Extensible Markup Language
- `SQLite` - SQLite database
- `GGUF` - GGUF model format

**Usage:**
```powershell
# Export data to JSON
.\data-migrator.ps1 -Action Export -Format JSON

# Export and compress
.\data-migrator.ps1 -Action Export -Compress

# Import from backup
.\data-migrator.ps1 -Action Import -SourcePath "backup-20240115.zip"

# Convert CSV to JSON
.\data-migrator.ps1 -Action Convert -SourcePath "data.csv" -DestinationPath "data.json" -Format JSON

# Validate data
.\data-migrator.ps1 -Action Validate -SourcePath "data"

# Dry run export
.\data-migrator.ps1 -Action Export -DryRun
```

## Notification Sender

### `notification-sender.ps1`

Sends notifications via multiple channels.

**Channels:**
- `Console` - Local console output
- `Email` - SMTP email (requires SMTP_* env vars)
- `Slack` - Slack webhook
- `Discord` - Discord webhook
- `Teams` - Microsoft Teams webhook
- `Webhook` - Custom webhook endpoint
- `All` - Send to all configured channels

**Levels:**
- `Info` - Informational message
- `Warning` - Warning message
- `Error` - Error message
- `Success` - Success message

**Usage:**
```powershell
# Console notification
.\notification-sender.ps1 -Message "Build complete" -Level Success

# Multi-channel notification
.\notification-sender.ps1 -Message "Deployment failed" -Level Error -Channels @("Console", "Slack")

# Email notification
.\notification-sender.ps1 -Message "System alert" -Level Warning -Channels Email -ToEmail "admin@example.com"

# Slack notification
.\notification-sender.ps1 -Message "New model available" -Level Info -Channels Slack -SlackWebhook "https://hooks.slack.com/..."

# Send to all channels
.\notification-sender.ps1 -Message "Critical error" -Level Error -Channels All
```

## Report Generator

### `report-generator.ps1`

Generates comprehensive reports in multiple formats.

**Report Types:**
- `System` - System information and health
- `Performance` - Performance metrics and benchmarks
- `Security` - Security audit results
- `Usage` - Usage statistics and analytics
- `Compliance` - Compliance status
- `Custom` - Custom report
- `All` - Comprehensive report

**Formats:**
- `HTML` - Rich HTML report with styling
- `PDF` - PDF document
- `CSV` - Comma-separated values
- `JSON` - JSON data
- `Markdown` - Markdown document
- `XML` - XML format

**Usage:**
```powershell
# Generate system report (HTML)
.\report-generator.ps1 -ReportType System -Format HTML

# Performance report with date range
.\report-generator.ps1 -ReportType Performance -Format HTML -StartDate (Get-Date).AddDays(-7)

# Export as CSV
.\report-generator.ps1 -ReportType Usage -Format CSV -OutputPath "reports"

# Generate and open
.\report-generator.ps1 -ReportType System -Format HTML -OpenAfter

# Email report
.\report-generator.ps1 -ReportType Security -Format PDF -EmailReport -EmailTo "admin@example.com"
```

## Task Scheduler

### `scheduler.ps1`

Manages scheduled tasks and automation jobs.

**Actions:**
- `List` - List scheduled tasks
- `Create` - Create new scheduled task
- `Delete` - Delete scheduled task
- `Run` - Run task immediately
- `Enable` - Enable disabled task
- `Disable` - Disable task
- `Export` - Export task configuration
- `Import` - Import task configuration

**Schedules:**
- `Daily` - Run daily at specified time
- `Weekly` - Run weekly
- `Monthly` - Run monthly
- `AtStartup` - Run at system startup
- `AtLogon` - Run at user logon
- `Once` - Run once
- `Interval` - Run at interval (minutes)

**Usage:**
```powershell
# List all RawrXD tasks
.\scheduler.ps1 -Action List

# Create daily backup task
.\scheduler.ps1 -Action Create -TaskName "RawrXD-Backup" -Command ".\backup-manager.ps1" -Schedule Daily -Time "02:00"

# Create hourly monitoring task
.\scheduler.ps1 -Action Create -TaskName "RawrXD-Monitor" -Command ".\diagnostics.ps1" -Schedule Interval -IntervalMinutes 60

# Run task immediately
.\scheduler.ps1 -Action Run -TaskName "RawrXD-Backup"

# Disable task
.\scheduler.ps1 -Action Disable -TaskName "RawrXD-Backup"

# Delete task
.\scheduler.ps1 -Action Delete -TaskName "RawrXD-Backup"

# Export tasks
.\scheduler.ps1 -Action Export -ExportPath "tasks-backup.json"
```

## Health Checker

### `health-checker.ps1`

Comprehensive health monitoring with automatic issue detection.

**Check Levels:**
- `Quick` - Basic system checks only
- `Standard` - System, disk, memory, and network
- `Full` - All checks including RawrXD-specific
- `Custom` - User-defined categories

**Check Categories:**
- `System` - CPU, memory, uptime
- `Disk` - Disk space and health
- `Services` - Windows services status
- `Network` - Connectivity and DNS
- `Memory` - Memory usage and pressure

**Usage:**
```powershell
# Quick health check
.\health-checker.ps1 -CheckLevel Quick

# Full system check
.\health-checker.ps1 -CheckLevel Full

# Custom categories
.\health-checker.ps1 -CheckCategories @("System", "Disk")

# Export results
.\health-checker.ps1 -OutputFormat JSON -OutputPath "health-report.json"

# Auto-fix issues (clean temp files, etc.)
.\health-checker.ps1 -AutoFix

# Notify on failure
.\health-checker.ps1 -NotifyOnFailure -NotificationChannel Slack
```

## Dependency Checker

### `dependency-checker.ps1`

Validates all build and runtime dependencies.

**Actions:**
- `Check` - Verify all dependencies
- `Install` - Attempt to install missing dependencies
- `List` - Show all required dependencies
- `Export` - Export dependency report

**Categories:**
- `Build` - CMake, Git, Ninja, Visual Studio
- `Runtime` - CUDA, Vulkan, Python
- `Development` - Docker, Node.js, PowerShell
- `All` - All categories

**Usage:**
```powershell
# Check all dependencies
.\dependency-checker.ps1 -Action Check

# Check build dependencies only
.\dependency-checker.ps1 -Action Check -Category Build

# Auto-install missing dependencies
.\dependency-checker.ps1 -Action Install -AutoInstall

# List all dependencies
.\dependency-checker.ps1 -Action List

# Export report
.\dependency-checker.ps1 -Action Export -ExportPath "deps-report.json"
```

## Common Workflows

### First-Time Setup

```powershell
# 1. Run development setup (as Administrator)
.\scripts\dev-setup.ps1

# 2. Restart PowerShell/Terminal

# 3. Build the project
cd C:\RawrXD-Dev\rawrxd
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel $env:NUMBER_OF_PROCESSORS

# 4. Run tests
ctest --output-on-failure
```

### Daily Development

```powershell
# Quick build and test
cd build
cmake --build . --parallel $env:NUMBER_OF_PROCESSORS
ctest --output-on-failure

# Run benchmarks
..\scripts\benchmark-runner.ps1 -Suite Quick

# Check model status
..\scripts\model-manager.ps1 -Action List
```

### Release Process

```powershell
# 1. Run full CI/CD pipeline
.\scripts\ci-cd-pipeline.ps1 -Stage Full -Environment staging

# 2. Create release build
.\scripts\build-release.ps1 -BuildType Release -EnableCUDA -EnableVulkan -Package -Version "3.2.0"

# 3. Deploy to production (after approval)
.\scripts\ci-cd-pipeline.ps1 -Stage Deploy -Environment production
```

## Script Parameters

All scripts support common parameters:

- `-Verbose` - Detailed output
- `-WhatIf` - Show what would happen without executing
- `-Confirm` - Prompt before making changes
- `-ErrorAction` - Control error handling

## Requirements

- Windows 10/11 or Windows Server 2019+
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges (for setup scripts)
- Internet connection (for downloads)

## Troubleshooting

### Script Execution Policy

If you get execution policy errors:

```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy for current user (requires Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Missing Dependencies

If scripts fail due to missing tools:

```powershell
# Re-run development setup
.\scripts\dev-setup.ps1

# Or install manually via Chocolatey
choco install cmake git python
```

### Permission Issues

Most scripts require Administrator privileges:

```powershell
# Run PowerShell as Administrator
# Right-click PowerShell → Run as Administrator
```

## Contributing

When adding new scripts:

1. Follow the existing naming convention
2. Include proper error handling
3. Add verbose output option
4. Document in this README
5. Test on clean Windows installation

## Support

- **Issues**: https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Documentation**: https://docs.rawrxd.ai
- **Discord**: https://discord.gg/rawrxd

---

**Happy scripting!** 🚀
