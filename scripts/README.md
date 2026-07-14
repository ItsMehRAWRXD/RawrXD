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
| `hotpatch-manager.ps1` | 7-layer hotpatch system management | `.\hotpatch-manager.ps1` |
| `model-optimizer.ps1` | Model quantization & optimization | `.\model-optimizer.ps1` |
| `test-runner.ps1` | Unified test execution | `.\test-runner.ps1` |
| `monitor-dashboard.ps1` | Real-time monitoring dashboard | `.\monitor-dashboard.ps1` |
| `data-migrator.ps1` | Data migration & conversion | `.\data-migrator.ps1` |
| `notification-sender.ps1` | Multi-channel notifications | `.\notification-sender.ps1` |
| `report-generator.ps1` | Report generation | `.\report-generator.ps1` |
| `scheduler.ps1` | Task scheduling | `.\scheduler.ps1` |
| `health-checker.ps1` | System health monitoring | `.\health-checker.ps1` |
| `dependency-checker.ps1` | Dependency validation | `.\dependency-checker.ps1` |
| `log-rotator.ps1` | Log rotation and archival | `.\log-rotator.ps1` |
| `version-manager.ps1` | Version and release management | `.\version-manager.ps1` |
| `cleanup-utility.ps1` | System cleanup and maintenance | `.\cleanup-utility.ps1` |
| `metrics-collector.ps1` | Metrics collection and export | `.\metrics-collector.ps1` |
| `ssl-manager.ps1` | SSL certificate management | `.\ssl-manager.ps1` |
| `docs-generator.ps1` | Documentation generation | `.\docs-generator.ps1` |
| `secrets-manager.ps1` | Secrets and API key management | `.\secrets-manager.ps1` |
| `database-manager.ps1` | Database operations and migrations | `.\database-manager.ps1` |
| `cache-manager.ps1` | Application cache management | `.\cache-manager.ps1` |
| `service-manager.ps1` | Windows service management | `.\service-manager.ps1` |
| `package-manager.ps1` | Package and dependency management | `.\package-manager.ps1` |
| `workspace-manager.ps1` | Development workspace management | `.\workspace-manager.ps1` |
| `feature-flags.ps1` | Feature flags and gradual rollouts | `.\feature-flags.ps1` |
| `env-manager.ps1` | Environment configuration management | `.\env-manager.ps1` |
| `troubleshooter.ps1` | Automated troubleshooting and repair | `.\troubleshooter.ps1` |
| `update-manager.ps1` | Software updates and version management | `.\update-manager.ps1` |
| `diagnostic-tools.ps1` | System diagnostics and troubleshooting | `.\diagnostic-tools.ps1` |
| `workflow-automation.ps1` | Development workflow automation | `.\workflow-automation.ps1` |
| `plugin-manager.ps1` | Plugin/extension management | `.\plugin-manager.ps1` |
| `template-generator.ps1` | Project template and boilerplate generator | `.\template-generator.ps1` |
| `import-export.ps1` | Data import/export and format conversion | `.\import-export.ps1` |
| `remote-manager.ps1` | Remote instance and distributed operations | `.\remote-manager.ps1` |
| `integration-manager.ps1` | Third-party integrations and connectors | `.\integration-manager.ps1` |
| `analytics-dashboard.ps1` | Analytics and insights dashboard | `.\analytics-dashboard.ps1` |
| `model-comparator.ps1` | Model comparison and benchmarking | `.\model-comparator.ps1` |
| `chat-session-manager.ps1` | Chat session and conversation management | `.\chat-session-manager.ps1` |
| `prompt-engineer.ps1` | Prompt engineering and optimization | `.\prompt-engineer.ps1` |
| `token-calculator.ps1` | Token counting and cost estimation | `.\token-calculator.ps1` |
| `model-validator.ps1` | Model file validation and repair | `.\model-validator.ps1` |
| `api-gateway-manager.ps1` | API gateway configuration and routing | `.\api-gateway-manager.ps1` |
| `load-balancer.ps1` | Load balancing across instances | `.\load-balancer.ps1` |
| `system-resource-monitor.ps1` | System resource monitoring | `.\system-resource-monitor.ps1` |
| `log-aggregator.ps1` | Log aggregation and centralization | `.\log-aggregator.ps1` |
| `config-validator.ps1` | Configuration validation and schemas | `.\config-validator.ps1` |
| `deployment-orchestrator.ps1` | Multi-stage deployment orchestration | `.\deployment-orchestrator.ps1` |

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

## Hotpatch Management

### `hotpatch-manager.ps1`

Manages the 7-layer hotpatching system for real-time failure correction.

**7-Layer Architecture:**
- `pt-driver` - Page table watchpoints and snapshots (Layer 0)
- `memory` - Direct RAM patching with SIMD/TSX RTM (Layer 1)
- `byte` - GGUF file byte-level patches (Layer 2)
- `server` - Request/response transforms (Layer 3)
- `binary` - Live binary code replacement (Layer 5)
- `shadow` - Atomic prologue rewrite (Layer 6)
- `sentinel` - .text integrity monitor (Layer 6)

**Failure Types:**
- Refusal, Hallucination, FormatViolation, InfiniteLoop
- TokenLimit, ResourceExhausted, Timeout, SafetyViolation
- LowConfidence, GarbageOutput

**Usage:**
```powershell
# Show hotpatch system status
.\hotpatch-manager.ps1 -Action Status

# Enable a layer
.\hotpatch-manager.ps1 -Action Enable -Layer memory

# Disable a layer
.\hotpatch-manager.ps1 -Action Disable -Layer byte -Force

# Test hotpatch system
.\hotpatch-manager.ps1 -Action Test

# Apply a patch
.\hotpatch-manager.ps1 -Action Apply -PatchFile "fix.json" -Layer memory

# List available patches
.\hotpatch-manager.ps1 -Action List

# Monitor hotpatch activity
.\hotpatch-manager.ps1 -Action Monitor -MonitorDuration 120

# View policies
.\hotpatch-manager.ps1 -Action Policy
```

## Model Optimization

### `model-optimizer.ps1`

Optimizes GGUF models for performance and memory efficiency.

**Actions:**
- `Analyze` - Analyze model and show optimization options
- `Quantize` - Convert to quantized format
- `Prune` - Remove redundant parameters
- `Convert` - Convert between formats
- `Benchmark` - Performance benchmarking
- `Tune` - Optimize for target hardware

**Quantization Types:**
- `Q4_0` / `Q4_1` - 4-bit (75% size reduction)
- `Q5_0` / `Q5_1` - 5-bit (68% size reduction)
- `Q8_0` / `Q8_1` - 8-bit (50% size reduction)
- `F16` - Half precision (50% size reduction)
- `F32` - Full precision (no reduction)

**Usage:**
```powershell
# Analyze model
.\model-optimizer.ps1 -Action Analyze -ModelPath "model.gguf"

# Quantize to Q4_0
.\model-optimizer.ps1 -Action Quantize -ModelPath "model.gguf" -Quantization Q4_0

# Quantize with custom output
.\model-optimizer.ps1 -Action Quantize -ModelPath "model.gguf" -Quantization Q5_0 -OutputPath "model-q5.gguf"

# Benchmark model
.\model-optimizer.ps1 -Action Benchmark -ModelPath "model.gguf"

# Tune for hardware
.\model-optimizer.ps1 -Action Tune -ModelPath "model.gguf"

# Convert format
.\model-optimizer.ps1 -Action Convert -ModelPath "model.bin"
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

## Log Rotator

### `log-rotator.ps1`

Manages log file rotation, archival, and cleanup.

**Actions:**
- `Rotate` - Rotate oversized log files
- `Archive` - Archive old log files
- `Clean` - Delete very old archived logs
- `Status` - Show log directory status
- `Configure` - Export configuration

**Usage:**
```powershell
# Rotate logs over 100MB
.\log-rotator.ps1 -Action Rotate -MaxSizeMB 100

# Rotate and compress
.\log-rotator.ps1 -Action Rotate -Compress

# Archive logs older than 30 days
.\log-rotator.ps1 -Action Archive -MaxAgeDays 30

# Clean old archives
.\log-rotator.ps1 -Action Clean -MaxAgeDays 60

# Show status
.\log-rotator.ps1 -Action Status

# Dry run
.\log-rotator.ps1 -Action Rotate -DryRun
```

## Version Manager

### `version-manager.ps1`

Manages versioning, releases, and changelogs.

**Actions:**
- `Show` - Display current version info
- `Bump` - Bump version number
- `Release` - Create new release
- `Changelog` - Show changelog
- `Tag` - Create git tag
- `Validate` - Validate version consistency

**Bump Types:**
- `Major` - Increment major version
- `Minor` - Increment minor version
- `Patch` - Increment patch version
- `Build` - Increment build number

**Usage:**
```powershell
# Show current version
.\version-manager.ps1 -Action Show

# Bump patch version
.\version-manager.ps1 -Action Bump -BumpType Patch

# Create release
.\version-manager.ps1 -Action Release -Version "3.2.0" -Message "Release notes"

# Create and push git tag
.\version-manager.ps1 -Action Tag -PushTag

# Validate version consistency
.\version-manager.ps1 -Action Validate
```

## Cleanup Utility

### `cleanup-utility.ps1`

Cleans up temporary files, build artifacts, and cache.

**Cleanup Types:**
- `Temp` - Temporary files only
- `Build` - Build artifacts
- `Cache` - Cache directories
- `Logs` - Old log files
- `All` - All of the above
- `Aggressive` - Deep cleanup (requires -Force)

**Usage:**
```powershell
# Clean temporary files
.\cleanup-utility.ps1 -CleanupType Temp

# Clean build artifacts
.\cleanup-utility.ps1 -CleanupType Build

# Clean everything
.\cleanup-utility.ps1 -CleanupType All

# Aggressive cleanup
.\cleanup-utility.ps1 -CleanupType Aggressive -Force

# Dry run
.\cleanup-utility.ps1 -CleanupType All -DryRun

# Clean custom paths
.\cleanup-utility.ps1 -CleanupType Temp -AdditionalPaths @("C:\Custom\Temp")
```

## Metrics Collector

### `metrics-collector.ps1`

Collects and exports system and application metrics.

**Actions:**
- `Collect` - Collect metrics once
- `Export` - Export collected metrics
- `Dashboard` - Show metrics dashboard
- `Alert` - Check thresholds and alert

**Metric Types:**
- `System` - CPU, memory, disk, network
- `Application` - Process metrics, logs, models
- `Performance` - Inference metrics, request stats
- `All` - All metric types

**Formats:**
- `JSON` - JSON format
- `CSV` - Comma-separated values
- `Prometheus` - Prometheus exposition format

**Usage:**
```powershell
# Collect all metrics
.\metrics-collector.ps1 -Action Collect

# Collect system metrics only
.\metrics-collector.ps1 -Action Collect -MetricType System

# Export as Prometheus format
.\metrics-collector.ps1 -Action Export -Format Prometheus

# Show dashboard
.\metrics-collector.ps1 -Action Dashboard

# Stream metrics (continuous collection)
.\metrics-collector.ps1 -Action Collect -Stream -IntervalSeconds 60
```

## SSL Manager

### `ssl-manager.ps1`

Manages SSL certificates and HTTPS configuration.

**Actions:**
- `Check` - Check certificate status
- `Generate` - Generate self-signed certificate
- `Install` - Install certificate to Windows store
- `Renew` - Renew certificate
- `List` - List certificates
- `Export` - Export certificate to PFX

**Usage:**
```powershell
# Check certificates
.\ssl-manager.ps1 -Action Check

# Generate self-signed certificate
.\ssl-manager.ps1 -Action Generate -Domain "localhost" -SelfSigned

# Install to Windows store
.\ssl-manager.ps1 -Action Install -Domain "localhost"

# List certificates
.\ssl-manager.ps1 -Action List

# Export to PFX
.\ssl-manager.ps1 -Action Export -Domain "localhost"
```

## Documentation Generator

### `docs-generator.ps1`

Generates documentation from source code and configuration.

**Doc Types:**
- `API` - API reference from source code comments
- `CLI` - CLI command reference
- `Config` - Configuration reference
- `All` - Generate all documentation types
- `Markdown` - Markdown output
- `HTML` - HTML output

**Features:**
- Extracts documentation from C++, Python, PowerShell comments
- Generates markdown and HTML output
- Includes examples and parameter descriptions
- Built-in documentation server

**Usage:**
```powershell
# Generate all documentation
.\docs-generator.ps1 -DocType All

# Generate API docs only
.\docs-generator.ps1 -DocType API -SourcePath "src"

# Generate with examples
.\docs-generator.ps1 -DocType All -IncludeExamples

# Generate HTML documentation
.\docs-generator.ps1 -DocType All -DocType HTML

# Serve documentation locally
.\docs-generator.ps1 -DocType All -Serve -Port 8080
```

## Secrets Manager

### `secrets-manager.ps1`

Manages secrets, API keys, and sensitive configuration.

**Actions:**
- `Set` - Store a secret
- `Get` - Retrieve a secret
- `Remove` - Delete a secret
- `List` - List all secrets
- `Rotate` - Rotate all secrets
- `Export` - Export secrets to file
- `Import` - Import secrets from file

**Security:**
- Encrypted storage
- Environment variable integration
- Machine-specific encryption key
- Secure input prompts

**Usage:**
```powershell
# Set a secret
.\secrets-manager.ps1 -Action Set -Key "API_KEY" -Value "secret123"

# Set secret with secure prompt
.\secrets-manager.ps1 -Action Set -Key "API_KEY"

# Get a secret
.\secrets-manager.ps1 -Action Get -Key "API_KEY"

# Set as environment variable
.\secrets-manager.ps1 -Action Get -Key "API_KEY" -UseEnvironmentVariable

# List all secrets
.\secrets-manager.ps1 -Action List

# Remove a secret
.\secrets-manager.ps1 -Action Remove -Key "API_KEY"

# Export secrets
.\secrets-manager.ps1 -Action Export -FilePath "secrets-backup.json"

# Import secrets
.\secrets-manager.ps1 -Action Import -FilePath "secrets-backup.json"
```

## Database Manager

### `database-manager.ps1`

Manages database connections, migrations, and operations.

**Actions:**
- `Connect` - Test database connection
- `Query` - Execute SQL query
- `Migrate` - Run database migrations
- `Backup` - Create database backup
- `Restore` - Restore from backup
- `Status` - Show database status
- `Optimize` - Optimize database

**Database Types:**
- `SQLite` - SQLite database (default)
- `PostgreSQL` - PostgreSQL database
- `MySQL` - MySQL database
- `SQLServer` - Microsoft SQL Server

**Usage:**
```powershell
# Check database status
.\database-manager.ps1 -Action Status

# Test connection
.\database-manager.ps1 -Action Connect

# Execute query
.\database-manager.ps1 -Action Query -Query "SELECT * FROM models"

# Run migrations
.\database-manager.ps1 -Action Migrate -MigrationPath "migrations"

# Backup database
.\database-manager.ps1 -Action Backup -BackupPath "backups"

# Restore database
.\database-manager.ps1 -Action Restore -BackupFile "backups/rawrxd-backup-20240115.zip"

# Optimize database
.\database-manager.ps1 -Action Optimize
```

## Cache Manager

### `cache-manager.ps1`

Manages application cache for improved performance.

**Actions:**
- `Clear` - Clear expired cache entries
- `Warm` - Pre-populate cache
- `Status` - Show cache statistics
- `Configure` - Export cache configuration
- `Analyze` - Analyze cache contents

**Usage:**
```powershell
# Show cache status
.\cache-manager.ps1 -Action Status

# Clear old cache entries
.\cache-manager.ps1 -Action Clear -MaxAgeHours 24

# Warm cache with specific paths
.\cache-manager.ps1 -Action Warm -WarmPaths @("models/*.gguf", "config/*.json")

# Analyze cache contents
.\cache-manager.ps1 -Action Analyze

# Export configuration
.\cache-manager.ps1 -Action Configure

# Dry run (show what would be cleared)
.\cache-manager.ps1 -Action Clear -DryRun
```

## Service Manager

### `service-manager.ps1`

Manages RawrXD as a Windows service.

**Actions:**
- `Install` - Install RawrXD as a Windows service
- `Uninstall` - Remove the service
- `Start` - Start the service
- `Stop` - Stop the service
- `Restart` - Restart the service
- `Status` - Show service status
- `Configure` - Configure service settings

**Usage:**
```powershell
# Install service
.\service-manager.ps1 -Action Install -ServiceName "RawrXD" -AutoStart

# Install with custom binary path
.\service-manager.ps1 -Action Install -BinaryPath "C:\RawrXD\bin\rawrxd.exe"

# Start service
.\service-manager.ps1 -Action Start

# Stop service
.\service-manager.ps1 -Action Stop

# Restart service
.\service-manager.ps1 -Action Restart

# Check status
.\service-manager.ps1 -Action Status

# Uninstall service
.\service-manager.ps1 -Action Uninstall

# Configure delayed start
.\service-manager.ps1 -Action Configure -DelayedStart
```

## Package Manager

### `package-manager.ps1`

Manages packages, dependencies, and distribution.

**Actions:**
- `Create` - Create a new package
- `Install` - Install a package
- `Uninstall` - Remove a package
- `List` - List installed packages
- `Update` - Update a package
- `Validate` - Validate package structure
- `Publish` - Publish package to repository

**Usage:**
```powershell
# Create package
.\package-manager.ps1 -Action Create -PackageName "my-model" -PackagePath "./my-model"

# Install package
.\package-manager.ps1 -Action Install -PackageName "llama-7b-q4"

# Install specific version
.\package-manager.ps1 -Action Install -PackageName "llama-7b-q4" -Version "1.2.0"

# List installed packages
.\package-manager.ps1 -Action List

# Update package
.\package-manager.ps1 -Action Update -PackageName "llama-7b-q4"

# Uninstall package
.\package-manager.ps1 -Action Uninstall -PackageName "llama-7b-q4"

# Validate package
.\package-manager.ps1 -Action Validate -PackagePath "./my-model"

# Publish package
.\package-manager.ps1 -Action Publish -PackagePath "./my-model"
```

## Workspace Manager

### `workspace-manager.ps1`

Manages development workspaces and environments.

**Actions:**
- `Create` - Create a new workspace
- `Switch` - Switch to a workspace
- `List` - List all workspaces
- `Delete` - Delete a workspace
- `Backup` - Backup a workspace
- `Clone` - Clone an existing workspace

**Templates:**
- `default` - Standard workspace
- `development` - Development-optimized workspace
- `production` - Production-like workspace

**Usage:**
```powershell
# Create new workspace
.\workspace-manager.ps1 -Action Create -WorkspaceName "my-project"

# Create with template
.\workspace-manager.ps1 -Action Create -WorkspaceName "my-project" -Template "development"

# List workspaces
.\workspace-manager.ps1 -Action List

# Switch workspace
.\workspace-manager.ps1 -Action Switch -WorkspaceName "my-project"

# Backup workspace
.\workspace-manager.ps1 -Action Backup -WorkspaceName "my-project"

# Clone workspace
.\workspace-manager.ps1 -Action Clone -SourceWorkspace "my-project" -WorkspaceName "my-project-copy"

# Delete workspace
.\workspace-manager.ps1 -Action Delete -WorkspaceName "my-project"
```

## Feature Flags

### `feature-flags.ps1`

Manages feature flags and toggles for gradual rollouts.

**Actions:**
- `List` - List all feature flags
- `Enable` - Enable a feature flag
- `Disable` - Disable a feature flag
- `Create` - Create a new feature flag
- `Delete` - Delete a feature flag
- `Rollout` - Gradual percentage rollout
- `Status` - Show flag status

**Flag Types:**
- `Boolean` - Simple on/off toggle
- `Percentage` - Gradual rollout percentage
- `UserGroup` - Enable for specific user groups
- `TimeBased` - Time-based activation

**Usage:**
```powershell
# List all feature flags
.\feature-flags.ps1 -Action List

# Create feature flag
.\feature-flags.ps1 -Action Create -FlagName "new-ui" -Description "New UI design" -FlagType Boolean

# Create percentage-based flag
.\feature-flags.ps1 -Action Create -FlagName "beta-feature" -Description "Beta feature" -FlagType Percentage -Percentage 10

# Enable flag
.\feature-flags.ps1 -Action Enable -FlagName "new-ui"

# Disable flag
.\feature-flags.ps1 -Action Disable -FlagName "new-ui"

# Gradual rollout
.\feature-flags.ps1 -Action Rollout -FlagName "beta-feature"

# Show flag status
.\feature-flags.ps1 -Action Status -FlagName "new-ui"

# Delete flag
.\feature-flags.ps1 -Action Delete -FlagName "new-ui"
```

## Environment Manager

### `env-manager.ps1`

Manages different deployment environments (dev, staging, prod).

**Actions:**
- `List` - List all environments
- `Create` - Create a new environment
- `Switch` - Switch to an environment
- `Delete` - Delete an environment
- `Compare` - Compare two environments
- `Sync` - Sync environment configuration

**Default Environments:**
- `development` - Development environment
- `staging` - Staging environment
- `production` - Production environment

**Usage:**
```powershell
# List environments
.\env-manager.ps1 -Action List

# Create environment
.\env-manager.ps1 -Action Create -Environment "testing"

# Switch environment
.\env-manager.ps1 -Action Switch -Environment "staging"

# Compare environments
.\env-manager.ps1 -Action Compare -SourceEnv "development" -Environment "production"

# Sync environments
.\env-manager.ps1 -Action Sync -SourceEnv "development" -Environment "staging"

# Delete environment
.\env-manager.ps1 -Action Delete -Environment "testing"
```

## Troubleshooter

### `troubleshooter.ps1`

Automated troubleshooting and diagnostic repair.

**Actions:**
- `Diagnose` - Run diagnostics and identify issues
- `Repair` - Attempt automatic repairs
- `Reset` - Reset configuration to defaults
- `Clean` - Clean temporary files
- `Verify` - Verify installation integrity

**Usage:**
```powershell
# Run diagnostics
.\troubleshooter.ps1 -Action Diagnose

# Run diagnostics with auto-fix
.\troubleshooter.ps1 -Action Diagnose -AutoFix

# Repair issues
.\troubleshooter.ps1 -Action Repair

# Reset configuration
.\troubleshooter.ps1 -Action Reset

# Clean temporary files
.\troubleshooter.ps1 -Action Clean

# Verify installation
.\troubleshooter.ps1 -Action Verify
```

## Update Manager

### `update-manager.ps1`

Manages software updates and version migrations.

**Actions:**
- `Check` - Check for available updates
- `Download` - Download update package
- `Install` - Install update
- `Rollback` - Rollback to previous version
- `Status` - Show update status
- `History` - Show update history

**Usage:**
```powershell
# Check for updates
.\update-manager.ps1 -Action Check

# Download specific version
.\update-manager.ps1 -Action Download -Version "3.3.0"

# Install latest update
.\update-manager.ps1 -Action Install

# Install specific version with backup
.\update-manager.ps1 -Action Install -Version "3.3.0" -BackupBeforeUpdate

# Rollback to previous version
.\update-manager.ps1 -Action Rollback

# Show update status
.\update-manager.ps1 -Action Status

# Show update history
.\update-manager.ps1 -Action History
```

## Plugin Manager

### `plugin-manager.ps1`

Manages plugins and extensions.

**Actions:**
- `List` - List installed plugins
- `Install` - Install a plugin
- `Uninstall` - Remove a plugin
- `Enable` - Enable a plugin
- `Disable` - Disable a plugin
- `Update` - Update all plugins
- `Search` - Search for plugins
- `Info` - Show plugin information

**Usage:**
```powershell
# List installed plugins
.\plugin-manager.ps1 -Action List

# Search for plugins
.\plugin-manager.ps1 -Action Search -PluginName "vision"

# Install a plugin
.\plugin-manager.ps1 -Action Install -PluginName "my-plugin"

# Install from local source
.\plugin-manager.ps1 -Action Install -PluginName "my-plugin" -Source "./local-plugin"

# Uninstall a plugin
.\plugin-manager.ps1 -Action Uninstall -PluginName "my-plugin"

# Enable/disable plugin
.\plugin-manager.ps1 -Action Enable -PluginName "my-plugin"
.\plugin-manager.ps1 -Action Disable -PluginName "my-plugin"

# Update all plugins
.\plugin-manager.ps1 -Action Update

# Show plugin info
.\plugin-manager.ps1 -Action Info -PluginName "my-plugin"
```

## Template Generator

### `template-generator.ps1`

Generates project templates and boilerplate code.

**Template Types:**
- `Model` - New GGML model wrapper
- `Plugin` - RawrXD plugin/extension
- `API` - REST API endpoint
- `Test` - Unit test suite
- `Config` - Configuration file
- `Script` - PowerShell automation script
- `List` - List available templates

**Usage:**
```powershell
# List available templates
.\template-generator.ps1 -TemplateType List

# Generate model template
.\template-generator.ps1 -TemplateType Model -Name "MyModel"

# Generate plugin template
.\template-generator.ps1 -TemplateType Plugin -Name "MyPlugin"

# Generate API endpoint
.\template-generator.ps1 -TemplateType API -Name "MyAPI" -OutputPath "./api"

# Generate test suite
.\template-generator.ps1 -TemplateType Test -Name "MyFeature"

# Generate config files
.\template-generator.ps1 -TemplateType Config -Name "production"

# Generate script template
.\template-generator.ps1 -TemplateType Script -Name "my-script"
```

## Import/Export Manager

### `import-export.ps1`

Manages data import, export, and format conversion.

**Actions:**
- `Export` - Export data to file
- `Import` - Import data from file
- `Convert` - Convert between formats
- `Validate` - Validate data file
- `List` - List supported formats

**Usage:**
```powershell
# Export data to JSON
.\import-export.ps1 -Action Export -Source "./data" -Destination "./backup" -Format json

# Export with compression
.\import-export.ps1 -Action Export -Source "./data" -Destination "./backup" -Format json -Compress

# Import data
.\import-export.ps1 -Action Import -Source "./backup/export.json" -Destination "./data"

# Convert format
.\import-export.ps1 -Action Convert -Source "./data.json" -Format csv

# Validate file
.\import-export.ps1 -Action Validate -Source "./data.json"

# List supported formats
.\import-export.ps1 -Action List
```

## Remote Manager

### `remote-manager.ps1`

Manages remote instances and distributed operations.

**Actions:**
- `List` - List known remote hosts
- `Connect` - Connect to remote host
- `Deploy` - Deploy to remote host
- `Sync` - Sync data with remote
- `Execute` - Execute command on remote
- `Monitor` - Monitor remote status
- `Disconnect` - Disconnect from remote

**Usage:**
```powershell
# List known hosts
.\remote-manager.ps1 -Action List

# Connect to remote host
.\remote-manager.ps1 -Action Connect -Host "server1" -User "admin"

# Execute command remotely
.\remote-manager.ps1 -Action Execute -Host "server1" -Command "Get-Process"

# Deploy to remote
.\remote-manager.ps1 -Action Deploy -Host "server1" -ConfigFile "./app" -User "C:/apps"

# Sync data
.\remote-manager.ps1 -Action Sync -ConfigFile "./local" -User "./remote"

# Monitor remote
.\remote-manager.ps1 -Action Monitor -Host "server1"

# Disconnect
.\remote-manager.ps1 -Action Disconnect -Host "server1"
```

## Integration Manager

### `integration-manager.ps1`

Manages third-party integrations and connectors.

**Actions:**
- `List` - List available integrations
- `Configure` - Configure an integration
- `Test` - Test integration connection
- `Enable` - Enable an integration
- `Disable` - Disable an integration
- `Status` - Show integration status

**Supported Integrations:**
- OpenAI - OpenAI API for GPT models
- Anthropic - Claude API
- HuggingFace - Hugging Face Hub
- AWS - Amazon Web Services
- Azure - Microsoft Azure
- GoogleCloud - Google Cloud Platform
- Discord - Discord bot
- Slack - Slack workspace
- GitHub - GitHub API
- Webhook - Generic webhooks

**Usage:**
```powershell
# List available integrations
.\integration-manager.ps1 -Action List

# Configure OpenAI integration
.\integration-manager.ps1 -Action Configure -Integration "OpenAI" -Parameters @{ api_key = "sk-..."; base_url = "https://api.openai.com" }

# Test integration
.\integration-manager.ps1 -Action Test -Integration "OpenAI"

# Enable/disable integration
.\integration-manager.ps1 -Action Enable -Integration "OpenAI"
.\integration-manager.ps1 -Action Disable -Integration "OpenAI"

# Show status
.\integration-manager.ps1 -Action Status
```

## Analytics Dashboard

### `analytics-dashboard.ps1`

Provides analytics and insights.

**Views:**
- `Overview` - High-level system metrics
- `Usage` - API endpoint usage statistics
- `Performance` - Performance metrics and latencies
- `Models` - Model usage statistics
- `Export` - Export analytics data
- `Schedule` - Schedule reports

**Usage:**
```powershell
# Show overview
.\analytics-dashboard.ps1 -View Overview

# Show usage statistics
.\analytics-dashboard.ps1 -View Usage

# Show performance metrics
.\analytics-dashboard.ps1 -View Performance

# Show model statistics
.\analytics-dashboard.ps1 -View Models

# Export analytics
.\analytics-dashboard.ps1 -View Export -ExportPath "./analytics.json"

# Interactive mode
.\analytics-dashboard.ps1 -Interactive
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
