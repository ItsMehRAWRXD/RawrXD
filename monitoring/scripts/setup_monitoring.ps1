# RawrXD Monitoring Stack Setup Script
# Version: 1.0.0
# Sets up Prometheus, Grafana, and Alertmanager for RawrXD

param(
    [string]$InstallDir = "C:\ProgramData\RawrXD\Monitoring",
    [string]$DataDir = "C:\ProgramData\RawrXD\Monitoring\data",
    [switch]$StartServices,
    [switch]$ConfigureFirewall
)

$ErrorActionPreference = "Stop"

# Configuration
$PrometheusVersion = "2.47.0"
$GrafanaVersion = "10.1.0"
$AlertmanagerVersion = "0.26.0"

$Downloads = @{
    Prometheus = "https://github.com/prometheus/prometheus/releases/download/v$PrometheusVersion/prometheus-$PrometheusVersion.windows-amd64.zip"
    Grafana = "https://dl.grafana.com/oss/release/grafana-$GrafanaVersion.windows-amd64.zip"
    Alertmanager = "https://github.com/prometheus/alertmanager/releases/download/v$AlertmanagerVersion/alertmanager-$AlertmanagerVersion.windows-amd64.zip"
}

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $color = switch ($Status) {
        "Success" { "Green" }
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "Cyan" }
    }
    Write-Host "[$Status] $Message" -ForegroundColor $color
}

function Initialize-DirectoryStructure {
    Write-Status "Creating directory structure..."
    
    $dirs = @(
        $InstallDir,
        "$InstallDir\prometheus",
        "$InstallDir\grafana",
        "$InstallDir\alertmanager",
        $DataDir,
        "$DataDir\prometheus",
        "$DataDir\grafana",
        "$DataDir\alertmanager"
    )
    
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Status "Created: $dir" "Success"
        }
    }
}

function Install-Prometheus {
    Write-Status "Installing Prometheus v$PrometheusVersion..."
    
    $downloadPath = "$env:TEMP\prometheus.zip"
    $extractPath = "$InstallDir\prometheus"
    
    try {
        # Download
        if (-not (Test-Path $downloadPath)) {
            Write-Status "Downloading Prometheus..."
            Invoke-WebRequest -Uri $Downloads.Prometheus -OutFile $downloadPath -UseBasicParsing
        }
        
        # Extract
        Write-Status "Extracting Prometheus..."
        Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
        
        # Move files from subdirectory
        $subdir = Get-ChildItem $extractPath -Directory | Select-Object -First 1
        if ($subdir) {
            Get-ChildItem $subdir.FullName | Move-Item -Destination $extractPath -Force
            Remove-Item $subdir.FullName -Force
        }
        
        # Copy configuration
        Write-Status "Configuring Prometheus..."
        Copy-Item "monitoring/prometheus/prometheus.yml" "$extractPath\prometheus.yml" -Force
        
        # Create rules directory
        New-Item -ItemType Directory -Path "$extractPath\rules" -Force | Out-Null
        Copy-Item "monitoring/prometheus/rules/*.yml" "$extractPath\rules\" -Force
        
        Write-Status "Prometheus installed successfully" "Success"
    }
    catch {
        Write-Status "Failed to install Prometheus: $_" "Error"
        throw
    }
}

function Install-Grafana {
    Write-Status "Installing Grafana v$GrafanaVersion..."
    
    $downloadPath = "$env:TEMP\grafana.zip"
    $extractPath = "$InstallDir\grafana"
    
    try {
        # Download
        if (-not (Test-Path $downloadPath)) {
            Write-Status "Downloading Grafana..."
            Invoke-WebRequest -Uri $Downloads.Grafana -OutFile $downloadPath -UseBasicParsing
        }
        
        # Extract
        Write-Status "Extracting Grafana..."
        Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
        
        # Move files from subdirectory
        $subdir = Get-ChildItem $extractPath -Directory | Select-Object -First 1
        if ($subdir) {
            Get-ChildItem $subdir.FullName | Move-Item -Destination $extractPath -Force
            Remove-Item $subdir.FullName -Force
        }
        
        # Copy dashboards
        Write-Status "Installing Grafana dashboards..."
        $dashboardsDir = "$extractPath\public\dashboards"
        New-Item -ItemType Directory -Path $dashboardsDir -Force | Out-Null
        Copy-Item "monitoring/grafana/dashboards/*.json" $dashboardsDir -Force
        
        Write-Status "Grafana installed successfully" "Success"
    }
    catch {
        Write-Status "Failed to install Grafana: $_" "Error"
        throw
    }
}

function Install-Alertmanager {
    Write-Status "Installing Alertmanager v$AlertmanagerVersion..."
    
    $downloadPath = "$env:TEMP\alertmanager.zip"
    $extractPath = "$InstallDir\alertmanager"
    
    try {
        # Download
        if (-not (Test-Path $downloadPath)) {
            Write-Status "Downloading Alertmanager..."
            Invoke-WebRequest -Uri $Downloads.Alertmanager -OutFile $downloadPath -UseBasicParsing
        }
        
        # Extract
        Write-Status "Extracting Alertmanager..."
        Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
        
        # Move files from subdirectory
        $subdir = Get-ChildItem $extractPath -Directory | Select-Object -First 1
        if ($subdir) {
            Get-ChildItem $subdir.FullName | Move-Item -Destination $extractPath -Force
            Remove-Item $subdir.FullName -Force
        }
        
        # Copy configuration
        Write-Status "Configuring Alertmanager..."
        Copy-Item "monitoring/alerts/alertmanager.yml" "$extractPath\alertmanager.yml" -Force
        
        Write-Status "Alertmanager installed successfully" "Success"
    }
    catch {
        Write-Status "Failed to install Alertmanager: $_" "Error"
        throw
    }
}

function New-ServiceWrapper {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Description,
        [string]$Executable,
        [string]$Arguments,
        [string]$WorkingDirectory
    )
    
    $serviceExists = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($serviceExists) {
        Write-Status "Service $Name already exists, removing..." "Warning"
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        sc.exe delete $Name | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Create service using NSSM (Non-Sucking Service Manager)
    $nssmPath = "$InstallDir\nssm.exe"
    if (-not (Test-Path $nssmPath)) {
        Write-Status "Downloading NSSM..."
        Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\nssm.zip" -UseBasicParsing
        Expand-Archive -Path "$env:TEMP\nssm.zip" -DestinationPath "$env:TEMP\nssm" -Force
        Copy-Item "$env:TEMP\nssm\nssm-2.24\win64\nssm.exe" $nssmPath -Force
    }
    
    & $nssmPath install $Name $Executable
    & $nssmPath set $Name DisplayName $DisplayName
    & $nssmPath set $Name Description $Description
    & $nssmPath set $Name AppDirectory $WorkingDirectory
    & $nssmPath set $Name AppParameters $Arguments
    & $nssmPath set $Name Start SERVICE_AUTO_START
    
    Write-Status "Service $Name created" "Success"
}

function Install-Services {
    Write-Status "Creating Windows services..."
    
    # Prometheus Service
    New-ServiceWrapper `
        -Name "RawrXD-Prometheus" `
        -DisplayName "RawrXD Prometheus Monitoring" `
        -Description "Prometheus monitoring for RawrXD Hotpatch System" `
        -Executable "$InstallDir\prometheus\prometheus.exe" `
        -Arguments "--config.file=`"$InstallDir\prometheus\prometheus.yml`" --storage.tsdb.path=`"$DataDir\prometheus`" --web.listen-address=:9090" `
        -WorkingDirectory "$InstallDir\prometheus"
    
    # Grafana Service
    New-ServiceWrapper `
        -Name "RawrXD-Grafana" `
        -DisplayName "RawrXD Grafana Dashboards" `
        -Description "Grafana dashboards for RawrXD Hotpatch System" `
        -Executable "$InstallDir\grafana\bin\grafana-server.exe" `
        -Arguments "--config=`"$InstallDir\grafana\conf\defaults.ini`" --homepath=`"$InstallDir\grafana`"" `
        -WorkingDirectory "$InstallDir\grafana"
    
    # Alertmanager Service
    New-ServiceWrapper `
        -Name "RawrXD-Alertmanager" `
        -DisplayName "RawrXD Alertmanager" `
        -Description "Alertmanager for RawrXD Hotpatch System" `
        -Executable "$InstallDir\alertmanager\alertmanager.exe" `
        -Arguments "--config.file=`"$InstallDir\alertmanager\alertmanager.yml`" --storage.path=`"$DataDir\alertmanager`" --web.listen-address=:9093" `
        -WorkingDirectory "$InstallDir\alertmanager"
    
    Write-Status "Services created successfully" "Success"
}

function Set-FirewallRules {
    if (-not $ConfigureFirewall) {
        return
    }
    
    Write-Status "Configuring Windows Firewall..."
    
    $rules = @(
        @{Name="RawrXD-Prometheus"; Port=9090; Protocol="TCP"},
        @{Name="RawrXD-Grafana"; Port=3000; Protocol="TCP"},
        @{Name="RawrXD-Alertmanager"; Port=9093; Protocol="TCP"},
        @{Name="RawrXD-Metrics"; Port=8080; Protocol="TCP"}
    )
    
    foreach ($rule in $rules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -DisplayName $rule.Name
        }
        
        New-NetFirewallRule `
            -DisplayName $rule.Name `
            -Direction Inbound `
            -LocalPort $rule.Port `
            -Protocol $rule.Protocol `
            -Action Allow `
            -Profile Any | Out-Null
        
        Write-Status "Firewall rule created: $($rule.Name) (port $($rule.Port))" "Success"
    }
}

function Start-MonitoringServices {
    if (-not $StartServices) {
        return
    }
    
    Write-Status "Starting services..."
    
    $services = @("RawrXD-Prometheus", "RawrXD-Grafana", "RawrXD-Alertmanager")
    
    foreach ($service in $services) {
        try {
            Start-Service -Name $service
            Write-Status "Service $service started" "Success"
        }
        catch {
            Write-Status "Failed to start $service`: $_" "Error"
        }
    }
    
    Write-Status ""
    Write-Status "Monitoring stack is running!" "Success"
    Write-Status "Prometheus: http://localhost:9090"
    Write-Status "Grafana: http://localhost:3000 (admin/admin)"
    Write-Status "Alertmanager: http://localhost:9093"
}

function New-MetricsExporterService {
    Write-Status "Creating RawrXD Metrics Exporter service..."
    
    $serviceName = "RawrXD-MetricsExporter"
    $serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($serviceExists) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
    
    $nssmPath = "$InstallDir\nssm.exe"
    $scriptPath = Resolve-Path "monitoring/scripts/metrics_exporter.ps1"
    
    & $nssmPath install $serviceName powershell.exe
    & $nssmPath set $serviceName DisplayName "RawrXD Metrics Exporter"
    & $nssmPath set $serviceName Description "Exports RawrXD metrics for Prometheus"
    & $nssmPath set $serviceName AppDirectory (Get-Location).Path
    & $nssmPath set $serviceName AppParameters "-ExecutionPolicy Bypass -File `"$scriptPath`""
    & $nssmPath set $serviceName Start SERVICE_AUTO_START
    
    Write-Status "Metrics Exporter service created" "Success"
    
    if ($StartServices) {
        Start-Service -Name $serviceName
        Write-Status "Metrics Exporter started" "Success"
    }
}

# Main execution
function Install-MonitoringStack {
    Write-Status "RawrXD Monitoring Stack Setup" "Info"
    Write-Status "============================" "Info"
    Write-Status ""
    
    try {
        Initialize-DirectoryStructure
        Install-Prometheus
        Install-Grafana
        Install-Alertmanager
        Install-Services
        New-MetricsExporterService
        Set-FirewallRules
        Start-MonitoringServices
        
        Write-Status ""
        Write-Status "Setup complete!" "Success"
        Write-Status ""
        Write-Status "Next steps:"
        Write-Status "1. Configure alertmanager.yml with your Slack/PagerDuty credentials"
        Write-Status "2. Import dashboards in Grafana from public/dashboards/"
        Write-Status "3. Start the metrics exporter: Start-Service RawrXD-MetricsExporter"
        Write-Status "4. Run health check: .\monitoring\scripts\health_check.ps1"
    }
    catch {
        Write-Status "Setup failed: $_" "Error"
        exit 1
    }
}

# Run setup
Install-MonitoringStack
