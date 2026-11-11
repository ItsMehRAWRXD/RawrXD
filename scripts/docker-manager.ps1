# RawrXD Docker Manager
# Manages Docker containers, images, and deployments

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Up", "Down", "Build", "Logs", "Shell", "Clean", "Status", "Update", "Scale")]
    [string]$Action = "Status",
    
    [string]$ComposeFile = "docker-compose.yml",
    [string]$Service = "",
    [int]$ScaleCount = 1,
    [switch]$Detach,
    [switch]$RemoveVolumes,
    [switch]$RemoveImages,
    [string]$Environment = "development"
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    ComposeFiles = @{
        Development = "docker-compose.yml"
        Production = "docker-compose.production.yml"
        GPU = "docker-compose.gpu.yml"
    }
    Services = @("rawrxd", "rawrxd-api", "rawrxd-worker", "redis", "nginx")
}

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

function Test-DockerAvailable {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Error "Docker is not installed or not in PATH"
        exit 1
    }
    
    try {
        $info = docker info 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Docker daemon is not running"
            exit 1
        }
    }
    catch {
        Write-Error "Cannot connect to Docker daemon"
        exit 1
    }
    
    Write-Success "Docker is available"
}

function Test-ComposeFile {
    param([string]$File)
    
    if (-not (Test-Path $File)) {
        # Try to find alternative compose files
        $alternatives = @(
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml"
        )
        
        foreach ($alt in $alternatives) {
            if (Test-Path $alt) {
                $script:Config.ComposeFile = $alt
                return $alt
            }
        }
        
        Write-Error "Docker Compose file not found: $File"
        exit 1
    }
    
    return $File
}

function Invoke-DockerCompose {
    param(
        [string]$Command,
        [array]$Arguments = @()
    )
    
    $composeFile = Test-ComposeFile $ComposeFile
    
    $cmdArgs = @("-f", $composeFile)
    
    # Add environment-specific compose file if exists
    $envFile = $script:Config.ComposeFiles[$Environment]
    if ($envFile -and (Test-Path $envFile) -and $envFile -ne $composeFile) {
        $cmdArgs += @("-f", $envFile)
    }
    
    $cmdArgs += $Command
    $cmdArgs += $Arguments
    
    Write-Status "Executing: docker compose $cmdArgs"
    
    & docker compose @cmdArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker compose command failed with exit code $LASTEXITCODE"
        exit 1
    }
}

function Start-Containers {
    Write-Status "Starting containers..."
    
    $args = @()
    if ($Detach) {
        $args += "-d"
    }
    if ($Service) {
        $args += $Service
    }
    
    Invoke-DockerCompose -Command "up" -Arguments $args
    
    Write-Success "Containers started"
    
    if ($Detach) {
        Show-Status
    }
}

function Stop-Containers {
    Write-Status "Stopping containers..."
    
    $args = @()
    if ($RemoveVolumes) {
        $args += "-v"
    }
    if ($Service) {
        $args += $Service
    }
    
    Invoke-DockerCompose -Command "down" -Arguments $args
    
    Write-Success "Containers stopped"
}

function Build-Images {
    Write-Status "Building Docker images..."
    
    $args = @("--no-cache")
    if ($Service) {
        $args += $Service
    }
    
    Invoke-DockerCompose -Command "build" -Arguments $args
    
    Write-Success "Images built"
}

function Show-Logs {
    Write-Status "Fetching logs..."
    
    $args = @("-f", "--tail", "100")
    if ($Service) {
        $args += $Service
    }
    
    Invoke-DockerCompose -Command "logs" -Arguments $args
}

function Enter-Shell {
    if (-not $Service) {
        $Service = "rawrxd"
    }
    
    Write-Status "Opening shell in $Service..."
    
    Invoke-DockerCompose -Command "exec" -Arguments @($Service, "/bin/sh")
}

function Clear-Environment {
    Write-Warning "This will remove all containers, networks, and optionally volumes and images"
    $confirm = Read-Host "Are you sure? (type 'yes' to confirm)"
    
    if ($confirm -ne "yes") {
        Write-Status "Operation cancelled"
        return
    }
    
    Write-Status "Cleaning up Docker environment..."
    
    # Stop and remove containers
    Invoke-DockerCompose -Command "down" -Arguments @("-v", "--remove-orphans")
    
    # Remove images if requested
    if ($RemoveImages) {
        Write-Status "Removing images..."
        docker image prune -f
        Write-Success "Images removed"
    }
    
    # Clean up dangling volumes
    Write-Status "Cleaning up volumes..."
    docker volume prune -f
    
    # Clean up networks
    Write-Status "Cleaning up networks..."
    docker network prune -f
    
    Write-Success "Environment cleaned"
}

function Show-Status {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Docker Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Container status
    Write-Host "Containers:" -ForegroundColor White
    $containers = docker compose ps --format json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($containers) {
        foreach ($container in $containers) {
            $status = $container.State
            $color = switch ($status) {
                "running" { "Green" }
                "exited" { "Red" }
                "paused" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "  $($container.Name): " -NoNewline
            Write-Host $status -ForegroundColor $color
        }
    } else {
        Write-Host "  No containers running" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Image status
    Write-Host "Images:" -ForegroundColor White
    $images = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "rawrxd"
    if ($images) {
        foreach ($image in $images) {
            Write-Host "  $image" -ForegroundColor Gray
        }
    } else {
        Write-Host "  No RawrXD images found" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Resource usage
    Write-Host "Resource Usage:" -ForegroundColor White
    $stats = docker stats --no-stream --format "{{.Name}}: {{.CPUPerc}} CPU, {{.MemUsage}}" 2>$null
    if ($stats) {
        foreach ($stat in $stats) {
            Write-Host "  $stat" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
}

function Update-Containers {
    Write-Status "Updating containers..."
    
    # Pull latest images
    Invoke-DockerCompose -Command "pull"
    
    # Recreate containers
    Invoke-DockerCompose -Command "up" -Arguments @("-d", "--force-recreate", "--build")
    
    Write-Success "Containers updated"
}

function Set-ServiceScale {
    if (-not $Service) {
        Write-Error "Service name required for scaling"
        exit 1
    }
    
    Write-Status "Scaling $Service to $ScaleCount instances..."
    
    Invoke-DockerCompose -Command "up" -Arguments @("-d", "--scale", "$Service=$ScaleCount")
    
    Write-Success "Service scaled"
}

# Main execution
function Main {
    Write-Host "RawrXD Docker Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Test-DockerAvailable
    
    switch ($Action) {
        "Up" { Start-Containers }
        "Down" { Stop-Containers }
        "Build" { Build-Images }
        "Logs" { Show-Logs }
        "Shell" { Enter-Shell }
        "Clean" { Clear-Environment }
        "Status" { Show-Status }
        "Update" { Update-Containers }
        "Scale" { Set-ServiceScale }
    }
    
    Write-Host ""
}

Main
