# RawrXD Load Balancer Setup Script
# Phase L.1 - Load Balancer Configuration
# Supports both Nginx and HAProxy deployment

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("nginx", "haproxy")]
    [string]$BalancerType,

    [Parameter(Mandatory=$false)]
    [string[]]$BackendNodes = @("192.168.1.10:8080", "192.168.1.11:8080"),

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "",

    [Parameter(Mandatory=$false)]
    [switch]$TestConfig,

    [Parameter(Mandatory=$false)]
    [switch]$InstallService
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Logging setup
$LogFile = "/var/log/rawrxd/lb-setup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$LogDir = Split-Path $LogFile -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

function Test-BackendHealth {
    param([string[]]$Nodes)

    Write-Log "Testing backend node health..."
    $healthyNodes = @()

    foreach ($node in $Nodes) {
        $parts = $node -split ':'
        $ip = $parts[0]
        $port = if ($parts[1]) { $parts[1] } else { 8080 }

        try {
            $response = Invoke-WebRequest -Uri "http://$ip`:$port/health" -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Log "  ✓ $node - HEALTHY" "SUCCESS"
                $healthyNodes += $node
            } else {
                Write-Log "  ✗ $node - UNHEALTHY (Status: $($response.StatusCode))" "WARNING"
            }
        } catch {
            Write-Log "  ✗ $node - UNREACHABLE ($($_.Exception.Message))" "WARNING"
        }
    }

    return $healthyNodes
}

function Install-Nginx {
    Write-Log "Installing Nginx..."

    if ($IsWindows) {
        # Windows - use Chocolatey
        if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
            throw "Chocolatey not found. Please install Chocolatey first."
        }
        choco install nginx -y
        $nginxPath = "C:\tools\nginx"
    } else {
        # Linux
        if (Test-Path "/etc/debian_version") {
            apt-get update
            apt-get install -y nginx nginx-extras
        } elseif (Test-Path "/etc/redhat-release") {
            yum install -y nginx
        }
        $nginxPath = "/etc/nginx"
    }

    Write-Log "Nginx installed at $nginxPath"
    return $nginxPath
}

function Install-HAProxy {
    Write-Log "Installing HAProxy..."

    if ($IsWindows) {
        # Windows - use Chocolatey
        if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
            throw "Chocolatey not found. Please install Chocolatey first."
        }
        choco install haproxy -y
        $haproxyPath = "C:\Program Files\HA-Proxy"
    } else {
        # Linux
        if (Test-Path "/etc/debian_version") {
            apt-get update
            apt-get install -y haproxy
        } elseif (Test-Path "/etc/redhat-release") {
            yum install -y haproxy
        }
        $haproxyPath = "/etc/haproxy"
    }

    Write-Log "HAProxy installed at $haproxyPath"
    return $haproxyPath
}

function Generate-NginxConfig {
    param([string[]]$Nodes)

    Write-Log "Generating Nginx configuration..."

    $upstreamConfig = @()
    $upstreamWsConfig = @()

    $weight = 5
    foreach ($node in $Nodes) {
        $upstreamConfig += "    server $node weight=$weight max_fails=3 fail_timeout=30s;"
        $parts = $node -split ':'
        $wsNode = "$($parts[0]):8081"
        $upstreamWsConfig += "    server $wsNode weight=$weight max_fails=3 fail_timeout=30s;"
    }

    $config = @"
# Auto-generated RawrXD Load Balancer Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

upstream rawrxd_backend {
    least_conn;
$(($upstreamConfig -join "`n"))
    keepalive 32;
}

upstream rawrxd_ws_backend {
    least_conn;
$(($upstreamWsConfig -join "`n"))
    keepalive 32;
}

limit_req_zone `$binary_remote_addr zone=api_limit:10m rate=100r/s;
limit_req_zone `$binary_remote_addr zone=stream_limit:10m rate=50r/s;

server {
    listen 80;
    server_name _;
    return 301 https://`$host`$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate /etc/nginx/ssl/rawrxd.crt;
    ssl_certificate_key /etc/nginx/ssl/rawrxd.key;

    client_max_body_size 50m;

    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    location /v1/completions {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://rawrxd_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    location /v1/completions/stream {
        limit_req zone=stream_limit burst=10 nodelay;
        proxy_pass http://rawrxd_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location / {
        proxy_pass http://rawrxd_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
    }
}
"@

    return $config
}

function Generate-HAProxyConfig {
    param([string[]]$Nodes)

    Write-Log "Generating HAProxy configuration..."

    $serverConfig = @()
    $index = 1
    foreach ($node in $Nodes) {
        $weight = if ($index -le 2) { 5 } else { 3 }
        $backup = if ($index -gt 2) { " backup" } else { "" }
        $serverConfig += "    server node$index $node check weight $weight inter 5s rise 2 fall 3$backup"
        $index++
    }

    $config = @"
# Auto-generated RawrXD HAProxy Configuration
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

global
    log /dev/log local0
    maxconn 4096
    daemon

defaults
    mode http
    option redispatch
    retries 3
    timeout connect 5s
    timeout client 300s
    timeout server 300s

backend rawrxd_api
    balance leastconn
    option httpchk GET /health HTTP/1.1\\r\\nHost:\\ localhost
    http-check expect status 200
$(($serverConfig -join "`n"))

frontend rawrxd_frontend
    bind *:80
    bind *:443 ssl crt /etc/haproxy/ssl/rawrxd.pem
    default_backend rawrxd_api

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
"@

    return $config
}

# Main execution
Write-Log "RawrXD Load Balancer Setup Started"
Write-Log "Balancer Type: $BalancerType"
Write-Log "Backend Nodes: $($BackendNodes -join ', ')"

# Test backend health
$healthyNodes = Test-BackendHealth -Nodes $BackendNodes
if ($healthyNodes.Count -eq 0) {
    Write-Log "No healthy backend nodes found!" "ERROR"
    exit 1
}

Write-Log "Found $($healthyNodes.Count) healthy nodes"

# Install and configure
if ($BalancerType -eq "nginx") {
    $installPath = Install-Nginx
    $config = Generate-NginxConfig -Nodes $healthyNodes

    if ($IsWindows) {
        $configPath = "$installPath\conf\nginx.conf"
    } else {
        $configPath = "$installPath/sites-available/rawrxd"
    }

    $config | Out-File -FilePath $configPath -Encoding UTF8
    Write-Log "Configuration written to $configPath"

    if ($TestConfig) {
        Write-Log "Testing Nginx configuration..."
        & nginx -t
    }

    if ($InstallService) {
        Write-Log "Installing Nginx service..."
        if ($IsWindows) {
            nssm install Nginx $installPath\nginx.exe
            nssm start Nginx
        } else {
            systemctl enable nginx
            systemctl start nginx
        }
    }

} else {
    $installPath = Install-HAProxy
    $config = Generate-HAProxyConfig -Nodes $healthyNodes

    if ($IsWindows) {
        $configPath = "$installPath\haproxy.cfg"
    } else {
        $configPath = "$installPath/haproxy.cfg"
    }

    $config | Out-File -FilePath $configPath -Encoding UTF8
    Write-Log "Configuration written to $configPath"

    if ($TestConfig) {
        Write-Log "Testing HAProxy configuration..."
        & haproxy -c -f $configPath
    }

    if ($InstallService) {
        Write-Log "Installing HAProxy service..."
        if ($IsWindows) {
            nssm install HAProxy "$installPath\haproxy.exe" -f "$configPath"
            nssm start HAProxy
        } else {
            systemctl enable haproxy
            systemctl start haproxy
        }
    }
}

Write-Log "Load balancer setup complete!" "SUCCESS"
Write-Log "Log file: $LogFile"
