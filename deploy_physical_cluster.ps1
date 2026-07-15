# Sovereign Engine Physical Deployment
# Deploys to 8-node cluster at 192.168.1.10-17
# Usage: .\deploy_physical_cluster.ps1 [-ValidateOnly] [-WhatIf]

param(
    [switch]$ValidateOnly = $false,
    [switch]$WhatIf = $false
)

$ErrorActionPreference = "Stop"

# Physical node configuration
$Nodes = @(
    @{ Id = 0; Role = "HEAD";   IP = "192.168.1.10"; RouterPort = 5555; PubPort = 5556; GPU = $true;  AMX = $true },
    @{ Id = 1; Role = "WORKER"; IP = "192.168.1.11"; RouterPort = 5557; PubPort = 5558; GPU = $true;  AMX = $true },
    @{ Id = 2; Role = "WORKER"; IP = "192.168.1.12"; RouterPort = 5559; PubPort = 5560; GPU = $true;  AMX = $true },
    @{ Id = 3; Role = "WORKER"; IP = "192.168.1.13"; RouterPort = 5561; PubPort = 5562; GPU = $true;  AMX = $true },
    @{ Id = 4; Role = "WORKER"; IP = "192.168.1.14"; RouterPort = 5563; PubPort = 5564; GPU = $false; AMX = $true },
    @{ Id = 5; Role = "WORKER"; IP = "192.168.1.15"; RouterPort = 5565; PubPort = 5566; GPU = $false; AMX = $true },
    @{ Id = 6; Role = "WORKER"; IP = "192.168.1.16"; RouterPort = 5567; PubPort = 5568; GPU = $false; AMX = $true },
    @{ Id = 7; Role = "WORKER"; IP = "192.168.1.17"; RouterPort = 5569; PubPort = 5570; GPU = $false; AMX = $true }
)

$BinarySource = "D:\RawrXD\build\bin"
$RemoteBinaryPath = "C:\Sovereign\bin"
$RemoteConfigPath = "C:\Sovereign\config"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Physical Deployment" -ForegroundColor Cyan
Write-Host "Target: 8-Node Cluster (192.168.1.10-17)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "WHATIF MODE: No changes will be made`n" -ForegroundColor Magenta
}

# Phase 1: Pre-deployment Validation
Write-Host "Phase 1: Pre-deployment Validation" -ForegroundColor Yellow

$allNodesReady = $true
$validationResults = @()

foreach ($node in $Nodes) {
    Write-Host "  Checking Node $($node.Id) ($($node.IP))..." -NoNewline
    
    $result = @{
        NodeId = $node.Id
        IP = $node.IP
        Reachable = $false
        PortsOpen = $false
        WinRM = $false
    }
    
    # Test connectivity
    if (Test-Connection -ComputerName $node.IP -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Host " ✅ Online" -ForegroundColor Green
        $result.Reachable = $true
    } else {
        Write-Host " ❌ Offline" -ForegroundColor Red
        $allNodesReady = $false
        $validationResults += $result
        continue
    }
    
    # Check WinRM
    try {
        $winrmTest = Test-WSMan -ComputerName $node.IP -ErrorAction SilentlyContinue
        if ($winrmTest) {
            Write-Host "    WinRM: ✅ Enabled" -ForegroundColor Green
            $result.WinRM = $true
        } else {
            Write-Host "    WinRM: ⚠️ Check service" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    WinRM: ❌ Not accessible" -ForegroundColor Red
        $allNodesReady = $false
    }
    
    # Check ports
    try {
        $portTest = Test-NetConnection -ComputerName $node.IP -Port $node.RouterPort -WarningAction SilentlyContinue
        if ($portTest.TcpTestSucceeded) {
            Write-Host "    Port $($node.RouterPort): ✅ Open" -ForegroundColor Green
            $result.PortsOpen = $true
        } else {
            Write-Host "    Port $($node.RouterPort): ⚠️ May need firewall rule" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Port check: ⚠️ Unable to verify" -ForegroundColor Yellow
    }
    
    $validationResults += $result
}

Write-Host "`nValidation Summary:" -ForegroundColor Yellow
$reachableNodes = ($validationResults | Where-Object { $_.Reachable }).Count
$winrmNodes = ($validationResults | Where-Object { $_.WinRM }).Count
Write-Host "  Reachable: $reachableNodes/8" -ForegroundColor $(if ($reachableNodes -eq 8) { "Green" } else { "Yellow" })
Write-Host "  WinRM: $winrmNodes/8" -ForegroundColor $(if ($winrmNodes -eq 8) { "Green" } else { "Yellow" })

if ($ValidateOnly) {
    Write-Host "`n✅ Validation complete. Use -ValidateOnly:$false to deploy." -ForegroundColor Green
    exit 0
}

if (-not $allNodesReady) {
    Write-Host "`n⚠️  Some nodes are not ready. Continue anyway? (y/N)" -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -ne 'y') {
        Write-Host "Deployment cancelled." -ForegroundColor Red
        exit 1
    }
}

# Phase 2: Binary Distribution
Write-Host "`nPhase 2: Binary Distribution" -ForegroundColor Yellow

if (-not (Test-Path $BinarySource)) {
    Write-Host "❌ Binary source not found: $BinarySource" -ForegroundColor Red
    exit 1
}

$binaries = @(
    "sovereign_engine.dll",
    "sovereign_cli.exe",
    "sovereign_head.exe",
    "sovereign_worker.exe"
)

foreach ($node in $Nodes | Where-Object { $_.Reachable -or $allNodesReady }) {
    Write-Host "  Deploying to Node $($node.Id) ($($node.IP))..." -NoNewline
    
    if ($WhatIf) {
        Write-Host " WHATIF: Would copy binaries" -ForegroundColor Magenta
        continue
    }
    
    try {
        # Create remote directories
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($binPath, $cfgPath)
            New-Item -ItemType Directory -Path $binPath -Force | Out-Null
            New-Item -ItemType Directory -Path $cfgPath -Force | Out-Null
        } -ArgumentList $RemoteBinaryPath, $RemoteConfigPath -ErrorAction Stop
        
        # Copy binaries
        foreach ($binary in $binaries) {
            $sourcePath = Join-Path $BinarySource $binary
            if (Test-Path $sourcePath) {
                Copy-Item -Path $sourcePath -Destination "\\$($node.IP)\$($RemoteBinaryPath.Replace(':', '$'))\" -Force
            }
        }
        
        Write-Host " ✅ Deployed" -ForegroundColor Green
    } catch {
        Write-Host " ❌ Failed: $_" -ForegroundColor Red
    }
}

# Phase 3: Configuration Generation
Write-Host "`nPhase 3: Configuration Generation" -ForegroundColor Yellow

foreach ($node in $Nodes) {
    $config = @{
        node_id = $node.Id
        role = $node.Role
        ip = $node.IP
        router_port = $node.RouterPort
        pub_port = $node.PubPort
        has_gpu = $node.GPU
        has_amx = $node.AMX
        head_ip = $Nodes[0].IP
        head_router_port = $Nodes[0].RouterPort
        head_pub_port = $Nodes[0].PubPort
        total_nodes = 8
        metrics_port = 8080 + $node.Id
    } | ConvertTo-Json -Depth 10
    
    $configPath = Join-Path $RemoteConfigPath "node_$($node.Id)_config.json"
    
    if ($WhatIf) {
        Write-Host "  Node $($node.Id): WHATIF - Would create config" -ForegroundColor Magenta
    } else {
        # Save locally first, then copy
        $localConfig = "D:\RawrXD\temp_config_node_$($node.Id).json"
        $config | Set-Content $localConfig
        
        try {
            Copy-Item -Path $localConfig -Destination "\\$($node.IP)\$($RemoteConfigPath.Replace(':', '$'))\config.json" -Force
            Remove-Item $localConfig
            Write-Host "  Node $($node.Id): ✅ Config deployed" -ForegroundColor Green
        } catch {
            Write-Host "  Node $($node.Id): ❌ Config failed" -ForegroundColor Red
        }
    }
}

# Phase 4: Firewall Configuration
Write-Host "`nPhase 4: Firewall Configuration" -ForegroundColor Yellow

$firewallScript = @"
# Sovereign Engine Firewall Rules
New-NetFirewallRule -DisplayName "Sovereign-ZMQ-Router" -Direction Inbound -LocalPort 5555-5570 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Sovereign-ZMQ-Pub" -Direction Inbound -LocalPort 5556-5570 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Sovereign-Metrics" -Direction Inbound -LocalPort 8080-8087 -Protocol TCP -Action Allow
"@

foreach ($node in $Nodes | Where-Object { $_.Reachable -or $allNodesReady }) {
    Write-Host "  Configuring Node $($node.Id) firewall..." -NoNewline
    
    if ($WhatIf) {
        Write-Host " WHATIF" -ForegroundColor Magenta
        continue
    }
    
    try {
        Invoke-Command -ComputerName $node.IP -ScriptBlock {
            param($script)
            Invoke-Expression $script
        } -ArgumentList $firewallScript -ErrorAction Stop
        Write-Host " ✅ Rules applied" -ForegroundColor Green
    } catch {
        Write-Host " ⚠️  Manual config required" -ForegroundColor Yellow
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Deployment Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "`nWHATIF: No changes were made." -ForegroundColor Magenta
    Write-Host "Run without -WhatIf to execute deployment." -ForegroundColor Gray
} else {
    Write-Host "`n✅ Deployment complete!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "  1. Start swarm: .\start_swarm.ps1" -ForegroundColor Gray
    Write-Host "  2. Monitor: .\monitor_cluster.ps1" -ForegroundColor Gray
    Write-Host "  3. Test: .\integration_test_full.ps1" -ForegroundColor Gray
}
