# RawrXD Remote Manager
# Manages remote instances and distributed operations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Connect", "Deploy", "Sync", "Execute", "Monitor", "Disconnect")]
    [string]$Action = "List",
    
    [string]$Host = "",
    [string]$User = "",
    [string]$KeyFile = "",
    [string]$Command = "",
    [string]$ConfigFile = "",
    [switch]$Parallel
)

$ErrorActionPreference = "Stop"

$script:RemoteConfigDir = "$env:USERPROFILE/.rawrxd/remote"
$script:KnownHostsFile = "$script:RemoteConfigDir/known_hosts.json"

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

function Initialize-RemoteManager {
    if (-not (Test-Path $script:RemoteConfigDir)) {
        New-Item -ItemType Directory -Path $script:RemoteConfigDir -Force | Out-Null
    }
    
    if (-not (Test-Path $script:KnownHostsFile)) {
        @{} | ConvertTo-Json | Out-File $script:KnownHostsFile
    }
    
    Write-Status "Remote Manager initialized"
}

function Get-KnownHosts {
    if (Test-Path $script:KnownHostsFile) {
        return Get-Content $script:KnownHostsFile | ConvertFrom-Json
    }
    return @{}
}

function Save-KnownHosts {
    param([hashtable]$Hosts)
    $Hosts | ConvertTo-Json -Depth 5 | Out-File $script:KnownHostsFile
}

function Show-RemoteHosts {
    $hosts = Get-KnownHosts
    
    Write-Host ""
    Write-Host "Known Remote Hosts" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    if ($hosts.Count -eq 0) {
        Write-Warning "No remote hosts configured"
        return
    }
    
    foreach ($hostEntry in $hosts.PSObject.Properties) {
        $info = $hostEntry.Value
        $status = if ($info.connected) { "Connected" } else { "Disconnected" }
        $statusColor = if ($info.connected) { "Green" } else { "Yellow" }
        
        Write-Host "  $($hostEntry.Name)" -ForegroundColor Cyan
        Write-Host "    Host: $($info.hostname):$($info.port)"
        Write-Host "    User: $($info.user)"
        Write-Host "    Status: $status" -ForegroundColor $statusColor
        if ($info.lastConnected) {
            Write-Host "    Last Connected: $($info.lastConnected)"
        }
        Write-Host ""
    }
}

function Connect-RemoteHost {
    param([string]$TargetHost, [string]$Username, [string]$Key)
    
    Write-Status "Connecting to: $TargetHost"
    
    $hosts = Get-KnownHosts
    
    # Test connection
    try {
        $session = New-PSSession -ComputerName $TargetHost -Credential (Get-Credential -UserName $Username -Message "Enter password for $Username@$TargetHost") -ErrorAction Stop
        
        $hosts.$TargetHost = @{
            hostname = $TargetHost
            port = 22
            user = $Username
            connected = $true
            lastConnected = Get-Date -Format "o"
            sessionId = $session.Id
        }
        
        Save-KnownHosts -Hosts $hosts
        Write-Success "Connected to $TargetHost"
        
        return $session
    }
    catch {
        Write-Error "Connection failed: $_"
        return $null
    }
}

function Invoke-RemoteCommand {
    param([string]$TargetHost, [string]$RemoteCommand)
    
    Write-Status "Executing on $TargetHost: $RemoteCommand"
    
    try {
        $result = Invoke-Command -ComputerName $TargetHost -ScriptBlock { 
            param($cmd)
            Invoke-Expression $cmd
        } -ArgumentList $RemoteCommand
        
        Write-Success "Command executed successfully"
        Write-Host "Output:"
        $result
    }
    catch {
        Write-Error "Command execution failed: $_"
    }
}

function Deploy-ToRemote {
    param([string]$TargetHost, [string]$SourcePath, [string]$DestPath)
    
    Write-Status "Deploying to $TargetHost"
    
    if (-not (Test-Path $SourcePath)) {
        Write-Error "Source not found: $SourcePath"
        return
    }
    
    try {
        # Create remote directory
        Invoke-Command -ComputerName $TargetHost -ScriptBlock {
            param($path)
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        } -ArgumentList $DestPath
        
        # Copy files
        Copy-Item -Path $SourcePath -Destination "\\$TargetHost\$DestPath" -Recurse -Force
        
        Write-Success "Deployed to $TargetHost"
    }
    catch {
        Write-Error "Deployment failed: $_"
    }
}

function Sync-RemoteData {
    param([string]$Source, [string]$Target, [string]$Direction = "Push")
    
    Write-Status "Syncing data: $Direction"
    
    try {
        if ($Direction -eq "Push") {
            # Local to remote
            Copy-Item -Path $Source -Destination $Target -Recurse -Force
        } else {
            # Remote to local
            Copy-Item -Path $Target -Destination $Source -Recurse -Force
        }
        
        Write-Success "Sync completed"
    }
    catch {
        Write-Error "Sync failed: $_"
    }
}

function Get-RemoteStatus {
    param([string]$TargetHost)
    
    Write-Status "Checking status of $TargetHost"
    
    try {
        $status = Invoke-Command -ComputerName $TargetHost -ScriptBlock {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                OS = (Get-CimInstance Win32_OperatingSystem).Caption
                Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
                CPU = (Get-CimInstance Win32_Processor).Name
                Memory = "{0:N2} GB" -f ((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
                DiskSpace = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' } | ForEach-Object { 
                    "{0:N2} GB free of {1:N2} GB" -f ($_.FreeSpace / 1GB), ($_.Size / 1GB)
                }
            }
        }
        
        Write-Host ""
        Write-Host "Remote Status: $TargetHost" -ForegroundColor Cyan
        Write-Host "========================" -ForegroundColor Cyan
        $status | Format-List
    }
    catch {
        Write-Error "Could not retrieve status: $_"
    }
}

function Disconnect-RemoteSession {
    param([string]$TargetHost)
    
    Write-Status "Disconnecting from $TargetHost"
    
    $hosts = Get-KnownHosts
    
    if ($hosts.$TargetHost) {
        $hosts.$TargetHost.connected = $false
        Save-KnownHosts -Hosts $hosts
    }
    
    # Remove session
    Get-PSSession | Where-Object { $_.ComputerName -eq $TargetHost } | Remove-PSSession
    
    Write-Success "Disconnected from $TargetHost"
}

# Main execution
function Main {
    Write-Host "RawrXD Remote Manager" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-RemoteManager
    
    switch ($Action) {
        "List" { Show-RemoteHosts }
        "Connect" { Connect-RemoteHost -TargetHost $Host -Username $User -Key $KeyFile }
        "Execute" { Invoke-RemoteCommand -TargetHost $Host -RemoteCommand $Command }
        "Deploy" { Deploy-ToRemote -TargetHost $Host -SourcePath $ConfigFile -DestPath $User }
        "Sync" { Sync-RemoteData -Source $ConfigFile -Target $User }
        "Monitor" { Get-RemoteStatus -TargetHost $Host }
        "Disconnect" { Disconnect-RemoteSession -TargetHost $Host }
    }
    
    Write-Host ""
}

Main
