# Sovereign Engine - Environment Lock
# Freezes the codebase to ensure deployment integrity
# Usage: .\freeze_environment.ps1 [-Lock] [-Unlock] [-Status]

param(
    [switch]$Lock = $false,
    [switch]$Unlock = $false,
    [switch]$Status = $false,
    [string]$LockFile = "D:\RawrXD\ENVIRONMENT_LOCK.json",
    [string[]]$ProtectedPaths = @(
        "D:\RawrXD\asm\*.asm",
        "D:\RawrXD\RawrXD_*.asm",
        "D:\RawrXD\src\Sovereign_*.cpp",
        "D:\RawrXD\src\core\*.cpp",
        "D:\RawrXD\deploy_*.ps1",
        "D:\RawrXD\start_swarm.ps1",
        "D:\RawrXD\stop_swarm.ps1",
        "D:\RawrXD\monitor_cluster.ps1"
    )
)

$ErrorActionPreference = "Stop"

function Get-FileHashList {
    param($Path)
    
    $hashes = @{}
    foreach ($pattern in $Path) {
        Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            $hash = Get-FileHash $_.FullName -Algorithm SHA256
            $hashes[$_.FullName] = $hash.Hash
        }
    }
    return $hashes
}

function Write-LockFile {
    param($Hashes)
    
    $lockData = @{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Version = "1.0.0"
        Status = "LOCKED"
        Files = $Hashes
    }
    
    $lockData | ConvertTo-Json -Depth 10 | Out-File $LockFile -Encoding UTF8
}

function Read-LockFile {
    if (Test-Path $LockFile) {
        return Get-Content $LockFile | ConvertFrom-Json
    }
    return $null
}

function Test-EnvironmentIntegrity {
    param($LockData)
    
    $currentHashes = Get-FileHashList -Path $ProtectedPaths
    $violations = @()
    
    foreach ($file in $LockData.Files.PSObject.Properties) {
        $expectedHash = $file.Value
        $actualHash = $currentHashes[$file.Name]
        
        if ($actualHash -ne $expectedHash) {
            $violations += @{
                File = $file.Name
                Expected = $expectedHash
                Actual = $actualHash
            }
        }
    }
    
    return $violations
}

# Main logic
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           SOVEREIGN ENGINE - ENVIRONMENT LOCK                  ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Status -or (-not $Lock -and -not $Unlock)) {
    # Show current status
    $lockData = Read-LockFile
    
    if ($lockData) {
        Write-Host "🔒 Environment Status: $($lockData.Status)" -ForegroundColor $(if($lockData.Status -eq "LOCKED"){"Green"}else{"Yellow"})
        Write-Host "   Locked at: $($lockData.Timestamp)"
        Write-Host "   Version: $($lockData.Version)"
        Write-Host "   Protected files: $($lockData.Files.PSObject.Properties.Count)"
        Write-Host ""
        
        if ($lockData.Status -eq "LOCKED") {
            Write-Host "🔍 Checking integrity..." -ForegroundColor Yellow
            $violations = Test-EnvironmentIntegrity -LockData $lockData
            
            if ($violations.Count -eq 0) {
                Write-Host "   ✅ All files match lock signature" -ForegroundColor Green
            } else {
                Write-Host "   ⚠️  $($violations.Count) file(s) modified since lock:" -ForegroundColor Red
                foreach ($v in $violations) {
                    Write-Host "      - $(Split-Path $v.File -Leaf)" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "🔓 Environment Status: UNLOCKED" -ForegroundColor Yellow
        Write-Host "   No lock file found. Environment is mutable."
    }
    
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "   .\freeze_environment.ps1 -Lock    # Freeze environment"
    Write-Host "   .\freeze_environment.ps1 -Unlock # Unfreeze environment"
    Write-Host "   .\freeze_environment.ps1 -Status # Check status"
    Write-Host ""
    exit 0
}

if ($Lock) {
    Write-Host "🔒 LOCKING ENVIRONMENT..." -ForegroundColor Yellow
    Write-Host ""
    
    # Calculate hashes
    Write-Host "   Calculating file hashes..." -ForegroundColor Gray
    $hashes = Get-FileHashList -Path $ProtectedPaths
    
    # Write lock file
    Write-LockFile -Hashes $hashes
    
    Write-Host ""
    Write-Host "   ✅ Environment LOCKED" -ForegroundColor Green
    Write-Host "   📁 Lock file: $LockFile"
    Write-Host "   🔐 Protected files: $($hashes.Count)"
    Write-Host ""
    Write-Host "   Any modifications to protected files will be detected."
    Write-Host "   Run with -Status to verify integrity."
    Write-Host ""
    
    # Create a marker file
    "ENVIRONMENT_LOCKED_$(Get-Date -Format 'yyyyMMdd_HHmmss')" | Out-File "D:\RawrXD\LOCKED.marker" -Force
}

if ($Unlock) {
    Write-Host "🔓 UNLOCKING ENVIRONMENT..." -ForegroundColor Yellow
    Write-Host ""
    
    if (Test-Path $LockFile) {
        Remove-Item $LockFile -Force
        Write-Host "   ✅ Lock file removed" -ForegroundColor Green
    }
    
    if (Test-Path "D:\RawrXD\LOCKED.marker") {
        Remove-Item "D:\RawrXD\LOCKED.marker" -Force
    }
    
    Write-Host ""
    Write-Host "   🔓 Environment UNLOCKED" -ForegroundColor Yellow
    Write-Host "   Changes to protected files are now allowed."
    Write-Host ""
}
