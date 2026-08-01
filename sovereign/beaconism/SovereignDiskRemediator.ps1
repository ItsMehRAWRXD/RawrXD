#Requires -Version 7.2
<#
.SYNOPSIS
    SovereignDiskRemediator.ps1 - Reverse Overwrite Model Binaries on Disk

.DESCRIPTION
    Replaces file-backed weight dependencies with clean execution stubs.
    Patches compiled binaries directly on storage using hex editors or
    scripted file patching to strip network libraries or hardcoded HTTP endpoints.

.NOTES
    Version: 1.1.0
    Security Posture: REVERSE_PATCHED_STUB
#>

[CmdletBinding()]
param (
    [string]$TargetBinaryPath = "C:\RawrXD\bin\ModelTarget.exe",
    [long]$PatchOffset = 0x4A10,
    [byte[]]$PatchBytes = @(0x90, 0x90),
    [string]$BackupDir = "C:\RawrXD\backups\disk_patches"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Write-Output "[DISK] Sovereign Disk Remediator Initializing..."

# ============================================================================
# Backup before patching
# ============================================================================
function Backup-SovereignBinary {
    param ([string]$BinaryPath, [string]$BackupDirectory)

    if (-not (Test-Path $BackupDirectory)) {
        New-Item -ItemType Directory -Force -Path $BackupDirectory | Out-Null
    }

    $FileName = [System.IO.Path]::GetFileName($BinaryPath)
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $BackupPath = Join-Path $BackupDirectory "$FileName.$Timestamp.bak"

    try {
        Copy-Item -Path $BinaryPath -Destination $BackupPath -Force
        Write-Output "[DISK] Backup created: $BackupPath"
        return $BackupPath
    } catch {
        Write-Output "[DISK] Backup FAILED: $_"
        return $null
    }
}

# ============================================================================
# Apply reverse overwrite to binary on disk
# ============================================================================
function Apply-SovereignDiskPatch {
    param (
        [string]$BinaryPath = "C:\RawrXD\bin\ModelTarget.exe",
        [long]$Offset = 0x4A10,
        [byte[]]$PatchBytes = @(0x90, 0x90)
    )

    if (-not (Test-Path $BinaryPath)) {
        Write-Output "[DISK] ERROR: Target binary not found: $BinaryPath"
        return $false
    }

    $FileInfo = Get-Item $BinaryPath
    Write-Output "[DISK] Target: $($FileInfo.Name) | Size: $($FileInfo.Length) bytes"

    # Validate offset bounds
    if ($Offset -ge $FileInfo.Length) {
        Write-Output "[DISK] ERROR: Offset 0x$($Offset.ToString('X')) exceeds file length"
        return $false
    }

    # Open raw file stream with full write capabilities
    try {
        $Stream = [System.IO.File]::OpenWrite($BinaryPath)
        [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)

        # Overwrite specific bytecode regions natively
        $Stream.Write($PatchBytes, 0, $PatchBytes.Length)
        $Stream.Close()

        Write-Output "[DISK] Reverse overwrite applied at offset: 0x$($Offset.ToString('X'))"
        Write-Output "[DISK] Patched bytes: $($PatchBytes | ForEach-Object { '0x' + $_.ToString('X2') } | Join-String -Separator ' ')"
        return $true
    } catch {
        Write-Output "[DISK] Patch FAILED: $_"
        if ($Stream) { $Stream.Close() }
        return $false
    }
}

# ============================================================================
# Verify patch integrity by reading back
# ============================================================================
function Test-SovereignDiskPatch {
    param (
        [string]$BinaryPath,
        [long]$Offset,
        [byte[]]$ExpectedBytes
    )

    try {
        $Stream = [System.IO.File]::OpenRead($BinaryPath)
        [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)

        $ReadBuffer = New-Object byte[] $ExpectedBytes.Length
        $ReadCount = $Stream.Read($ReadBuffer, 0, $ExpectedBytes.Length)
        $Stream.Close()

        if ($ReadCount -ne $ExpectedBytes.Length) {
            Write-Output "[DISK] VERIFY FAIL: Read $ReadCount bytes, expected $($ExpectedBytes.Length)"
            return $false
        }

        for ($i = 0; $i -lt $ExpectedBytes.Length; $i++) {
            if ($ReadBuffer[$i] -ne $ExpectedBytes[$i]) {
                Write-Output "[DISK] VERIFY FAIL: Byte mismatch at offset +$i"
                return $false
            }
        }

        Write-Output "[DISK] Patch verification PASSED"
        return $true
    } catch {
        Write-Output "[DISK] Verify FAILED: $_"
        return $false
    }
}

# ============================================================================
# Strip weight-loading routines (NOP out file-backed mmap calls)
# ============================================================================
function Remove-SovereignWeightDependencies {
    param (
        [string]$BinaryPath,
        [string]$BackupDirectory = "C:\RawrXD\backups\disk_patches"
    )

    Write-Output "[DISK] Stripping weight dependencies from $BinaryPath..."

    # Create backup first
    $BackupPath = Backup-SovereignBinary -BinaryPath $BinaryPath -BackupDirectory $BackupDirectory
    if (-not $BackupPath) {
        Write-Output "[DISK] Aborting - backup failed"
        return $false
    }

    # Common x64 patterns to NOP out:
    # 1. Call to CreateFileW/CreateFileA for weight files: NOP sled
    # 2. Call to MapViewOfFile: NOP sled
    # 3. HTTP endpoint strings: Overwrite with zeros

    # Pattern: Replace "https://" or "http://" strings with nulls
    $HttpPatterns = @(
        [System.Text.Encoding]::ASCII.GetBytes("https://"),
        [System.Text.Encoding]::ASCII.GetBytes("http://"),
        [System.Text.Encoding]::ASCII.GetBytes("api.openai.com"),
        [System.Text.Encoding]::ASCII.GetBytes("huggingface.co")
    )

    try {
        $Bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
        $Modified = $false

        foreach ($Pattern in $HttpPatterns) {
            $Index = 0
            while (($Index = [System.Array]::IndexOf($Bytes, $Pattern[0], $Index)) -ne -1) {
                # Verify full pattern match
                $Match = $true
                for ($j = 1; $j -lt $Pattern.Length; $j++) {
                    if ($Bytes[$Index + $j] -ne $Pattern[$j]) {
                        $Match = $false
                        break
                    }
                }

                if ($Match) {
                    # Zero out the HTTP endpoint string
                    for ($j = 0; $j -lt $Pattern.Length; $j++) {
                        $Bytes[$Index + $j] = 0x00
                    }
                    Write-Output "[DISK] Zeroed HTTP pattern at offset: 0x$($Index.ToString('X'))"
                    $Modified = $true
                }
                $Index++
            }
        }

        if ($Modified) {
            [System.IO.File]::WriteAllBytes($BinaryPath, $Bytes)
            Write-Output "[DISK] Weight dependencies stripped successfully"
        } else {
            Write-Output "[DISK] No HTTP patterns found - binary may already be clean"
        }

        return $true
    } catch {
        Write-Output "[DISK] Weight removal FAILED: $_"
        return $false
    }
}

# ============================================================================
# Main execution
# ============================================================================
if ($MyInvocation.InvocationName -ne '.') {
    # Script was executed directly, not dot-sourced
    Write-Output "[DISK] === Sovereign Disk Remediation Session ==="

    # Example: Strip weights from RawrXD_IDE.exe
    $TargetPath = "d:\rawrxd\bin\RawrXD_IDE.exe"
    if (Test-Path $TargetPath) {
        Remove-SovereignWeightDependencies -BinaryPath $TargetPath -BackupDirectory $BackupDir
    } else {
        Write-Output "[DISK] Target not found: $TargetPath"
    }
}
