# Deep PE Analysis - Try to load and analyze imports
param([string]$FilePath = ".\test_proof.exe")

if (-not (Test-Path $FilePath)) {
    Write-Host "❌ File not found: $FilePath" -ForegroundColor Red
    exit 1
}

$FullPath = Resolve-Path $FilePath
$bytes = [System.IO.File]::ReadAllBytes($FullPath)

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  DEEP ANALYSIS: $FilePath" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Parse PE
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$fileHeaderOffset = $e_lfanew + 4
$optHeaderOffset = $fileHeaderOffset + 20
$optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 16)
$numSections = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 2)

# Get import directory
$dataDirOffset = $optHeaderOffset + 112
$importRVA = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
$importSize = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 12)

Write-Host "`n[Import Table]" -ForegroundColor Yellow
Write-Host "  RVA: 0x$($importRVA.ToString('X8'))"
Write-Host "  Size: $importSize bytes"

if ($importRVA -eq 0 -or $importSize -eq 0) {
    Write-Host "  ⚠️  No import table!" -ForegroundColor Yellow
} else {
    # Find section containing imports
    $sectionTableOffset = $optHeaderOffset + $optionalHeaderSize
    $importFileOffset = 0
    
    for ($i = 0; $i -lt $numSections; $i++) {
        $secOffset = $sectionTableOffset + ($i * 40)
        $virtualAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 12)
        $rawAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 20)
        $virtualSize = [BitConverter]::ToUInt32($bytes, $secOffset + 8)
        
        if ($importRVA -ge $virtualAddr -and $importRVA -lt ($virtualAddr + $virtualSize)) {
            $importFileOffset = $rawAddr + ($importRVA - $virtualAddr)
            Write-Host "  Found in section at file offset: 0x$($importFileOffset.ToString('X8'))"
            break
        }
    }
    
    if ($importFileOffset -gt 0) {
        Write-Host "`n  Import Descriptors:" -ForegroundColor Yellow
        $descOffset = $importFileOffset
        $descNum = 0
        
        while ($descOffset + 20 -le $bytes.Length) {
            $iltRVA = [BitConverter]::ToUInt32($bytes, $descOffset)
            $timeStamp = [BitConverter]::ToUInt32($bytes, $descOffset + 4)
            $forwarderChain = [BitConverter]::ToUInt32($bytes, $descOffset + 8)
            $nameRVA = [BitConverter]::ToUInt32($bytes, $descOffset + 12)
            $iatRVA = [BitConverter]::ToUInt32($bytes, $descOffset + 16)
            
            if ($iltRVA -eq 0 -and $nameRVA -eq 0) { break }
            
            # Get DLL name
            $dllName = ""
            if ($nameRVA -gt 0) {
                $nameFileOffset = 0
                for ($i = 0; $i -lt $numSections; $i++) {
                    $secOffset = $sectionTableOffset + ($i * 40)
                    $virtualAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 12)
                    $rawAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 20)
                    $virtualSize = [BitConverter]::ToUInt32($bytes, $secOffset + 8)
                    
                    if ($nameRVA -ge $virtualAddr -and $nameRVA -lt ($virtualAddr + $virtualSize)) {
                        $nameFileOffset = $rawAddr + ($nameRVA - $virtualAddr)
                        break
                    }
                }
                
                if ($nameFileOffset -gt 0 -and $nameFileOffset -lt $bytes.Length) {
                    $nameBytes = @()
                    $j = $nameFileOffset
                    while ($j -lt $bytes.Length -and $bytes[$j] -ne 0) {
                        $nameBytes += $bytes[$j]
                        $j++
                    }
                    $dllName = [System.Text.Encoding]::ASCII.GetString($nameBytes)
                }
            }
            
            Write-Host "    [$descNum] $dllName" -ForegroundColor Green
            Write-Host "         ILT RVA: 0x$($iltRVA.ToString('X8'))"
            Write-Host "         IAT RVA: 0x$($iatRVA.ToString('X8'))"
            
            $descOffset += 20
            $descNum++
            if ($descNum -gt 20) { break }  # Safety limit
        }
    }
}

# Check file permissions
Write-Host "`n[File Permissions]" -ForegroundColor Yellow
$acl = Get-Acl $FullPath
Write-Host "  Owner: $($acl.Owner)"
Write-Host "  Access Rules:"
foreach ($rule in $acl.Access) {
    Write-Host "    - $($rule.IdentityReference): $($rule.FileSystemRights)"
}

# Try to execute
Write-Host "`n[Execution Test]" -ForegroundColor Yellow
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $FullPath
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

try {
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit(5000)  # 5 second timeout
    
    Write-Host "  ✅ Process started!" -ForegroundColor Green
    Write-Host "  Exit Code: $($process.ExitCode)"
    if ($stdout) { Write-Host "  STDOUT: $stdout" }
    if ($stderr) { Write-Host "  STDERR: $stderr" }
} catch {
    Write-Host "  ❌ Failed to start: $_" -ForegroundColor Red
    
    # Check specific error
    if ($_.Exception.Message -like "*access*") {
        Write-Host "`n  🔍 ACCESS DENIED Analysis:" -ForegroundColor Red
        Write-Host "     This could be caused by:"
        Write-Host "     1. Windows Defender SmartScreen"
        Write-Host "     2. Antivirus software"
        Write-Host "     3. Group Policy restrictions"
        Write-Host "     4. Corrupted import table"
        Write-Host "     5. Missing DLL dependencies"
    }
}

# Check Windows Defender
Write-Host "`n[Windows Defender Check]" -ForegroundColor Yellow
$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref) {
    Write-Host "  Real-time protection: $($mpPref.DisableRealtimeMonitoring -eq $false)"
    Write-Host "  Cloud-delivered protection: $($mpPref.DisableIOAVProtection -eq $false)"
} else {
    Write-Host "  ⚠️  Could not query Windows Defender settings"
}

Write-Host "`n================================================" -ForegroundColor Cyan
