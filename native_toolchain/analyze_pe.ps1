# PE Header Analyzer - PowerShell Version
# Analyzes PE files to diagnose "Access Denied" issues

param([string]$FilePath = "")

if ($FilePath -eq "") {
    Write-Host "Usage: .\analyze_pe.ps1 <filepath.exe>" -ForegroundColor Yellow
    Write-Host "Example: .\analyze_pe.ps1 .\test_proof.exe"
    exit 1
}

# Resolve full path
$FullPath = Resolve-Path $FilePath -ErrorAction SilentlyContinue
if (-not $FullPath) {
    $FullPath = $FilePath
}

if (-not (Test-Path $FullPath)) {
    Write-Host "❌ File not found: $FullPath" -ForegroundColor Red
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($FullPath)
$size = $bytes.Length

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  PE Analysis: $FilePath" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "File size: $size bytes`n"

# Check minimum size
if ($size -lt 64) {
    Write-Host "❌ File too small to be a valid PE" -ForegroundColor Red
    exit 1
}

# Check DOS signature
$dosMagic = [BitConverter]::ToUInt16($bytes, 0)
Write-Host "[1/8] DOS Header" -ForegroundColor Yellow
if ($dosMagic -eq 0x5A4D) {
    Write-Host "  ✅ DOS Signature: MZ (0x5A4D)" -ForegroundColor Green
} else {
    Write-Host "  ❌ DOS Signature: 0x$($dosMagic.ToString('X4')) (expected MZ = 0x5A4D)" -ForegroundColor Red
}

# Get e_lfanew (offset to PE header)
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
Write-Host "  e_lfanew: 0x$($e_lfanew.ToString('X8'))"

if ($e_lfanew -lt 64 -or $e_lfanew -gt ($size - 4)) {
    Write-Host "  ❌ Invalid e_lfanew offset!" -ForegroundColor Red
    exit 1
}

# Check PE signature
$peSig = [BitConverter]::ToUInt32($bytes, $e_lfanew)
Write-Host "`n[2/8] NT Headers" -ForegroundColor Yellow
if ($peSig -eq 0x00004550) {
    Write-Host "  ✅ PE Signature: PE\0\0 (0x00004550)" -ForegroundColor Green
} else {
    Write-Host "  ❌ PE Signature: 0x$($peSig.ToString('X8')) (expected 0x00004550)" -ForegroundColor Red
}

# File header
$fileHeaderOffset = $e_lfanew + 4
$machine = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset)
$numSections = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 2)
$timeStamp = [BitConverter]::ToUInt32($bytes, $fileHeaderOffset + 4)
$optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 16)
$characteristics = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 18)

Write-Host "`n[3/8] File Header" -ForegroundColor Yellow
$machineType = switch ($machine) {
    0x014c { "x86 (Intel 386)" }
    0x8664 { "x64 (AMD64)" }
    0xAA64 { "ARM64" }
    default { "Unknown (0x$($machine.ToString('X4')))" }
}
Write-Host "  Machine: 0x$($machine.ToString('X4')) - $machineType"
if ($machine -eq 0x8664) {
    Write-Host "  ✅ x64 architecture" -ForegroundColor Green
} elseif ($machine -eq 0x014c) {
    Write-Host "  ⚠️  x86 architecture (should still run on x64)" -ForegroundColor Yellow
} else {
    Write-Host "  ❌ Unknown architecture!" -ForegroundColor Red
}

Write-Host "  Number of Sections: $numSections"
if ($numSections -eq 0) {
    Write-Host "  ❌ No sections!" -ForegroundColor Red
}

Write-Host "  Time Stamp: $([DateTime]::UnixEpoch.AddSeconds($timeStamp).ToLocalTime())"
Write-Host "  Optional Header Size: $optionalHeaderSize bytes"
if ($optionalHeaderSize -eq 0) {
    Write-Host "  ❌ No optional header - not an executable!" -ForegroundColor Red
}

$isExecutable = ($characteristics -band 0x0002) -ne 0
Write-Host "  Characteristics: 0x$($characteristics.ToString('X4'))"
if ($isExecutable) {
    Write-Host "  ✅ Executable flag set" -ForegroundColor Green
} else {
    Write-Host "  ❌ Executable flag NOT set!" -ForegroundColor Red
}

# Optional header
if ($optionalHeaderSize -gt 0) {
    $optHeaderOffset = $fileHeaderOffset + 20
    $magic = [BitConverter]::ToUInt16($bytes, $optHeaderOffset)
    
    Write-Host "`n[4/8] Optional Header" -ForegroundColor Yellow
    Write-Host "  Magic: 0x$($magic.ToString('X4'))"
    if ($magic -eq 0x20B) {
        Write-Host "  ✅ PE32+ (64-bit)" -ForegroundColor Green
        $isPE32Plus = $true
    } elseif ($magic -eq 0x10B) {
        Write-Host "  ⚠️  PE32 (32-bit)" -ForegroundColor Yellow
        $isPE32Plus = $false
    } else {
        Write-Host "  ❌ Unknown magic!" -ForegroundColor Red
        $isPE32Plus = $false
    }
    
    if ($isPE32Plus) {
        $entryPoint = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 16)
        $imageBase = [BitConverter]::ToUInt64($bytes, $optHeaderOffset + 24)
        $sectionAlignment = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 32)
        $fileAlignment = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 36)
        $imageSize = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 56)
        $headersSize = [BitConverter]::ToUInt32($bytes, $optHeaderOffset + 60)
        $subsystem = [BitConverter]::ToUInt16($bytes, $optHeaderOffset + 68)
        $dllCharacteristics = [BitConverter]::ToUInt16($bytes, $optHeaderOffset + 70)
        
        Write-Host "`n[5/8] Memory Layout" -ForegroundColor Yellow
        Write-Host "  Entry Point RVA: 0x$($entryPoint.ToString('X8'))"
        if ($entryPoint -eq 0) {
            Write-Host "  ❌ Entry point is NULL!" -ForegroundColor Red
        } else {
            Write-Host "  ✅ Entry point defined" -ForegroundColor Green
        }
        
        Write-Host "  Image Base: 0x$($imageBase.ToString('X16'))"
        Write-Host "  Section Alignment: 0x$($sectionAlignment.ToString('X8'))"
        Write-Host "  File Alignment: 0x$($fileAlignment.ToString('X8'))"
        
        if ($sectionAlignment -lt $fileAlignment) {
            Write-Host "  ❌ Section alignment < file alignment!" -ForegroundColor Red
        }
        
        Write-Host "  Image Size: $imageSize bytes"
        Write-Host "  Headers Size: $headersSize bytes"
        
        $subsystemName = switch ($subsystem) {
            1 { "Native (Driver)" }
            2 { "Windows GUI" }
            3 { "Windows Console" }
            default { "Unknown ($subsystem)" }
        }
        Write-Host "`n[6/8] Subsystem" -ForegroundColor Yellow
        Write-Host "  Subsystem: $subsystem ($subsystemName)"
        if ($subsystem -eq 3) {
            Write-Host "  ✅ Console subsystem" -ForegroundColor Green
        } elseif ($subsystem -eq 2) {
            Write-Host "  ✅ GUI subsystem" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Unusual subsystem" -ForegroundColor Yellow
        }
        
        # Data directories
        Write-Host "`n[7/8] Data Directories" -ForegroundColor Yellow
        $dataDirOffset = $optHeaderOffset + 112
        for ($i = 0; $i -lt 16; $i++) {
            $rva = [BitConverter]::ToUInt32($bytes, $dataDirOffset + ($i * 8))
            $dirSize = [BitConverter]::ToUInt32($bytes, $dataDirOffset + ($i * 8) + 4)
            
            $dirNames = @(
                "Export", "Import", "Resource", "Exception", "Certificate",
                "Base Reloc", "Debug", "Architecture", "Global Ptr", "TLS",
                "Load Config", "Bound Import", "IAT", "Delay Import", "CLR Header", "Reserved"
            )
            
            if ($rva -ne 0 -and $dirSize -gt 0) {
                Write-Host "  $($dirNames[$i]): RVA=0x$($rva.ToString('X8')), Size=$dirSize"
            }
        }
    }
}

# Sections
if ($numSections -gt 0 -and $numSections -lt 100) {
    Write-Host "`n[8/8] Sections" -ForegroundColor Yellow
    $sectionTableOffset = $optHeaderOffset + $optionalHeaderSize
    
    for ($i = 0; $i -lt $numSections; $i++) {
        $secOffset = $sectionTableOffset + ($i * 40)
        if ($secOffset + 40 -gt $size) { break }
        
        $nameBytes = $bytes[$secOffset..($secOffset + 7)]
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd("`0")
        $virtualSize = [BitConverter]::ToUInt32($bytes, $secOffset + 8)
        $virtualAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $secOffset + 16)
        $rawAddr = [BitConverter]::ToUInt32($bytes, $secOffset + 20)
        $characteristics = [BitConverter]::ToUInt32($bytes, $secOffset + 36)
        
        $flags = @()
        if ($characteristics -band 0x20000000) { $flags += "EXEC" }
        if ($characteristics -band 0x40000000) { $flags += "READ" }
        if ($characteristics -band 0x80000000) { $flags += "WRITE" }
        if ($characteristics -band 0x00000020) { $flags += "CODE" }
        if ($characteristics -band 0x00000040) { $flags += "DATA" }
        
        Write-Host "  Section $i`: $name" -NoNewline
        Write-Host "  VA=0x$($virtualAddr.ToString('X8')), Size=$virtualSize, Flags=$($flags -join ',')"
    }
}

# Summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

$issues = @()
if ($dosMagic -ne 0x5A4D) { $issues += "Invalid DOS signature" }
if ($peSig -ne 0x00004550) { $issues += "Invalid PE signature" }
if ($machine -ne 0x8664 -and $machine -ne 0x014c) { $issues += "Unknown architecture" }
if ($numSections -eq 0) { $issues += "No sections" }
if ($optionalHeaderSize -eq 0) { $issues += "No optional header" }
if ($isPE32Plus -and $magic -ne 0x20B) { $issues += "Wrong optional header magic" }
if ($entryPoint -eq 0) { $issues += "No entry point" }
if ($sectionAlignment -lt $fileAlignment) { $issues += "Invalid alignment" }
if (-not $isExecutable) { $issues += "Not marked as executable" }

if ($issues.Count -eq 0) {
    Write-Host "✅ No critical issues found" -ForegroundColor Green
    Write-Host "`nThe file should execute. If it still fails:"
    Write-Host "  1. Check Windows Defender / antivirus"
    Write-Host "  2. Run as Administrator"
    Write-Host "  3. Check file permissions (icacls $FilePath)"
} else {
    Write-Host "❌ Found $($issues.Count) critical issue(s):" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "   - $issue" -ForegroundColor Red
    }
    Write-Host "`nThis file will NOT execute. Use pe_fixer.exe to repair."
}

Write-Host ""
