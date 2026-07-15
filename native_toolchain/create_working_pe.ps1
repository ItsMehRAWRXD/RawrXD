# Create a minimal working PE executable
# This creates a valid x64 PE that returns exit code 42

param([string]$OutputFile = "working_test.exe")

Write-Host "Creating minimal working PE executable..." -ForegroundColor Cyan
Write-Host "Output: $OutputFile" -ForegroundColor Yellow

# Create a minimal PE file
$pe = @()

# DOS Header (64 bytes)
$pe += [byte[]](0x4D, 0x5A)  # MZ signature
$pe += [byte[]](0x00) * 58   # Padding
$pe += [byte[]](0x80, 0x00, 0x00, 0x00)  # e_lfanew: offset to PE header (0x80)

# DOS Stub (at offset 0x40, up to 0x80)
$pe += [byte[]](0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68)
$pe += [byte[]](0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F)
$pe += [byte[]](0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20)
$pe += [byte[]](0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

# PE Signature (at offset 0x80)
$pe += [byte[]](0x50, 0x45, 0x00, 0x00)  # PE\0\0

# File Header (20 bytes at offset 0x84)
$pe += [byte[]](0x64, 0x86)  # Machine: AMD64
$pe += [byte[]](0x01, 0x00)  # NumberOfSections: 1
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)  # TimeDateStamp
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)  # PointerToSymbolTable
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)  # NumberOfSymbols
$pe += [byte[]](0xF0, 0x00)  # SizeOfOptionalHeader: 240
$pe += [byte[]](0x22, 0x00)  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

# Optional Header (240 bytes at offset 0x98)
# Magic: PE32+ (0x020B)
$pe += [byte[]](0x0B, 0x02)
# MajorLinkerVersion, MinorLinkerVersion
$pe += [byte[]](0x0E, 0x00)
# SizeOfCode
$pe += [byte[]](0x00, 0x10, 0x00, 0x00)  # 4096
# SizeOfInitializedData
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# SizeOfUninitializedData
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# AddressOfEntryPoint
$pe += [byte[]](0x00, 0x10, 0x00, 0x00)  # 0x1000
# BaseOfCode
$pe += [byte[]](0x00, 0x10, 0x00, 0x00)  # 0x1000
# ImageBase (8 bytes)
$pe += [byte[]](0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00)  # 0x140000000
# SectionAlignment
$pe += [byte[]](0x00, 0x10, 0x00, 0x00)  # 0x1000
# FileAlignment
$pe += [byte[]](0x00, 0x02, 0x00, 0x00)  # 0x200
# MajorOperatingSystemVersion, MinorOperatingSystemVersion
$pe += [byte[]](0x06, 0x00, 0x00, 0x00)
# MajorImageVersion, MinorImageVersion
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# MajorSubsystemVersion, MinorSubsystemVersion
$pe += [byte[]](0x06, 0x00, 0x00, 0x00)
# Win32VersionValue
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# SizeOfImage
$pe += [byte[]](0x00, 0x20, 0x00, 0x00)  # 0x2000
# SizeOfHeaders
$pe += [byte[]](0x00, 0x02, 0x00, 0x00)  # 512
# CheckSum
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# Subsystem: WINDOWS_CUI (3)
$pe += [byte[]](0x03, 0x00)
# DllCharacteristics
$pe += [byte[]](0x00, 0x00)
# SizeOfStackReserve (8 bytes)
$pe += [byte[]](0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00)  # 0x100000
# SizeOfStackCommit (8 bytes)
$pe += [byte[]](0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)  # 0x1000
# SizeOfHeapReserve (8 bytes)
$pe += [byte[]](0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00)  # 0x100000
# SizeOfHeapCommit (8 bytes)
$pe += [byte[]](0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)  # 0x1000
# LoaderFlags
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)
# NumberOfRvaAndSizes
$pe += [byte[]](0x10, 0x00, 0x00, 0x00)

# Data Directories (16 entries, 8 bytes each = 128 bytes)
# All zero (no imports, exports, etc.)
$pe += [byte[]](0x00) * 128

# Section Header (40 bytes at offset 0x188)
# .text section
$pe += [byte[]](0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00)  # Name: .text
$pe += [byte[]](0x10, 0x00, 0x00, 0x00)  # VirtualSize: 16
$pe += [byte[]](0x00, 0x10, 0x00, 0x00)  # VirtualAddress: 0x1000
$pe += [byte[]](0x00, 0x02, 0x00, 0x00)  # SizeOfRawData: 512
$pe += [byte[]](0x00, 0x02, 0x00, 0x00)  # PointerToRawData: 512
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)  # PointerToRelocations
$pe += [byte[]](0x00, 0x00, 0x00, 0x00)  # PointerToLinenumbers
$pe += [byte[]](0x00, 0x00)  # NumberOfRelocations
$pe += [byte[]](0x00, 0x00)  # NumberOfLinenumbers
$pe += [byte[]](0x20, 0x00, 0x00, 0x60)  # Characteristics: CODE | EXECUTE | READ

# Pad to file alignment (512 bytes)
while ($pe.Length -lt 512) {
    $pe += [byte[]](0x00)
}

# Code section (at offset 512, mapped to 0x1000)
# mov eax, 42 (0xB8 0x2A 0x00 0x00 0x00)
# ret (0xC3)
$code = [byte[]](0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3)
$pe += $code

# Pad to 512 bytes for code section
while ($pe.Length -lt 1024) {
    $pe += [byte[]](0x00)
}

# Write the file
[System.IO.File]::WriteAllBytes($OutputFile, $pe)

Write-Host "`n✅ Created: $OutputFile" -ForegroundColor Green
Write-Host "   Size: $($pe.Length) bytes"
Write-Host "   Architecture: x64"
Write-Host "   Entry point: 0x1000"
Write-Host "   Returns: 42"

# Verify by reading back
$verify = [System.IO.File]::ReadAllBytes($OutputFile)
$dosMagic = [BitConverter]::ToUInt16($verify, 0)
$e_lfanew = [BitConverter]::ToInt32($verify, 0x3C)
$peSig = [BitConverter]::ToUInt32($verify, $e_lfanew)
$machine = [BitConverter]::ToUInt16($verify, $e_lfanew + 4)

Write-Host "`n[Verification]" -ForegroundColor Yellow
Write-Host "   DOS Magic: 0x$($dosMagic.ToString('X4')) $(if ($dosMagic -eq 0x5A4D) { '(OK)' } else { '(FAIL)' })"
Write-Host "   PE Sig: 0x$($peSig.ToString('X8')) $(if ($peSig -eq 0x00004550) { '(OK)' } else { '(FAIL)' })"
Write-Host "   Machine: 0x$($machine.ToString('X4')) $(if ($machine -eq 0x8664) { '(x64 OK)' } else { '(FAIL)' })"

# Test execution
Write-Host "`n[Execution Test]" -ForegroundColor Yellow
try {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $OutputFile
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $pinfo
    $process.Start() | Out-Null
    $process.WaitForExit(5000)
    
    Write-Host "   Exit code: $($process.ExitCode)" -ForegroundColor Green
    if ($process.ExitCode -eq 42) {
        Write-Host "   ✅ SUCCESS! Executable works correctly!" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Unexpected exit code" -ForegroundColor Yellow
    }
} catch {
    Write-Host "   ❌ Failed to execute: $_" -ForegroundColor Red
}

Write-Host ""
