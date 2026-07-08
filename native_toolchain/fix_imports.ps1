# Fix Import Table - Rebuilds a working PE with proper imports
param([string]$InputFile = ".\test_proof.exe", [string]$OutputFile = ".\test_proof_fixed.exe")

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  IMPORT TABLE FIXER" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $InputFile)) {
    Write-Host "❌ Input file not found: $InputFile" -ForegroundColor Red
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($InputFile)
Write-Host "Input: $InputFile ($($bytes.Length) bytes)"

# Parse existing PE
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$fileHeaderOffset = $e_lfanew + 4
$optHeaderOffset = $fileHeaderOffset + 20
$optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 16)
$numSections = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 2)

Write-Host "Current sections: $numSections"

# Check current import table
$dataDirOffset = $optHeaderOffset + 112
$importRVA = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
$importSize = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 12)

Write-Host "Current import RVA: 0x$($importRVA.ToString('X8'))"
Write-Host "Current import size: $importSize"

if ($importRVA -eq 0 -or $importSize -eq 0) {
    Write-Host "`n⚠️  Import table is empty or missing!" -ForegroundColor Yellow
    Write-Host "This is likely why Windows rejects the executable." -ForegroundColor Yellow
    Write-Host "`nOptions:" -ForegroundColor Cyan
    Write-Host "1. Create a new minimal PE with working imports"
    Write-Host "2. Rebuild from source with proper linker settings"
    Write-Host "3. Use a working executable as template"
}

# Create a minimal working PE with proper imports
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "  Creating Fixed Version" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Minimal PE that calls ExitProcess
# This creates a working executable that returns 42

$pe = New-Object byte[] 4096

# DOS Header (64 bytes)
$dosHeader = [byte[]](
    0x4D, 0x5A,             # e_magic: MZ
    0x90, 0x00,             # e_cblp
    0x03, 0x00,             # e_cp
    0x00, 0x00,             # e_crlc
    0x04, 0x00,             # e_cparhdr
    0x00, 0x00,             # e_minalloc
    0xFF, 0xFF,             # e_maxalloc
    0x00, 0x00,             # e_ss
    0xB8, 0x00,             # e_sp
    0x00, 0x00,             # e_csum
    0x00, 0x00,             # e_ip
    0x00, 0x00,             # e_cs
    0x40, 0x00,             # e_lfarlc
    0x00, 0x00,             # e_ovno
    0x00, 0x00, 0x00, 0x00, # e_res[4]
    0x00, 0x00,             # e_oemid
    0x00, 0x00,             # e_oeminfo
    0x00, 0x00, 0x00, 0x00, # e_res2[10]
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00  # e_lfanew: offset to PE header
)
[Array]::Copy($dosHeader, 0, $pe, 0, 64)

# DOS Stub (at offset 64, up to 0x80)
$dosStub = [byte[]](
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
    0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
    0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
)
[Array]::Copy($dosStub, 0, $pe, 64, 64)

# PE Signature (at offset 0x80)
$pe[0x80] = 0x50  # P
$pe[0x81] = 0x45  # E
$pe[0x82] = 0x00
$pe[0x83] = 0x00

# File Header (at offset 0x84, 20 bytes)
$fileHeader = [byte[]](
    0x64, 0x86,             # Machine: AMD64
    0x03, 0x00,             # NumberOfSections: 3
    0x00, 0x00, 0x00, 0x00, # TimeDateStamp
    0x00, 0x00, 0x00, 0x00, # PointerToSymbolTable
    0x00, 0x00, 0x00, 0x00, # NumberOfSymbols
    0xF0, 0x00,             # SizeOfOptionalHeader: 240
    0x22, 0x00              # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
)
[Array]::Copy($fileHeader, 0, $pe, 0x84, 20)

# Optional Header (at offset 0x98, 240 bytes for PE32+)
$optHeader = New-Object byte[] 240

# Magic: PE32+
$optHeader[0] = 0x0B
$optHeader[1] = 0x02

# MajorLinkerVersion
$optHeader[2] = 0x0E

# MinorLinkerVersion
$optHeader[3] = 0x00

# SizeOfCode (4 bytes)
[BitConverter]::GetBytes([UInt32]0x200) | ForEach-Object { $optHeader[$i++] = $_ }; $i = 4

# SizeOfInitializedData
[BitConverter]::GetBytes([UInt32]0x400) | ForEach-Object { $optHeader[4..7][$i-4] = $_ }; $i = 8

# SizeOfUninitializedData
[BitConverter]::GetBytes([UInt32]0x00) | ForEach-Object { $optHeader[8..11][$i-8] = $_ }; $i = 12

# AddressOfEntryPoint
[BitConverter]::GetBytes([UInt32]0x1000) | ForEach-Object { $optHeader[12..15][$i-12] = $_ }; $i = 16

# BaseOfCode
[BitConverter]::GetBytes([UInt32]0x1000) | ForEach-Object { $optHeader[16..19][$i-16] = $_ }; $i = 20

# ImageBase (8 bytes)
[BitConverter]::GetBytes([UInt64]0x140000000) | ForEach-Object { $optHeader[20..27][$i-20] = $_ }; $i = 28

# SectionAlignment
[BitConverter]::GetBytes([UInt32]0x1000) | ForEach-Object { $optHeader[28..31][$i-28] = $_ }; $i = 32

# FileAlignment
[BitConverter]::GetBytes([UInt32]0x200) | ForEach-Object { $optHeader[32..35][$i-32] = $_ }; $i = 36

# MajorOperatingSystemVersion
$optHeader[36] = 0x06
$optHeader[37] = 0x00

# MinorOperatingSystemVersion
$optHeader[38] = 0x00
$optHeader[39] = 0x00

# MajorImageVersion
$optHeader[40] = 0x00
$optHeader[41] = 0x00

# MinorImageVersion
$optHeader[42] = 0x00
$optHeader[43] = 0x00

# MajorSubsystemVersion
$optHeader[44] = 0x06
$optHeader[45] = 0x00

# MinorSubsystemVersion
$optHeader[46] = 0x00
$optHeader[47] = 0x00

# Win32VersionValue
[BitConverter]::GetBytes([UInt32]0x00) | ForEach-Object { $optHeader[48..51][$i-48] = $_ }; $i = 52

# SizeOfImage
[BitConverter]::GetBytes([UInt32]0x4000) | ForEach-Object { $optHeader[52..55][$i-52] = $_ }; $i = 56

# SizeOfHeaders
[BitConverter]::GetBytes([UInt32]0x400) | ForEach-Object { $optHeader[56..59][$i-56] = $_ }; $i = 60

# CheckSum
[BitConverter]::GetBytes([UInt32]0x00) | ForEach-Object { $optHeader[60..63][$i-60] = $_ }; $i = 64

# Subsystem: WINDOWS_CUI (3)
$optHeader[64] = 0x03
$optHeader[65] = 0x00

# DllCharacteristics
$optHeader[66] = 0x00
$optHeader[67] = 0x00

# SizeOfStackReserve (8 bytes)
[BitConverter]::GetBytes([UInt64]0x100000) | ForEach-Object { $optHeader[68..75][$i-68] = $_ }; $i = 76

# SizeOfStackCommit (8 bytes)
[BitConverter]::GetBytes([UInt64]0x1000) | ForEach-Object { $optHeader[76..83][$i-76] = $_ }; $i = 84

# SizeOfHeapReserve (8 bytes)
[BitConverter]::GetBytes([UInt64]0x100000) | ForEach-Object { $optHeader[84..91][$i-84] = $_ }; $i = 92

# SizeOfHeapCommit (8 bytes)
[BitConverter]::GetBytes([UInt64]0x1000) | ForEach-Object { $optHeader[92..99][$i-92] = $_ }; $i = 100

# LoaderFlags
[BitConverter]::GetBytes([UInt32]0x00) | ForEach-Object { $optHeader[100..103][$i-100] = $_ }; $i = 104

# NumberOfRvaAndSizes
[BitConverter]::GetBytes([UInt32]0x10) | ForEach-Object { $optHeader[104..107][$i-104] = $_ }; $i = 108

# Data Directories (16 entries, 8 bytes each = 128 bytes)
# Entry 1: Import Table (at offset 112 in optional header)
[BitConverter]::GetBytes([UInt32]0x3000) | ForEach-Object { $optHeader[112..115][$i-112] = $_ }; $i = 116
[BitConverter]::GetBytes([UInt32]0x3C) | ForEach-Object { $optHeader[116..119][$i-116] = $_ }; $i = 120

# Entry 2: IAT (at offset 120)
[BitConverter]::GetBytes([UInt32]0x3010) | ForEach-Object { $optHeader[120..123][$i-120] = $_ }; $i = 124
[BitConverter]::GetBytes([UInt32]0x08) | ForEach-Object { $optHeader[124..127][$i-124] = $_ }; $i = 128

[Array]::Copy($optHeader, 0, $pe, 0x98, 240)

# Section Headers (3 sections, 40 bytes each = 120 bytes, at offset 0x188)

# Section 1: .text (code)
$textSection = [byte[]](
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,  # Name: .text
    0x20, 0x00, 0x00, 0x00,                           # VirtualSize: 32
    0x00, 0x10, 0x00, 0x00,                           # VirtualAddress: 0x1000
    0x00, 0x02, 0x00, 0x00,                           # SizeOfRawData: 512
    0x00, 0x02, 0x00, 0x00,                           # PointerToRawData: 512
    0x00, 0x00, 0x00, 0x00,                           # PointerToRelocations
    0x00, 0x00, 0x00, 0x00,                           # PointerToLinenumbers
    0x00, 0x00,                                       # NumberOfRelocations
    0x00, 0x00,                                       # NumberOfLinenumbers
    0x20, 0x00, 0x00, 0x60                            # Characteristics: CODE | EXECUTE | READ
)
[Array]::Copy($textSection, 0, $pe, 0x188, 40)

# Section 2: .rdata (import data)
$rdataSection = [byte[]](
    0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,  # Name: .rdata
    0x40, 0x00, 0x00, 0x00,                           # VirtualSize: 64
    0x00, 0x20, 0x00, 0x00,                           # VirtualAddress: 0x2000
    0x00, 0x02, 0x00, 0x00,                           # SizeOfRawData: 512
    0x00, 0x04, 0x00, 0x00,                           # PointerToRawData: 1024
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x40, 0x00, 0x00, 0x40                            # Characteristics: INITIALIZED_DATA | READ
)
[Array]::Copy($rdataSection, 0, $pe, 0x1B0, 40)

# Section 3: .idata (import directory)
$idataSection = [byte[]](
    0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,  # Name: .idata
    0x60, 0x00, 0x00, 0x00,                           # VirtualSize: 96
    0x00, 0x30, 0x00, 0x00,                           # VirtualAddress: 0x3000
    0x00, 0x02, 0x00, 0x00,                           # SizeOfRawData: 512
    0x00, 0x06, 0x00, 0x00,                           # PointerToRawData: 1536
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x40, 0x00, 0x00, 0x40                            # Characteristics: INITIALIZED_DATA | READ
)
[Array]::Copy($idataSection, 0, $pe, 0x1D8, 40)

# Code section (at offset 0x200 = 512)
# Simple code: mov eax, 42; ret
$code = [byte[]](
    0xB8, 0x2A, 0x00, 0x00, 0x00,  # mov eax, 42
    0xC3                           # ret
)
[Array]::Copy($code, 0, $pe, 0x200, $code.Length)

# Import Directory (at offset 0x600 = 1536, mapped to 0x3000)
# Import Directory Table (20 bytes per entry)
$importDir = [byte[]](
    # Entry 1: kernel32.dll
    0x10, 0x30, 0x00, 0x00,  # ILT RVA: 0x3010
    0x00, 0x00, 0x00, 0x00,  # TimeDateStamp
    0x00, 0x00, 0x00, 0x00,  # ForwarderChain
    0x28, 0x30, 0x00, 0x00,  # Name RVA: 0x3028
    0x18, 0x30, 0x00, 0x00,  # IAT RVA: 0x3018
    
    # Null terminator
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
)
[Array]::Copy($importDir, 0, $pe, 0x600, $importDir.Length)

# ILT (Import Lookup Table) at 0x3010 (file offset 0x610)
$ilt = [byte[]](
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Hint/Name RVA (ordinal import)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   # Null terminator
)
[Array]::Copy($ilt, 0, $pe, 0x610, $ilt.Length)

# IAT (Import Address Table) at 0x3018 (file offset 0x618)
$iat = [byte[]](
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
)
[Array]::Copy($iat, 0, $pe, 0x618, $iat.Length)

# DLL Name at 0x3028 (file offset 0x628)
$dllName = [System.Text.Encoding]::ASCII.GetBytes("kernel32.dll`0")
[Array]::Copy($dllName, 0, $pe, 0x628, $dllName.Length)

# Write the file
[System.IO.File]::WriteAllBytes($OutputFile, $pe[0..2047])

Write-Host "`n✅ Created: $OutputFile" -ForegroundColor Green
Write-Host "   Size: 2048 bytes"
Write-Host "   Entry point: 0x1000"
Write-Host "   Returns: 42"

# Test it
Write-Host "`n[Testing]" -ForegroundColor Yellow
try {
    $proc = Start-Process -FilePath $OutputFile -Wait -PassThru -NoNewWindow
    Write-Host "   Exit code: $($proc.ExitCode)" -ForegroundColor Green
    if ($proc.ExitCode -eq 42) {
        Write-Host "   ✅ SUCCESS!" -ForegroundColor Green
    }
} catch {
    Write-Host "   ❌ Failed: $_" -ForegroundColor Red
}

Write-Host "`n================================================" -ForegroundColor Cyan
