# ==================================================================================
# SOVEREIGN INTEGRATION SYSTEM - AUTOMATED BUILD-GATE PROVISIONER
# File: Deploy-SovereignAssets.ps1
# Description: Automates generation of production tokens and testing fallbacks.
# ==================================================================================
$ErrorActionPreference = "Stop"

# --- Architectural Constants Matching Assembly Substrate ---
[uint64]$SOVEREIGN_SECRET = 0x41534D5F454C4954   # 'ASM_ELIT'
[uint64]$SOVEREIGN_SALT   = 0x9E3779B97F4A7C15   # Golden Ratio Expander
[uint64]$FEATURE_MASK     = 0x0000001F           # Full Tier Mask (Pro, Ent, 800B, Swarm)

# --- Define Target Paths ---
$WorkspaceDir      = "d:\rawrxd\src\asm"
$TargetIncludePath = Join-Path $WorkspaceDir "Sovereign_License_Payload.inc"

# --- Bitwise Rotation Helper Functions (64-Bit Clean) ---
function Rotate-Left ([uint64]$Value, [int]$Count) {
    return (([Value] -shl $Count) -bor ([Value] -shr (64 - $Count)))
}

function Rotate-Right ([uint64]$Value, [int]$Count) {
    return (([Value] -shr $Count) -bor ([Value] -shl (64 - $Count)))
}

# --- Step 1: Resolve Local Hardware Fingerprint ---
Write-Host "[*] Interrogating hardware layers for CPUID simulation..." -ForegroundColor Cyan
$Cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
[uint32]$Arch  = [uint32]$Cpu.Architecture
[uint32]$Type  = [uint32]$Cpu.ProcessorType
[uint32]$Rev   = [uint32]$Cpu.Revision

[uint64]$HardwareID = ([uint64]$Arch -shl 48) -bxor ([uint64]$Type -shl 32) -bxor [uint64]$Rev
if ($HardwareID -eq 0) {
    $HardwareID = 0x85A3C1B2D4E5F607 # Hardcoded fallback logic match
}

Write-Host "[+] Target HWID Formulated: 0x$([String]::Format('{0:X16}', $HardwareID))" -ForegroundColor Green

# --- Step 2: Compute Symmetrical Cryptographic Signature ---
Write-Host "[*] Simulating Sovereign mixing pipeline..." -ForegroundColor Cyan
[uint64]$MixReg = $HardwareID -bxor $SOVEREIGN_SECRET
$MixReg = Rotate-Left -Value $MixReg -Count 13
$MixReg = $MixReg + $FEATURE_MASK
$MixReg = Rotate-Right -Value $MixReg -Count 7
$MixReg = $MixReg -bxor $SOVEREIGN_SALT
$MixReg = Rotate-Left -Value $MixReg -Count 19
[uint64]$ValidSignature = $MixReg + $HardwareID

# --- Step 3: Payload Generation Modes ---
# Change to $true to intentionally force the assembly's self-healing fallback pathway
$GenerateTestingDummy = $false 

[uint64]$FinalSignature = $ValidSignature
if ($GenerateTestingDummy) {
    Write-Warning "[!] Warning: Generating dummy payload with zero-signature for fallback testing."
    $FinalSignature = 0x0000000000000000
}

# --- Step 4: Emit the Compiled Include Content ---
$PayloadData = @"
; ==================================================================================
; AUTOMATICALLY GENERATED SECURITY SIGNATURE PAYLOAD - DO NOT MODIFY
; Generated Via Deploy-SovereignAssets.ps1
; Target Architecture: x64 MASM (64-Byte Cache Line Isolated)
; ==================================================================================
ALIGN 64
STATIC_LICENSE_PAYLOAD_DATA:
    STATIC_HWID      QWORD 0x$([String]::Format('{0:X16}', $HardwareID))
    STATIC_FEATURES  QWORD 0x$([String]::Format('{0:X16}', $FEATURE_MASK))
    STATIC_SIGNATURE QWORD 0x$([String]::Format('{0:X16}', $FinalSignature))
    STATIC_EXPIRY    QWORD 0x0000000000000000
    STATIC_RESERVED  QWORD 4 DUP(0) ; Explicit padding matrix
"@

# Ensure structural directories exist safely before emission
if (!(Test-Path $WorkspaceDir)) {
    New-Item -ItemType Directory -Path $WorkspaceDir | Out-Null
}

Set-Content -Path $TargetIncludePath -Value $PayloadData -Encoding Ascii
Write-Host "[+] Structural asset successfully written to workspace: $TargetIncludePath" -ForegroundColor Green
