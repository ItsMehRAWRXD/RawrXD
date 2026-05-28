# ==================================================================================
# SOVEREIGN INTEGRATION SYSTEM - AUTOMATED BUILD-GATE PROVISIONER
# File: Deploy-SovereignAssets.ps1
# Description: Automates generation of production tokens and testing fallbacks.
# ==================================================================================
$ErrorActionPreference = "Stop"

# --- Architectural Constants Matching Assembly Substrate ---
[uint64]$SOVEREIGN_SECRET = [uint64]0x41534D5F454C4954   # 'ASM_ELIT'
$SOVEREIGN_SALT_HEX = "9E3779B97F4A7C15"
[uint64]$SOVEREIGN_SALT   = [System.Convert]::ToUInt64($SOVEREIGN_SALT_HEX, 16)
[uint64]$FEATURE_MASK     = 0x0000001F           # Full Tier Mask (Pro, Ent, 800B, Swarm)

# --- Define Target Paths ---
$WorkspaceDir      = "d:\rawrxd\src\asm"
$TargetIncludePath = Join-Path $WorkspaceDir "Sovereign_License_Payload.inc"

# --- Bitwise Rotation Helper Functions (64-Bit Clean) ---
function Rotate-Left ([uint64]$Value, [int]$Count) {
    return (($Value -shl $Count) -bor ($Value -shr (64 - $Count)))
}

function Rotate-Right ([uint64]$Value, [int]$Count) {
    return (($Value -shr $Count) -bor ($Value -shl (64 - $Count)))
}

# --- Step 1: Resolve Local Hardware Fingerprint ---
Write-Host "[*] Interrogating hardware layers for CPUID simulation..." -ForegroundColor Cyan

# Simulating the CPUID Leaf 1 + Leaf 7 logic from assembly
# Leaf 1: EAX=Family/Model, EDX=Features
# Leaf 7: EBX=Advanced Features

# To match exactly, we'll use the .NET CPUID injector pattern if available, 
# but for the deployment script, we'll use a stable CIM-based derivation 
# that matches the fallback logic if needed. 
# Better: Use the same Inline assembly as build_sovereign.ps1 for perfect symmetry.

$CpuIdDefinition = @"
using System;
using System.Runtime.InteropServices;

public class SovereignHardwareProvider {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    private delegate ulong ExecuteCpuIdDelegate();

    public static ulong ComputeAssemblyHWID() {
        byte[] nativeCode = new byte[] {
            0x53,                               // push rbx
            0x56,                               // push rsi
            0x57,                               // push rdi
            0xB8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1
            0x0F, 0xA2,                         // cpuid
            0x48, 0x89, 0xC6,                   // mov rsi, rax
            0x48, 0xC1, 0xE6, 0x20,             // shl rsi, 32
            0x89, 0xD0,                         // mov eax, edx
            0x48, 0x09, 0xC6,                   // or rsi, rax
            0x31, 0xC9,                         // xor ecx, ecx
            0xB8, 0x07, 0x00, 0x00, 0x00,       // mov eax, 7
            0x0F, 0xA2,                         // cpuid
            0x89, 0xD8,                         // mov eax, ebx
            0x48, 0xC1, 0xE0, 0x10,             // shl rax, 16
            0x48, 0x33, 0xC6,                   // xor rax, rsi
            0x5F,                               // pop rdi
            0x5E,                               // pop rsi
            0x5B,                               // pop rbx
            0xC3                                // ret
        };

        IntPtr memPage = VirtualAlloc(IntPtr.Zero, (uint)nativeCode.Length, 0x1000, 0x40);
        Marshal.Copy(nativeCode, 0, memPage, nativeCode.Length);
        var nativeMethod = (ExecuteCpuIdDelegate)Marshal.GetDelegateForFunctionPointer(memPage, typeof(ExecuteCpuIdDelegate));
        return nativeMethod();
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'SovereignHardwareProvider').Type) {
    Add-Type -TypeDefinition $CpuIdDefinition
}

[uint64]$HardwareID = [SovereignHardwareProvider]::ComputeAssemblyHWID()

Write-Host "[+] Target HWID Formulated: 0x$($HardwareID.ToString('X16'))" -ForegroundColor Green

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
    STATIC_HWID      QWORD 0x$($HardwareID.ToString('X16'))
    STATIC_FEATURES  QWORD 0x$($FEATURE_MASK.ToString('X16'))
    STATIC_SIGNATURE QWORD 0x$($FinalSignature.ToString('X16'))
    STATIC_EXPIRY    QWORD 0x0000000000000000
    STATIC_RESERVED  QWORD 4 DUP(0) ; Explicit padding matrix
"@

if (!(Test-Path $WorkspaceDir)) {
    New-Item -ItemType Directory -Path $WorkspaceDir | Out-Null
}

Set-Content -Path $TargetIncludePath -Value $PayloadData -Encoding Ascii
Write-Host "[+] Structural asset successfully written to workspace: $TargetIncludePath" -ForegroundColor Green
