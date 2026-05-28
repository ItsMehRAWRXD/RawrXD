# ==================================================================================
# SOVEREIGN ENGINE INTEGRATION LAYER - PRODUCTION SIGNATURE GENERATION
# File: build_sovereign.ps1
# ==================================================================================
$ErrorActionPreference = "Stop"

$ML = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$OBJ = "d:\rawrxd\obj"
$BIN = "D:\"
$SRC = "d:\rawrxd\src"
$ASM = "d:\rawrxd\src\asm"

if (!(Test-Path $OBJ)) { New-Item -ItemType Directory -Path $OBJ }

# --- Define Full Capabilities Payload Target ---
[uint64]$FEATURE_ALL_ENABLED = 0x0000001F
$PayloadPath = "$ASM\Sovereign_License_Payload.inc"

# --- In-Memory Inline Assembly Injector for Exact Symmetrical CPUID Mapping ---
$CpuIdDefinition = @"
using System;
using System.Runtime.InteropServices;

public class SovereignHardwareProvider {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    private delegate ulong ExecuteCpuIdDelegate();

    public static ulong ComputeAssemblyHWID() {
        // Raw machine instructions mimicking Sovereign_Get_Hardware_ID perfectly
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

        IntPtr memPage = VirtualAlloc(IntPtr.Zero, (uint)nativeCode.Length, 0x1000, 0x40); // MEM_COMMIT | PAGE_EXECUTE_READWRITE
        Marshal.Copy(nativeCode, 0, memPage, nativeCode.Length);
        var nativeMethod = (ExecuteCpuIdDelegate)Marshal.GetDelegateForFunctionPointer(memPage, typeof(ExecuteCpuIdDelegate));
        return nativeMethod();
    }
}
"@

# Compile the execution block natively inside the build task context
if (-not ([System.Management.Automation.PSTypeName]'SovereignHardwareProvider').Type) {
    Add-Type -TypeDefinition $CpuIdDefinition
}

Write-Host "[*] Interrogating hardware execution units via runtime shell reflection..." -ForegroundColor Cyan
[uint64]$HardwareID = [SovereignHardwareProvider]::ComputeAssemblyHWID()
Write-Host "[+] Absolute Hardware Fingerprint Generated: 0x$($HardwareID.ToString('X16'))" -ForegroundColor Green

# --- Match Sovereign Cryptographic Mixing Pipeline Calculations ---
[uint64]$SOVEREIGN_SECRET = [uint64]0x41534D5F454C4954
$SOVEREIGN_SALT_HEX = "9E3779B97F4A7C15"
[uint64]$SOVEREIGN_SALT   = [System.Convert]::ToUInt64($SOVEREIGN_SALT_HEX, 16)

function Rotate-Left ([uint64]$Value, [int]$Count) {
    return (($Value -shl $Count) -bor ($Value -shr (64 - $Count)))
}
function Rotate-Right ([uint64]$Value, [int]$Count) {
    return (($Value -shr $Count) -bor ($Value -shl (64 - $Count)))
}

# Execute cryptographic transformation pass
[uint64]$Mix = $HardwareID -bxor $SOVEREIGN_SECRET
$Mix = Rotate-Left -Value $Mix -Count 13
$Mix = $Mix + $FEATURE_ALL_ENABLED
$Mix = Rotate-Right -Value $Mix -Count 7
$Mix = $Mix -bxor $SOVEREIGN_SALT
$Mix = Rotate-Left -Value $Mix -Count 19
[uint64]$CalculatedSignature = $Mix + $HardwareID

Write-Host "[+] Synthesized Symmetrical Token Payload:  0x$($CalculatedSignature.ToString('X16'))" -ForegroundColor Green

# --- Commit Asset Layout Directly to File System Workspace ---
$PayloadData = @"
; ==================================================================================
; AUTOMATICALLY GENERATED SECURITY SIGNATURE PAYLOAD - DO NOT MODIFY
; Symmetrically Bound to System CPU Architecture Attributes during Build Pass
; ==================================================================================
.DATA
ALIGN 16
STATIC_LICENSE_PAYLOAD_DATA:
    STATIC_HWID      QWORD  $($HardwareID)
    STATIC_FEATURES  QWORD  $($FEATURE_ALL_ENABLED)
    STATIC_SIGNATURE QWORD  $($CalculatedSignature)
    STATIC_EXPIRY    QWORD  0
    STATIC_RESERVED  QWORD  0, 0, 0, 0
"@

Set-Content -Path $PayloadPath -Value $PayloadData -Encoding Ascii
Write-Host "[+] Symmetrical include payload injected to build source: $PayloadPath" -ForegroundColor Green

# --- Toolchain Compilation ---
$as_flags = @("/c", "/nologo", "/Zi", "/I$SRC", "/I$ASM")

Write-Host "[Sovereign] Assembling Core Components..."
& $ML @as_flags /Fo $OBJ\Sovereign_Main.obj $ASM\Sovereign_Main.asm
& $ML @as_flags /Fo $OBJ\Sovereign_PEB_Loader.obj $ASM\Sovereign_PEB_Loader.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Hooks.obj $ASM\Sovereign_Hooks.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Syscalls.obj $ASM\Sovereign_Syscall_Core.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Reverse.obj $ASM\Sovereign_Reverse_Engineering.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Graph.obj $ASM\Sovereign_Execution_Graph_Logic.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Stubs.obj $SRC\Sovereign_Elite_Stubs.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Globals.obj $ASM\Sovereign_Globals.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Dump.obj $ASM\Sovereign_Dump.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Dis.obj $ASM\Sovereign_Dis.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Plugins.obj $ASM\Sovereign_Plugin_Loader.asm
& $ML @as_flags /Fo $OBJ\Sovereign_UI.obj $SRC\Sovereign_UI_Console.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Heap.obj $SRC\Sovereign_Heap.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Scanner.obj $SRC\Sovereign_SIMD_Scanner.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Watchdog.obj $ASM\Sovereign_Watchdog_Lean.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Omni_Engine.obj $ASM\Sovereign_Omni_Engine.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Security.obj $ASM\Sovereign_Security.asm
& $ML @as_flags /Fo $OBJ\Sovereign_KeyGen_Utility.obj $ASM\Sovereign_KeyGen_Utility.asm
& $ML @as_flags /Fo $OBJ\Sovereign_GEMM_Q4_F32.obj $ASM\Sovereign_GEMM_Q4_F32.asm
& $ML @as_flags /Fo $OBJ\Sovereign_Console.obj $SRC\Sovereign_Console.asm
    & $ML @as_flags /Fo $OBJ\Sovereign_Hardening_Core.obj $ASM\Sovereign_Hardening_Core.asm

Write-Host "[Sovereign] Linking Overfeatured Elite Monolith..."
$objs = @(
    "$OBJ\Sovereign_Main.obj",
    "$OBJ\Sovereign_PEB_Loader.obj",
    "$OBJ\Sovereign_Hooks.obj",
    "$OBJ\Sovereign_Syscalls.obj",
    "$OBJ\Sovereign_Reverse.obj",
    "$OBJ\Sovereign_Graph.obj",
    "$OBJ\Sovereign_Stubs.obj",
    "$OBJ\Sovereign_Globals.obj",
    "$OBJ\Sovereign_Dump.obj",
    "$OBJ\Sovereign_Dis.obj",
    "$OBJ\Sovereign_Plugins.obj",
    "$OBJ\Sovereign_UI.obj",
    "$OBJ\Sovereign_Heap.obj",
    "$OBJ\Sovereign_Scanner.obj",
    "$OBJ\Sovereign_Watchdog.obj",
    "$OBJ\Sovereign_Omni_Engine.obj",
    "$OBJ\Sovereign_Security.obj",
    "$OBJ\Sovereign_KeyGen_Utility.obj",
    "$OBJ\Sovereign_GEMM_Q4_F32.obj",
    "$OBJ\Sovereign_Console.obj",
    "$OBJ\Sovereign_Hardening_Core.obj"
)

& $LINK /SUBSYSTEM:CONSOLE /ENTRY:Sovereign_Engine_Main /NODEFAULTLIB /LARGEADDRESSAWARE:NO /DEBUG /OUT:${BIN}Sovereign_Elite.exe $objs

