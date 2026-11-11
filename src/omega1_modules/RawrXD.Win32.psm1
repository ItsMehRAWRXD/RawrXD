#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 Win32 Module
# Native Windows API integration and P/Invoke wrappers

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"

# Native API definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32Native {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
    
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("kernel32.dll")]
    public static extern bool GetProcessMemoryInfo(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, uint cb);
    
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint INFINITE = 0xFFFFFFFF;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_MEMORY_COUNTERS {
        public uint cb;
        public uint PageFaultCount;
        public UIntPtr PeakWorkingSetSize;
        public UIntPtr WorkingSetSize;
        public UIntPtr QuotaPeakPagedPoolUsage;
        public UIntPtr QuotaPagedPoolUsage;
        public UIntPtr QuotaPeakNonPagedPoolUsage;
        public UIntPtr QuotaNonPagedPoolUsage;
        public UIntPtr PagefileUsage;
        public UIntPtr PeakPagefileUsage;
    }
}
"@ -ErrorAction SilentlyContinue

function Invoke-Win32 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    try {
        # Get process memory info via P/Invoke
        $counters = New-Object Win32Native+PROCESS_MEMORY_COUNTERS
        $counters.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($counters)
        $process = [Win32Native]::GetCurrentProcess()
        $result = [Win32Native]::GetProcessMemoryInfo($process, [ref]$counters, $counters.cb)
        
        $memInfo = if ($result) {
            @{
                WorkingSetMB = [Math]::Round($counters.WorkingSetSize.ToUInt64() / 1MB, 2)
                PeakWorkingSetMB = [Math]::Round($counters.PeakWorkingSetSize.ToUInt64() / 1MB, 2)
                PagefileUsageMB = [Math]::Round($counters.PagefileUsage.ToUInt64() / 1MB, 2)
            }
        } else {
            @{ Error = 'GetProcessMemoryInfo failed' }
        }
        
        $result = @{
            Status = 'Active'
            Module = 'RawrXD.Win32'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            NativeMemoryInfo = $memInfo
            PInvokeAvailable = $true
        }
        
        Write-Verbose "[Win32] Native API call completed"
        return $result
    }
    catch {
        Write-Error "[Win32] Error: $_"
        throw
    }
}

function Test-Win32Health {
    [CmdletBinding()]
    param()
    
    $pinvokeOk = $false
    try {
        $test = [Win32Native]::GetCurrentProcess()
        $pinvokeOk = $test -ne [IntPtr]::Zero
    } catch {}
    
    return @{
        Module = 'RawrXD.Win32'
        Healthy = $pinvokeOk
        Status = if ($pinvokeOk) { 'Operational' } else { 'PInvokeFailed' }
        Timestamp = Get-Date
        PInvokeStatus = if ($pinvokeOk) { 'Available' } else { 'Unavailable' }
    }
}

function Invoke-ReflectiveExecution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Shellcode
    )
    
    Write-Verbose "[Win32] Allocating executable memory"
    
    $addr = [Win32Native]::VirtualAlloc(
        [IntPtr]::Zero,
        [uint32]$Shellcode.Length,
        [Win32Native]::MEM_COMMIT -bor [Win32Native]::MEM_RESERVE,
        [Win32Native]::PAGE_READWRITE
    )
    
    if ($addr -eq [IntPtr]::Zero) {
        throw "VirtualAlloc failed"
    }
    
    try {
        # Copy shellcode
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $addr, $Shellcode.Length)
        
        # Change protection to execute
        $oldProtect = 0
        $protectResult = [Win32Native]::VirtualProtect(
            $addr,
            [uint32]$Shellcode.Length,
            [Win32Native]::PAGE_EXECUTE_READWRITE,
            [ref]$oldProtect
        )
        
        if (-not $protectResult) {
            throw "VirtualProtect failed"
        }
        
        # Create thread
        $threadId = 0
        $hThread = [Win32Native]::CreateThread(
            [IntPtr]::Zero,
            0,
            $addr,
            [IntPtr]::Zero,
            0,
            [ref]$threadId
        )
        
        if ($hThread -eq [IntPtr]::Zero) {
            throw "CreateThread failed"
        }
        
        # Wait for completion
        [Win32Native]::WaitForSingleObject($hThread, [Win32Native]::INFINITE) | Out-Null
        [Win32Native]::CloseHandle($hThread) | Out-Null
        
        Write-Verbose "[Win32] Reflective execution completed"
    }
    finally {
        # Cleanup
        [Win32Native]::VirtualFree($addr, 0, [Win32Native]::MEM_RELEASE) | Out-Null
    }
}

Export-ModuleMember -Function Invoke-Win32, Test-Win32Health, Invoke-ReflectiveExecution
