#include "av_safe_api.h"
#include <psapi.h>
#include <vector>

namespace RawrXD {
namespace Security {

AVSafeAPI& AVSafeAPI::Instance() {
    static AVSafeAPI instance;
    return instance;
}

bool AVSafeAPI::Initialize() {
    if (m_initialized) return true;
    
    if (!ResolveAPIs()) {
        return false;
    }
    
    // Check sandbox/AV on startup
    if (IsRunningInSandbox()) {
        m_re_enabled = false;
    }
    
    m_initialized = true;
    return true;
}

bool AVSafeAPI::ResolveAPIs() {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    
    if (!kernel32 || !ntdll) return false;
    
    // Resolve via GetProcAddress — no direct imports
    m_writeProcessMemory = reinterpret_cast<WriteProcessMemoryFn>(
        GetProcAddress(kernel32, "WriteProcessMemory"));
    m_virtualProtectEx = reinterpret_cast<VirtualProtectExFn>(
        GetProcAddress(kernel32, "VirtualProtectEx"));
    m_ntAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemoryFn>(
        GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
    
    return m_writeProcessMemory && m_virtualProtectEx && m_ntAllocateVirtualMemory;
}

BOOL AVSafeAPI::WriteProcessMemorySafe(HANDLE hProcess, LPVOID lpBaseAddress,
                                        LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (!m_initialized || !m_re_enabled || !m_writeProcessMemory) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return m_writeProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL AVSafeAPI::VirtualProtectExSafe(HANDLE hProcess, LPVOID lpAddress,
                                      SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    if (!m_initialized || !m_re_enabled || !m_virtualProtectEx) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return m_virtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

NTSTATUS AVSafeAPI::NtAllocateVirtualMemorySafe(HANDLE ProcessHandle, PVOID* BaseAddress,
                                                   ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                                   ULONG AllocationType, ULONG Protect) {
    if (!m_initialized || !m_re_enabled || !m_ntAllocateVirtualMemory) {
        return STATUS_ACCESS_DENIED;
    }
    return m_ntAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize,
                                       AllocationType, Protect);
}

bool AVSafeAPI::IsRunningInSandbox() const {
    // Check for common sandbox DLLs
    const wchar_t* sandboxDlls[] = {
        L"SbieDll.dll",           // Sandboxie
        L"dbghelp.dll",           // Often hooked in sandboxes
        L"api_log.dll",           // Cuckoo Sandbox
        L"dir_watch.dll",         // Cuckoo
        L"pstorec.dll",           // VMware
        L"vmcheck.dll",           // VMware
        L"wpespy.dll",            // WPE Pro
    };
    
    for (const auto* dll : sandboxDlls) {
        if (GetModuleHandleW(dll)) {
            return true;
        }
    }
    
    return false;
}

bool AVSafeAPI::IsAVHooked() const {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    
    auto* alloc = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    if (!alloc) return false;
    
    uint8_t* bytes = reinterpret_cast<uint8_t*>(alloc);
    // Check for hook: JMP (0xE9), JMP SHORT (0xEB), or INT3 (0xCC)
    return bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xCC;
}

bool AVSafeAPI::IsDebuggerAttached() const {
    return IsDebuggerPresent() != FALSE;
}

bool AVSafeAPI::CanUseREFeatures() const {
    return m_initialized && m_re_enabled;
}

void AVSafeAPI::DisableREFeatures() {
    m_re_enabled = false;
}

} // namespace Security
} // namespace RawrXD
