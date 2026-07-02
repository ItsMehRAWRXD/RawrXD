#pragma once
#include <windows.h>
#include <functional>
#include <atomic>

namespace RawrXD {
namespace Security {

// AV-safe function pointer types
using WriteProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using VirtualProtectExFn = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

class AVSafeAPI {
public:
    static AVSafeAPI& Instance();
    
    bool Initialize();
    bool IsInitialized() const { return m_initialized; }
    
    // AV-safe wrappers — resolved at runtime, no direct imports
    BOOL WriteProcessMemorySafe(HANDLE hProcess, LPVOID lpBaseAddress,
                                 LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    BOOL VirtualProtectExSafe(HANDLE hProcess, LPVOID lpAddress,
                                SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    NTSTATUS NtAllocateVirtualMemorySafe(HANDLE ProcessHandle, PVOID* BaseAddress,
                                           ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                           ULONG AllocationType, ULONG Protect);
    
    // Self-attestation
    bool IsRunningInSandbox() const;
    bool IsAVHooked() const;
    bool IsDebuggerAttached() const;
    
    // Feature gating
    bool CanUseREFeatures() const;
    void DisableREFeatures();
    
private:
    AVSafeAPI() = default;
    ~AVSafeAPI() = default;
    
    bool ResolveAPIs();
    
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_re_enabled{true};
    
    WriteProcessMemoryFn m_writeProcessMemory = nullptr;
    VirtualProtectExFn m_virtualProtectEx = nullptr;
    NtAllocateVirtualMemoryFn m_ntAllocateVirtualMemory = nullptr;
};

} // namespace Security
} // namespace RawrXD
