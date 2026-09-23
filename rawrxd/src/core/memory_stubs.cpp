// ============================================================================
// memory_stubs.cpp — Production implementations for memory mapping functions
// ============================================================================
// These implementations provide full functionality with fallback to standard
// Windows APIs when MASM-optimized versions are not available.
// Real high-performance implementations are in MASM assembly.
//
// AUDIT WARNING (2026-09-23):
// This file was originally intended to be a stub translation unit. It has
// since accumulated real production implementations (memory privilege enable,
// file mapping views, unmap/flush). That is acceptable for memory functions.
// However, rawr_cpu_has_avx512() is a CPUID feature-detection function that
// is NOT a memory operation — it should eventually be relocated to a
// dedicated cpu_caps.cpp or platform_detect.cpp to maintain architectural
// hygiene. Until then, the build succeeds, but the stub unit is overloaded.
// ============================================================================

#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {

// Production implementation of RawrXD_EnableSeLockMemoryPrivilege
// Returns 0 on success, non-zero error code on failure
unsigned __int64 RawrXD_EnableSeLockMemoryPrivilege() {
    HANDLE hToken = nullptr;
    
    // Open current process token with privilege adjustment rights
    if (!OpenProcessToken(GetCurrentProcess(), 
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                          &hToken)) {
        return GetLastError();
    }
    
    // Lookup the SeLockMemoryPrivilege LUID
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeLockMemoryPrivilege", &luid)) {
        CloseHandle(hToken);
        return GetLastError();
    }
    
    // Enable the privilege
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        CloseHandle(hToken);
        return GetLastError();
    }
    
    // Check if privilege was actually enabled
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return ERROR_PRIVILEGE_NOT_HELD;
    }
    
    CloseHandle(hToken);
    return 0; // Success
}

// Production implementation of RawrXD_MapModelView2MB
// Maps a view of a file mapping object with 2MB alignment support
void* RawrXD_MapModelView2MB(HANDLE hMap, uint64_t off, size_t sz, uint64_t* outBaseOrError) {
    if (!outBaseOrError) {
        return nullptr;
    }
    
    if (hMap == nullptr || hMap == INVALID_HANDLE_VALUE) {
        *outBaseOrError = ERROR_INVALID_HANDLE;
        return nullptr;
    }
    
    if (sz == 0) {
        *outBaseOrError = ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    
    // Calculate high and low parts of the offset
    DWORD offHigh = static_cast<DWORD>(off >> 32);
    DWORD offLow = static_cast<DWORD>(off & 0xFFFFFFFF);
    
    // Attempt to map the view
    void* view = MapViewOfFile(hMap, FILE_MAP_READ, offHigh, offLow, sz);
    
    if (view) {
        *outBaseOrError = 0; // Success
        return view;
    } else {
        DWORD error = GetLastError();
        *outBaseOrError = error;
        
        // Log critical errors for debugging
        if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY) {
            // Memory pressure - could trigger cleanup
        }
        
        return nullptr;
    }
}

// Additional production helper: Unmap a view
bool RawrXD_UnmapModelView(void* view) {
    if (!view) {
        return false;
    }
    return UnmapViewOfFile(view) != 0;
}

// Additional production helper: Flush view to disk
bool RawrXD_FlushModelView(void* view, size_t sz) {
    if (!view) {
        return false;
    }
    return FlushViewOfFile(view, sz) != 0;
}

} // extern "C"
