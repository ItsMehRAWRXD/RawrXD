// =============================================================================
// SovereignK Client Implementation
// =============================================================================

#include "SovereignK_Client.h"
#include <cstdio>
#include <cstdarg>
#include <windows.h>

namespace rxdn {

// ============================================================================
// Error Handling
// ============================================================================

void SovereignKClient::SetError(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(lastError_, sizeof(lastError_), fmt, args);
    va_end(args);
}

// ============================================================================
// Open/Close
// ============================================================================

bool SovereignKClient::Open() {
    if (hDevice_ != INVALID_HANDLE_VALUE) {
        return true; // Already open
    }
    
    hDevice_ = CreateFileW(
        L"\\\\.\\SovereignK",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );
    
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        SetError("Failed to open \\.\\SovereignK: %lu", GetLastError());
        return false;
    }
    
    barMapped_ = false;
    return true;
}

void SovereignKClient::Close() {
    if (hDevice_ != INVALID_HANDLE_VALUE) {
        if (barMapped_) {
            UnmapBAR();
        }
        CloseHandle(hDevice_);
        hDevice_ = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// BAR Operations
// ============================================================================

bool SovereignKClient::MapBAR(uint64_t physicalAddress, size_t size, uint32_t cacheType) {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        SetError("Device not open");
        return false;
    }
    
    SOVEREIGNK_BAR_REQUEST req = {};
    req.PhysicalAddress = physicalAddress;
    req.Size = size;
    req.CacheType = cacheType;
    
    SOVEREIGNK_BAR_RESPONSE resp = {};
    DWORD bytesReturned = 0;
    
    BOOL result = DeviceIoControl(
        hDevice_,
        IOCTL_SOVEREIGNK_MAP_BAR,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned,
        nullptr
        );
    
    if (!result) {
        SetError("IOCTL_SOVEREIGNK_MAP_BAR failed: %lu", GetLastError());
        return false;
    }
    
    barMapped_ = true;
    return true;
}

bool SovereignKClient::UnmapBAR() {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice_,
        IOCTL_SOVEREIGNK_UNMAP_BAR,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr
        );
    
    barMapped_ = false;
    return result != FALSE;
}

// ============================================================================
// Host Memory Locking
// ============================================================================

bool SovereignKClient::LockHostMemory(void* userVa, size_t size, bool writeAccess,
                                       uint64_t* outPhysical, HANDLE* outHandle) {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        SetError("Device not open");
        return false;
    }
    
    SOVEREIGNK_LOCK_REQUEST req = {};
    req.UserVirtualAddress = userVa;
    req.Size = size;
    req.WriteAccess = writeAccess;
    
    SOVEREIGNK_LOCK_RESPONSE resp = {};
    DWORD bytesReturned = 0;
    
    BOOL result = DeviceIoControl(
        hDevice_,
        IOCTL_SOVEREIGNK_LOCK_HOST,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned,
        nullptr
        );
    
    if (!result) {
        SetError("IOCTL_SOVEREIGNK_LOCK_HOST failed: %lu", GetLastError());
        return false;
    }
    
    if (outPhysical) *outPhysical = resp.PhysicalAddress;
    if (outHandle) *outHandle = resp.Handle;
    
    return true;
}

bool SovereignKClient::UnlockHostMemory(HANDLE handle) {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // TODO: Implement unlock IOCTL
    SetError("Unlock not yet implemented");
    return false;
}

// ============================================================================
// DMA Transfer
// ============================================================================

bool SovereignKClient::DMATransfer(uint64_t hostPhys, uint64_t gpuPhys, size_t size,
                                    uint64_t* outCycles) {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        SetError("Device not open");
        return false;
    }
    
    SOVEREIGNK_DMA_REQUEST req = {};
    req.HostPhysicalAddress = hostPhys;
    req.GpuPhysicalAddress = gpuPhys;
    req.Size = size;
    req.Async = false;
    req.Flags = 0;
    
    SOVEREIGNK_DMA_RESPONSE resp = {};
    DWORD bytesReturned = 0;
    
    BOOL result = DeviceIoControl(
        hDevice_,
        IOCTL_SOVEREIGNK_DMA_TRANSFER,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned,
        nullptr
        );
    
    if (!result) {
        SetError("IOCTL_SOVEREIGNK_DMA_TRANSFER failed: %lu", GetLastError());
        return false;
    }
    
    if (outCycles) *outCycles = resp.CyclesElapsed;
    
    return true;
}

// ============================================================================
// Statistics
// ============================================================================

bool SovereignKClient::GetStats(SOVEREIGNK_STATS* stats) {
    if (hDevice_ == INVALID_HANDLE_VALUE) {
        SetError("Device not open");
        return false;
    }
    
    if (!stats) {
        SetError("Invalid parameter");
        return false;
    }
    
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice_,
        IOCTL_SOVEREIGNK_GET_STATS,
        nullptr, 0,
        stats, sizeof(SOVEREIGNK_STATS),
        &bytesReturned,
        nullptr
        );
    
    if (!result) {
        SetError("IOCTL_SOVEREIGNK_GET_STATS failed: %lu", GetLastError());
        return false;
    }
    
    return true;
}

} // namespace rxdn
