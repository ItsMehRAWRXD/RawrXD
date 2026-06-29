// =============================================================================
// SovereignK User-Mode Client — Communicates with SovereignK.sys driver
// =============================================================================
// Opens \\.\SovereignK and sends IOCTLs for BAR mapping and DMA
// =============================================================================

#pragma once

#include <windows.h>
#include <winioctl.h>
#include <cstdint>
#include <cstddef>

// ============================================================================
// IOCTL Codes (must match driver)
// ============================================================================

#define SOVEREIGNK_IOCTL_BASE       0x800

#define IOCTL_SOVEREIGNK_MAP_BAR    CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                             SOVEREIGNK_IOCTL_BASE + 0, \
                                             METHOD_BUFFERED, \
                                             FILE_ANY_ACCESS)

#define IOCTL_SOVEREIGNK_UNMAP_BAR  CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                             SOVEREIGNK_IOCTL_BASE + 1, \
                                             METHOD_BUFFERED, \
                                             FILE_ANY_ACCESS)

#define IOCTL_SOVEREIGNK_LOCK_HOST  CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                             SOVEREIGNK_IOCTL_BASE + 2, \
                                             METHOD_BUFFERED, \
                                             FILE_ANY_ACCESS)

#define IOCTL_SOVEREIGNK_UNLOCK_HOST CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                              SOVEREIGNK_IOCTL_BASE + 3, \
                                              METHOD_BUFFERED, \
                                              FILE_ANY_ACCESS)

#define IOCTL_SOVEREIGNK_DMA_TRANSFER CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                               SOVEREIGNK_IOCTL_BASE + 4, \
                                               METHOD_BUFFERED, \
                                               FILE_ANY_ACCESS)

#define IOCTL_SOVEREIGNK_GET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                             SOVEREIGNK_IOCTL_BASE + 5, \
                                             METHOD_BUFFERED, \
                                             FILE_ANY_ACCESS)

// ============================================================================
// Structures (packed, must match driver)
// ============================================================================
#pragma pack(push, 8)

typedef struct _SOVEREIGNK_BAR_REQUEST {
    uint64_t    PhysicalAddress;
    size_t      Size;
    uint32_t    CacheType;
} SOVEREIGNK_BAR_REQUEST, *PSOVEREIGNK_BAR_REQUEST;

typedef struct _SOVEREIGNK_BAR_RESPONSE {
    void*       VirtualAddress;     // Kernel VA (for reference)
    uint64_t    PhysicalAddress;
    size_t      Size;
    uint32_t    CacheType;
} SOVEREIGNK_BAR_RESPONSE, *PSOVEREIGNK_BAR_RESPONSE;

typedef struct _SOVEREIGNK_LOCK_REQUEST {
    void*       UserVirtualAddress;
    size_t      Size;
    bool        WriteAccess;
} SOVEREIGNK_LOCK_REQUEST, *PSOVEREIGNK_LOCK_REQUEST;

typedef struct _SOVEREIGNK_LOCK_RESPONSE {
    uint64_t    PhysicalAddress;
    void*       SystemVirtualAddress;
    HANDLE      Handle;
} SOVEREIGNK_LOCK_RESPONSE, *PSOVEREIGNK_LOCK_RESPONSE;

typedef struct _SOVEREIGNK_DMA_REQUEST {
    uint64_t    HostPhysicalAddress;
    uint64_t    GpuPhysicalAddress;
    size_t      Size;
    bool        Async;
    uint32_t    Flags;
} SOVEREIGNK_DMA_REQUEST, *PSOVEREIGNK_DMA_REQUEST;

typedef struct _SOVEREIGNK_DMA_RESPONSE {
    uint64_t    FenceId;
    uint64_t    CyclesElapsed;
    int32_t     Status;
} SOVEREIGNK_DMA_RESPONSE, *PSOVEREIGNK_DMA_RESPONSE;

typedef struct _SOVEREIGNK_STATS {
    uint64_t    TotalTransfers;
    uint64_t    TotalBytesTransferred;
    uint64_t    TotalCycles;
    uint64_t    IsrCount;
    uint64_t    BarMapsActive;
    uint64_t    HostLocksActive;
} SOVEREIGNK_STATS, *PSOVEREIGNK_STATS;

#pragma pack(pop)

// ============================================================================
// C++ Client Class
// ============================================================================

namespace rxdn {

class SovereignKClient {
public:
    SovereignKClient() : hDevice_(INVALID_HANDLE_VALUE), barMapped_(false) {
        lastError_[0] = '\0';
    }
    ~SovereignKClient() { Close(); }
    
    // Non-copyable
    SovereignKClient(const SovereignKClient&) = delete;
    SovereignKClient& operator=(const SovereignKClient&) = delete;
    
    // Open/Close
    bool Open();
    void Close();
    bool IsOpen() const { return hDevice_ != INVALID_HANDLE_VALUE; }
    
    // BAR operations
    bool MapBAR(uint64_t physicalAddress, size_t size, uint32_t cacheType);
    bool UnmapBAR();
    bool IsBARMapped() const { return barMapped_; }
    
    // Host memory locking
    bool LockHostMemory(void* userVa, size_t size, bool writeAccess, 
                        uint64_t* outPhysical, HANDLE* outHandle);
    bool UnlockHostMemory(HANDLE handle);
    
    // DMA transfer
    bool DMATransfer(uint64_t hostPhys, uint64_t gpuPhys, size_t size,
                     uint64_t* outCycles);
    
    // Statistics
    bool GetStats(SOVEREIGNK_STATS* stats);
    
    // Error
    const char* GetLastError() const { return lastError_; }
    
private:
    HANDLE hDevice_;
    bool barMapped_;
    char lastError_[512];
    
    void SetError(const char* fmt, ...);
};

} // namespace rxdn
