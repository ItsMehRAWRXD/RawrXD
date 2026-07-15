/*++

Module Name:
    SovereignK.h

Abstract:
    Header for Sovereign Kernel Driver - Direct GPU VRAM Access
    Target: AMD RX 7800 XT (Navi 32, Device ID 0x747E)
    
    Provides:
    - Physical BAR0 mapping via MmMapIoSpace
    - Host memory pinning for DMA
    - Interrupt handling for command completion
    - Write-Combining cache policy for VRAM

Environment:
    Kernel mode only. IRQL <= DISPATCH_LEVEL for most operations.

--*/

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

// ============================================================================
// Constants
// ============================================================================

#define SOVEREIGNK_DEVICE_NAME      L"\\Device\\SovereignK"
#define SOVEREIGNK_SYMLINK_NAME     L"\\DosDevices\\SovereignK"
#define SOVEREIGNK_POOL_TAG         'KvRS'  // "SRVK" reversed

// AMD GPU PCI IDs
#define AMD_VENDOR_ID               0x1002
#define RX7800XT_DEVICE_ID          0x747E
#define RX7900XTX_DEVICE_ID         0x744C

// BAR alignment requirements
#define BAR0_ALIGNMENT              256     // RDNA3 cache line
#define HOST_DMA_ALIGNMENT          64      // PCIe requirement

// IOCTL codes
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

// Status codes
#define SOVEREIGNK_SUCCESS          STATUS_SUCCESS
#define SOVEREIGNK_ERR_NO_DEVICE    STATUS_DEVICE_DOES_NOT_EXIST
#define SOVEREIGNK_ERR_INVALID_ADDR STATUS_INVALID_ADDRESS
#define SOVEREIGNK_ERR_NO_MEMORY    STATUS_NO_MEMORY
#define SOVEREIGNK_ERR_ALIGNMENT      STATUS_INVALID_PARAMETER

// ============================================================================
// Structures (packed for IOCTL compatibility)
// ============================================================================
#pragma pack(push, 8)

typedef struct _SOVEREIGNK_BAR_REQUEST {
    PHYSICAL_ADDRESS    PhysicalAddress;    // Physical BAR address from PCI config
    SIZE_T              Size;                // BAR size (typically 256MB)
    MEMORY_CACHING_TYPE CacheType;         // MmNonCached or MmWriteCombined
} SOVEREIGNK_BAR_REQUEST, *PSOVEREIGNK_BAR_REQUEST;

typedef struct _SOVEREIGNK_BAR_RESPONSE {
    PVOID               VirtualAddress;     // Kernel-mode virtual address
    PHYSICAL_ADDRESS    PhysicalAddress;    // Confirmed physical address
    SIZE_T              Size;                // Actual mapped size
    ULONG               CacheType;          // Applied caching policy
} SOVEREIGNK_BAR_RESPONSE, *PSOVEREIGNK_BAR_RESPONSE;

typedef struct _SOVEREIGNK_LOCK_REQUEST {
    PVOID               UserVirtualAddress; // User-mode buffer
    SIZE_T              Size;                // Size to pin
    BOOLEAN             WriteAccess;        // TRUE for R/W, FALSE for RO
} SOVEREIGNK_LOCK_REQUEST, *PSOVEREIGNK_LOCK_REQUEST;

typedef struct _SOVEREIGNK_LOCK_RESPONSE {
    PHYSICAL_ADDRESS    PhysicalAddress;    // Physical address for DMA
    PVOID               SystemVirtualAddress; // System VA (for kernel use)
    HANDLE              Handle;              // Lock handle for unlock
} SOVEREIGNK_LOCK_RESPONSE, *PSOVEREIGNK_LOCK_RESPONSE;

typedef struct _SOVEREIGNK_DMA_REQUEST {
    PHYSICAL_ADDRESS    HostPhysicalAddress; // Source (locked host memory)
    PHYSICAL_ADDRESS    GpuPhysicalAddress; // Destination (VRAM BAR offset)
    SIZE_T              Size;                // Transfer size
    BOOLEAN             Async;               // TRUE = non-blocking
    ULONG               Flags;               // Transfer flags
} SOVEREIGNK_DMA_REQUEST, *PSOVEREIGNK_DMA_REQUEST;

typedef struct _SOVEREIGNK_DMA_RESPONSE {
    ULONGLONG           FenceId;             // Completion fence
    ULONGLONG           CyclesElapsed;       // RDTSC delta
    NTSTATUS            Status;              // Transfer status
} SOVEREIGNK_DMA_RESPONSE, *PSOVEREIGNK_DMA_RESPONSE;

typedef struct _SOVEREIGNK_STATS {
    ULONGLONG           TotalTransfers;
    ULONGLONG           TotalBytesTransferred;
    ULONGLONG           TotalCycles;
    ULONGLONG           IsrCount;
    ULONGLONG           BarMapsActive;
    ULONGLONG           HostLocksActive;
} SOVEREIGNK_STATS, *PSOVEREIGNK_STATS;

#pragma pack(pop)

// ============================================================================
// Device Extension
// ============================================================================

typedef struct _SOVEREIGNK_DEVICE_EXTENSION {
    // BAR0 state
    PVOID               Bar0VirtualAddress;
    PHYSICAL_ADDRESS    Bar0PhysicalAddress;
    SIZE_T              Bar0Size;
    BOOLEAN             Bar0Mapped;
    
    // Host memory locks
    LIST_ENTRY          HostLockList;
    KSPIN_LOCK          HostLockSpinLock;
    
    // Statistics
    SOVEREIGNK_STATS    Stats;
    KSPIN_LOCK          StatsLock;
    
    // Interrupt handling
    PKINTERRUPT         InterruptObject;
    BOOLEAN             InterruptConnected;
    
    // Device info
    PDEVICE_OBJECT      DeviceObject;
    PDEVICE_OBJECT      LowerDeviceObject;
} SOVEREIGNK_DEVICE_EXTENSION, *PSOVEREIGNK_DEVICE_EXTENSION;

// ============================================================================
// Function Prototypes
// ============================================================================

// Driver entry/exit
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SovereignKDriverUnload;

// Device handling
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
NTSTATUS
SovereignKCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
NTSTATUS
SovereignKDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

// BAR mapping
NTSTATUS
SovereignK_MapBAR(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_BAR_REQUEST Request,
    _Out_ PSOVEREIGNK_BAR_RESPONSE Response
    );

VOID
SovereignK_UnmapBAR(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt
    );

// Host memory locking
NTSTATUS
SovereignK_LockHostMemory(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_LOCK_REQUEST Request,
    _Out_ PSOVEREIGNK_LOCK_RESPONSE Response
    );

NTSTATUS
SovereignK_UnlockHostMemory(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ HANDLE LockHandle
    );

// DMA operations
NTSTATUS
SovereignK_DMATransfer(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_DMA_REQUEST Request,
    _Out_ PSOVEREIGNK_DMA_RESPONSE Response
    );

// Interrupt Service Routine
_IRQL_requires_(HIGH_LEVEL)
_IRQL_requires_same_
BOOLEAN
SovereignK_ISR(
    _In_ PKINTERRUPT InterruptObject,
    _Inout_opt_ PVOID ServiceContext
    );

// Statistics
VOID
SovereignK_UpdateStats(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ SIZE_T BytesTransferred,
    _In_ ULONGLONG Cycles
    );

// Utility
PVOID
SovereignK_AllocateMemory(
    _In_ SIZE_T Size
    );

VOID
SovereignK_FreeMemory(
    _In_ PVOID Memory
    );

// Logging
#if DBG
#define SovereignK_DbgPrint(...) KdPrint(("[SovereignK] " __VA_ARGS__))
#else
#define SovereignK_DbgPrint(...)
#endif
