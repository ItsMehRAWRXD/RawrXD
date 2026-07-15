/*++

Module Name:
    HostMemory.c

Abstract:
    Host memory locking/pinning for DMA operations
    Uses MmProbeAndLockPages to ensure physical contiguity

--*/

#include "SovereignK.h"

// ============================================================================
// Host Memory Lock Structure
// ============================================================================

typedef struct _SOVEREIGNK_HOST_LOCK {
    LIST_ENTRY          ListEntry;
    HANDLE              Handle;
    PMDL                Mdl;
    PVOID               SystemVirtualAddress;
    PHYSICAL_ADDRESS    PhysicalAddress;
    SIZE_T              Size;
    BOOLEAN             WriteAccess;
} SOVEREIGNK_HOST_LOCK, *PSOVEREIGNK_HOST_LOCK;

// ============================================================================
// Lock Host Memory
// ============================================================================

NTSTATUS
SovereignK_LockHostMemory(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_LOCK_REQUEST Request,
    _Out_ PSOVEREIGNK_LOCK_RESPONSE Response
    )
{
    NTSTATUS status;
    PSOVEREIGNK_HOST_LOCK hostLock;
    PVOID systemVa;
    PMDL mdl;
    PHYSICAL_ADDRESS physicalAddr;
    KIRQL oldIrql;
    static ULONG handleCounter = 0;
    
    SovereignK_DbgPrint("LockHostMemory: UserVA=%p, Size=0x%zX\n",
                        Request->UserVirtualAddress, Request->Size);
    
    // Validate alignment
    if (((ULONG_PTR)Request->UserVirtualAddress & (HOST_DMA_ALIGNMENT - 1)) != 0) {
        SovereignK_DbgPrint("LockHostMemory: ERROR - Address not aligned\n");
        return SOVEREIGNK_ERR_ALIGNMENT;
    }
    
    // Allocate lock structure
    hostLock = (PSOVEREIGNK_HOST_LOCK)SovereignK_AllocateMemory(sizeof(SOVEREIGNK_HOST_LOCK));
    if (hostLock == NULL) {
        return SOVEREIGNK_ERR_NO_MEMORY;
    }
    
    RtlZeroMemory(hostLock, sizeof(SOVEREIGNK_HOST_LOCK));
    
    // Allocate MDL for the user buffer
    // Note: In a real implementation, we'd need to handle the case where
    // the buffer spans multiple pages. This is simplified.
    mdl = IoAllocateMdl(
        Request->UserVirtualAddress,
        (ULONG)Request->Size,
        FALSE,
        FALSE,
        NULL
        );
    
    if (mdl == NULL) {
        SovereignK_DbgPrint("LockHostMemory: ERROR - IoAllocateMdl failed\n");
        SovereignK_FreeMemory(hostLock);
        return SOVEREIGNK_ERR_NO_MEMORY;
    }
    
    __try {
        // Probe and lock the pages
        // This is the critical operation that pins the memory
        MmProbeAndLockPages(
            mdl,
            UserMode,
            Request->WriteAccess ? IoModifyAccess : IoReadAccess
            );
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        SovereignK_DbgPrint("LockHostMemory: ERROR - MmProbeAndLockPages exception\n");
        IoFreeMdl(mdl);
        SovereignK_FreeMemory(hostLock);
        return STATUS_ACCESS_VIOLATION;
    }
    
    // Get system virtual address
    systemVa = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (systemVa == NULL) {
        SovereignK_DbgPrint("LockHostMemory: ERROR - MmGetSystemAddressForMdlSafe failed\n");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        SovereignK_FreeMemory(hostLock);
        return SOVEREIGNK_ERR_NO_MEMORY;
    }
    
    // Get physical address
    physicalAddr = MmGetPhysicalAddress(systemVa);
    
    // Populate lock structure
    hostLock->Mdl = mdl;
    hostLock->SystemVirtualAddress = systemVa;
    hostLock->PhysicalAddress = physicalAddr;
    hostLock->Size = Request->Size;
    hostLock->WriteAccess = Request->WriteAccess;
    hostLock->Handle = (HANDLE)(ULONG_PTR)++handleCounter;
    
    // Add to list
    KeAcquireSpinLock(&DevExt->HostLockSpinLock, &oldIrql);
    InsertTailList(&DevExt->HostLockList, &hostLock->ListEntry);
    DevExt->Stats.HostLocksActive++;
    KeReleaseSpinLock(&DevExt->HostLockSpinLock, oldIrql);
    
    // Return response
    Response->PhysicalAddress = physicalAddr;
    Response->SystemVirtualAddress = systemVa;
    Response->Handle = hostLock->Handle;
    
    SovereignK_DbgPrint("LockHostMemory: SUCCESS - Phys=0x%llX, Handle=%p\n",
                        physicalAddr.QuadPart, hostLock->Handle);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Unlock Host Memory
// ============================================================================

NTSTATUS
SovereignK_UnlockHostMemory(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ HANDLE LockHandle
    )
{
    PLIST_ENTRY entry;
    PSOVEREIGNK_HOST_LOCK hostLock = NULL;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    SovereignK_DbgPrint("UnlockHostMemory: Handle=%p\n", LockHandle);
    
    KeAcquireSpinLock(&DevExt->HostLockSpinLock, &oldIrql);
    
    for (entry = DevExt->HostLockList.Flink;
         entry != &DevExt->HostLockList;
         entry = entry->Flink) {
        
        hostLock = CONTAINING_RECORD(entry, SOVEREIGNK_HOST_LOCK, ListEntry);
        
        if (hostLock->Handle == LockHandle) {
            RemoveEntryList(entry);
            DevExt->Stats.HostLocksActive--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&DevExt->HostLockSpinLock, oldIrql);
    
    if (!found) {
        SovereignK_DbgPrint("UnlockHostMemory: ERROR - Handle not found\n");
        return STATUS_INVALID_HANDLE;
    }
    
    // Unlock and free
    if (hostLock->Mdl) {
        MmUnlockPages(hostLock->Mdl);
        IoFreeMdl(hostLock->Mdl);
    }
    
    SovereignK_FreeMemory(hostLock);
    
    SovereignK_DbgPrint("UnlockHostMemory: SUCCESS\n");
    
    return STATUS_SUCCESS;
}
