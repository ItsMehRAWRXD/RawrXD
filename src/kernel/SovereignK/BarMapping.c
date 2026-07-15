/*++

Module Name:
    BarMapping.c

Abstract:
    BAR0 physical-to-virtual mapping implementation
    Uses MmMapIoSpace with Write-Combining cache policy

--*/

#include "SovereignK.h"

// ============================================================================
// BAR Mapping
// ============================================================================

NTSTATUS
SovereignK_MapBAR(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_BAR_REQUEST Request,
    _Out_ PSOVEREIGNK_BAR_RESPONSE Response
    )
{
    PVOID virtualAddress;
    MEMORY_CACHING_TYPE cacheType;
    
    SovereignK_DbgPrint("MapBAR: Physical=0x%llX, Size=0x%zX\n",
                        Request->PhysicalAddress.QuadPart, Request->Size);
    
    // Validate alignment
    if ((Request->PhysicalAddress.QuadPart & (BAR0_ALIGNMENT - 1)) != 0) {
        SovereignK_DbgPrint("MapBAR: ERROR - Physical address not aligned\n");
        return SOVEREIGNK_ERR_ALIGNMENT;
    }
    
    // Unmap existing BAR if already mapped
    if (DevExt->Bar0Mapped) {
        SovereignK_DbgPrint("MapBAR: Unmapping existing BAR\n");
        SovereignK_UnmapBAR(DevExt);
    }
    
    // Determine cache type (Write-Combining is optimal for VRAM)
    cacheType = Request->CacheType;
    if (cacheType != MmNonCached && cacheType != MmWriteCombined) {
        SovereignK_DbgPrint("MapBAR: Using default Write-Combined cache\n");
        cacheType = MmWriteCombined;
    }
    
    // Map physical BAR into kernel virtual address space
    // This is the critical operation that gives us direct access
    virtualAddress = MmMapIoSpace(
        Request->PhysicalAddress,
        Request->Size,
        cacheType
        );
    
    if (virtualAddress == NULL) {
        SovereignK_DbgPrint("MapBAR: ERROR - MmMapIoSpace failed\n");
        return SOVEREIGNK_ERR_NO_MEMORY;
    }
    
    // Store mapping info
    DevExt->Bar0VirtualAddress = virtualAddress;
    DevExt->Bar0PhysicalAddress = Request->PhysicalAddress;
    DevExt->Bar0Size = Request->Size;
    DevExt->Bar0Mapped = TRUE;
    
    // Return response
    Response->VirtualAddress = virtualAddress;
    Response->PhysicalAddress = Request->PhysicalAddress;
    Response->Size = Request->Size;
    Response->CacheType = (ULONG)cacheType;
    
    SovereignK_DbgPrint("MapBAR: SUCCESS - Virtual=%p, Cache=%s\n",
                        virtualAddress,
                        (cacheType == MmWriteCombined) ? "WC" : "UC");
    
    return STATUS_SUCCESS;
}

// ============================================================================
// BAR Unmapping
// ============================================================================

VOID
SovereignK_UnmapBAR(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt
    )
{
    if (DevExt->Bar0Mapped && DevExt->Bar0VirtualAddress != NULL) {
        SovereignK_DbgPrint("UnmapBAR: Unmapping BAR at %p\n", DevExt->Bar0VirtualAddress);
        
        MmUnmapIoSpace(DevExt->Bar0VirtualAddress, DevExt->Bar0Size);
        
        DevExt->Bar0VirtualAddress = NULL;
        DevExt->Bar0PhysicalAddress.QuadPart = 0;
        DevExt->Bar0Size = 0;
        DevExt->Bar0Mapped = FALSE;
        
        SovereignK_DbgPrint("UnmapBAR: Complete\n");
    }
}
