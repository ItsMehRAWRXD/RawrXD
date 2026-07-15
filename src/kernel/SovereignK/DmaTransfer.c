/*++

Module Name:
    DmaTransfer.c

Abstract:
    DMA transfer implementation using REP MOVSQ
    Measures transfer time with RDTSC

--*/

#include "SovereignK.h"

// ============================================================================
// DMA Transfer
// ============================================================================

NTSTATUS
SovereignK_DMATransfer(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ PSOVEREIGNK_DMA_REQUEST Request,
    _Out_ PSOVEREIGNK_DMA_RESPONSE Response
    )
{
    PVOID hostVa;
    PVOID gpuVa;
    ULONGLONG startCycles, endCycles;
    KIRQL oldIrql;
    
    UNREFERENCED_PARAMETER(DevExt);
    
    SovereignK_DbgPrint("DMATransfer: HostPhys=0x%llX, GpuPhys=0x%llX, Size=0x%zX\n",
                        Request->HostPhysicalAddress.QuadPart,
                        Request->GpuPhysicalAddress.QuadPart,
                        Request->Size);
    
    // Validate BAR is mapped
    if (!DevExt->Bar0Mapped) {
        SovereignK_DbgPrint("DMATransfer: ERROR - BAR not mapped\n");
        return SOVEREIGNK_ERR_NO_DEVICE;
    }
    
    // Validate alignment
    if ((Request->HostPhysicalAddress.QuadPart & (HOST_DMA_ALIGNMENT - 1)) != 0 ||
        (Request->GpuPhysicalAddress.QuadPart & (BAR0_ALIGNMENT - 1)) != 0 ||
        (Request->Size & (HOST_DMA_ALIGNMENT - 1)) != 0) {
        SovereignK_DbgPrint("DMATransfer: ERROR - Alignment check failed\n");
        return SOVEREIGNK_ERR_ALIGNMENT;
    }
    
    // Calculate virtual addresses
    // Host: We need to map the physical address temporarily
    // In a real implementation, we'd use the locked MDL directly
    hostVa = MmMapIoSpace(Request->HostPhysicalAddress, Request->Size, MmNonCached);
    if (hostVa == NULL) {
        SovereignK_DbgPrint("DMATransfer: ERROR - Failed to map host physical\n");
        return SOVEREIGNK_ERR_NO_MEMORY;
    }
    
    // GPU: Calculate offset into BAR
    gpuVa = (PUCHAR)DevExt->Bar0VirtualAddress + 
            (Request->GpuPhysicalAddress.QuadPart - DevExt->Bar0PhysicalAddress.QuadPart);
    
    // Get start timestamp
    startCycles = __rdtsc();
    
    // Perform the copy
    // Note: In a real implementation, this would use the GPU's DMA engine
    // For now, we do a CPU-driven copy (which is still faster than user-mode)
    RtlCopyMemory(gpuVa, hostVa, Request->Size);
    
    // Memory fence to ensure completion
    _mm_sfence();
    
    // Get end timestamp
    endCycles = __rdtsc();
    
    // Unmap host
    MmUnmapIoSpace(hostVa, Request->Size);
    
    // Update statistics
    KeAcquireSpinLock(&DevExt->StatsLock, &oldIrql);
    DevExt->Stats.TotalTransfers++;
    DevExt->Stats.TotalBytesTransferred += Request->Size;
    DevExt->Stats.TotalCycles += (endCycles - startCycles);
    KeReleaseSpinLock(&DevExt->StatsLock, oldIrql);
    
    // Return response
    Response->FenceId = DevExt->Stats.TotalTransfers;
    Response->CyclesElapsed = endCycles - startCycles;
    Response->Status = STATUS_SUCCESS;
    
    SovereignK_DbgPrint("DMATransfer: SUCCESS - %llu cycles for %zu bytes\n",
                        Response->CyclesElapsed, Request->Size);
    
    return STATUS_SUCCESS;
}

// ============================================================================
// Update Statistics
// ============================================================================

VOID
SovereignK_UpdateStats(
    _In_ PSOVEREIGNK_DEVICE_EXTENSION DevExt,
    _In_ SIZE_T BytesTransferred,
    _In_ ULONGLONG Cycles
    )
{
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&DevExt->StatsLock, &oldIrql);
    DevExt->Stats.TotalTransfers++;
    DevExt->Stats.TotalBytesTransferred += BytesTransferred;
    DevExt->Stats.TotalCycles += Cycles;
    KeReleaseSpinLock(&DevExt->StatsLock, oldIrql);
}
