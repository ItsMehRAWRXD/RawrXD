/*++

Module Name:
    Utils.c

Abstract:
    Utility functions for memory allocation

--*/

#include "SovereignK.h"

// ============================================================================
// Memory Allocation
// ============================================================================

PVOID
SovereignK_AllocateMemory(
    _In_ SIZE_T Size
    )
{
    PVOID memory;
    
    memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, SOVEREIGNK_POOL_TAG);
    
    if (memory != NULL) {
        RtlZeroMemory(memory, Size);
    }
    
    return memory;
}

VOID
SovereignK_FreeMemory(
    _In_ PVOID Memory
    )
{
    if (Memory != NULL) {
        ExFreePoolWithTag(Memory, SOVEREIGNK_POOL_TAG);
    }
}
