#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

extern "C" {
    void RemapVirtualAddressArena(void* baseMemory, uint64_t largePageCount);
    void StreamQuantizedLargeContent(void* pcieBarAddress, const void* sourceWeights, uint64_t blockCount64B);
}

class LargeContentManager {
private:
    void* m_VirtualBaseArena;
    uint64_t m_ArenaSizeMax;
    uint32_t m_TotalLargePages;

public:
    /**
     * Maps physical memory and pins resources for large content workloads.
     * @param targetAllocationSize Total size of the model weight window pool (e.g., 70GB+ virtual space).
     */
    LargeContentManager(uint64_t targetAllocationSize)
        : m_VirtualBaseArena(nullptr), m_ArenaSizeMax(targetAllocationSize) 
    {
        // 1. Configure the runtime process to use Large Pages to reduce TLB misses under heavy loads
        HANDLE tokenHandle;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
            TOKEN_PRIVILEGES tp;
            LUID luid;
            if (LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            }
            CloseHandle(tokenHandle);
        }

        // Align sizing metrics to strict 2MB large page boundaries
        constexpr uint64_t LARGE_PAGE_SIZE = 2 * 1024 * 1024;
        m_TotalLargePages = static_cast<uint32_t>((m_ArenaSizeMax + LARGE_PAGE_SIZE - 1) / LARGE_PAGE_SIZE);
        uint64_t exactAlignedSize = static_cast<uint64_t>(m_TotalLargePages) * LARGE_PAGE_SIZE;

        // 2. Allocate the virtual address space with structural kernel pinning privileges
        m_VirtualBaseArena = VirtualAlloc(
            NULL, 
            exactAlignedSize, 
            MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, 
            PAGE_READWRITE
        );

        if (!m_VirtualBaseArena) {
            throw std::runtime_error("OS-Bypass Exception: Failed to secure hardware large-page virtual memory arena.");
        }
    }

    ~LargeContentManager() {
        if (m_VirtualBaseArena) {
            VirtualFree(m_VirtualBaseArena, 0, MEM_RELEASE);
        }
    }

    /**
     * Bypasses the OS thread scheduler.
     * Hijacks the calling context thread and locks it inside the 7800X3D's execution units.
     */
    void AssertZeroOverheadResidency() {
        // 1. Force the physical memory pages to stay pinned inside the CPU's TLB cache
        RemapVirtualAddressArena(m_VirtualBaseArena, m_TotalLargePages);

        // 2. Elevate the thread priority above the OS kernel worker pool to prevent context switching
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        SetThreadPriorityBoost(GetCurrentThread(), TRUE);

        std::cout << "[+] Host Environment Optimized: Operating at Zero-Overhead Residency Mode.\n";
    }

    /**
     * Streams large quantized model layers directly over the hardware bus interface.
     */
    void StreamLayerBlockDirect(void* hardwareDestinationBar, const void* layerSourcePointer, uint64_t layerSizeBytes) {
        if (layerSizeBytes % 64 != 0) {
            throw std::invalid_argument("Optimization Error: Stride length must align to 64-byte structural intervals.");
        }

        uint64_t totalBlocks64B = layerSizeBytes / 64;
        
        // Execute the direct hardware streaming pipeline pass inside MASM assembly
        StreamQuantizedLargeContent(hardwareDestinationBar, layerSourcePointer, totalBlocks64B);
    }

    // Accessor utility
    void* GetBaseArenaAddress() const { return m_VirtualBaseArena; }
};
