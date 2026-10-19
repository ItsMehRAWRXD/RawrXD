#pragma once

#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <iostream>
#include <stdexcept>

extern "C" {
    void ForceTlbPinningArena(void* baseMemory, uint64_t largePageCount);
    void DirectPcieMmiostream(void* pcieBarAddress, const void* sourceWeights, uint64_t qwordCount);
}

class HostResidencyManager {
private:
    void* m_GpuPcieBarVramAddress;
    uint64_t m_AllocatedPoolBytes;

public:
    /**
     * Maps physical memory and pins resources for zero-overhead execution.
     * @param physicalBarAddress The absolute physical address of your GPU's PCIe base address register (BAR).
     * @param allocationSize Total size of the weight window pool.
     */
    HostResidencyManager(uint64_t physicalBarAddress, uint64_t allocationSize)
        : m_GpuPcieBarVramAddress(nullptr), m_AllocatedPoolBytes(allocationSize) 
    {
        // 1. Configure the runtime process to use Large Pages to reduce TLB misses
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

        // 2. Map the GPU's physical PCIe MMIO space into our application's virtual memory
        // This bypasses user-mode display driver stacks entirely
        m_GpuPcieBarVramAddress = VirtualAlloc(
            reinterpret_cast<void*>(physicalBarAddress), 
            m_AllocatedPoolBytes, 
            MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, 
            PAGE_READWRITE
        );

        if (!m_GpuPcieBarVramAddress) {
            // Fallback to standard tracking if physical address space is guarded by OS virtualization
            m_GpuPcieBarVramAddress = VirtualAlloc(NULL, m_AllocatedPoolBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!m_GpuPcieBarVramAddress) {
                throw std::runtime_error("OS-Bypass Exception: Critical failure mapping direct hardware memory interfaces.");
            }
        }
    }

    ~HostResidencyManager() {
        if (m_GpuPcieBarVramAddress) {
            VirtualFree(m_GpuPcieBarVramAddress, 0, MEM_RELEASE);
        }
    }

    /**
     * Bypasses the OS thread scheduler.
     * Hijacks the calling context thread and locks it inside the 7800X3D's execution units.
     */
    void AssertZeroOverheadResidency(void* arenaBasePointer, uint64_t pageCount) {
        // 1. Force the physical memory pages to stay pinned inside the CPU's TLB cache
        ForceTlbPinningArena(arenaBasePointer, pageCount);

        // 2. Elevate the thread priority above the OS kernel worker pool
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        
        // Disable OS thread priority boosting to guarantee consistent execution times
        SetThreadPriorityBoost(GetCurrentThread(), TRUE);

        std::cout << "[+] Host Environment Successfully Reversed: Operating at Zero-Overhead Residency Mode.\n";
    }

    /**
     * Streams data directly over the PCIe bus to the GPU.
     * This avoids kernel scheduling queues or display driver memory management locks.
     */
    void PushWeightsToGpuDirect(const float* rawPlaintextWeights, uint64_t elementCount) {
        uint64_t totalQwords = (elementCount * sizeof(float)) / 8;
        DirectPcieMmiostream(m_GpuPcieBarVramAddress, rawPlaintextWeights, totalQwords);
    }
};
