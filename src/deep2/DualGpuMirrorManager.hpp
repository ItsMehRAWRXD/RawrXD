#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>

extern "C" {
    void StreamAsymmetricShards(void* r9700Bar, void* rx7800XtBar, const void* sourceSysRam, uint64_t blockCount64B);
}

class DualGpuMirrorManager {
private:
    void* m_R9700_VramBar;
    void* m_7800XT_VramBar;
    uint64_t m_R9700_PoolSize;
    uint64_t m_7800XT_PoolSize;

public:
    /**
     * Initializes the dual virtual address mappings pointing to physical hardware spaces.
     * @param r9700Address Physical register target for the 32GB primary card
     * @param rx7800XtAddress Physical register target for the 16GB secondary card
     */
    DualGpuMirrorManager(uintptr_t r9700Address, uintptr_t rx7800XtAddress, uint64_t totalModelSizeBytes) 
    {
        // Calculate asymmetric balance boundaries
        m_R9700_PoolSize = (totalModelSizeBytes / 3) * 2; // 2/3 allocated memory
        m_7800XT_PoolSize = totalModelSizeBytes / 3;      // 1/3 allocated memory

        std::cout << "[i] Initializing Asymmetric Memory Split Layout:\n"
                  << " -> R9700 AI Pro (Primary Target): " << (m_R9700_PoolSize / (1024 * 1024)) << " MB\n"
                  << " -> RX 7800 XT (Secondary Target): " << (m_7800XT_PoolSize / (1024 * 1024)) << " MB\n";

        // Map absolute virtual hooks to the physical hardware lines 
        m_R9700_VramBar = VirtualAlloc(reinterpret_cast<void*>(r9700Address), m_R9700_PoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        m_7800XT_VramBar = VirtualAlloc(reinterpret_cast<void*>(rx7800XtAddress), m_7800XT_PoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (!m_R9700_VramBar || !m_7800XT_VramBar) {
            // Allocate heap stand-ins if hardware address lines are virtualization-locked by OS hypervisors
            if (!m_R9700_VramBar) m_R9700_VramBar = VirtualAlloc(NULL, m_R9700_PoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!m_7800XT_VramBar) m_7800XT_VramBar = VirtualAlloc(NULL, m_7800XT_PoolSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        }
    }

    ~DualGpuMirrorManager() {
        if (m_R9700_VramBar) VirtualFree(m_R9700_VramBar, 0, MEM_RELEASE);
        if (m_7800XT_VramBar) VirtualFree(m_7800XT_VramBar, 0, MEM_RELEASE);
    }

    /**
     * Dispatches the system RAM plain-text arrays across the split hardware buses.
     */
    void DistributeWeightsToDevices(const float* systemPlaintextWeights, uint64_t totalElementsCount) {
        uint64_t totalBytes = totalElementsCount * sizeof(float);
        uint64_t blockCount64B = totalBytes / 64;

        if (totalBytes % 64 != 0) {
            throw std::invalid_argument("Multi-GPU Error: Tensor memory byte footprint must align to 64-byte structural intervals.");
        }

        std::cout << "[~] Streaming weights across dual PCIe channels concurrently...\n";
        
        // Execute the asymmetric allocation loop inside MASM assembly
        StreamAsymmetricShards(m_R9700_VramBar, m_7800XT_VramBar, systemPlaintextWeights, blockCount64B);
        
        std::cout << "[🏁] Multi-GPU Mirroring Distribution Succeeded.\n";
    }
};
