#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>

extern "C" uint64_t StreamRingBufferToVramAperture(const void* src, void* dst, uint64_t bytes);

class Deep2VramBridge {
private:
    void* hostRingBuffer = nullptr;
    void* gpuBarAperture = nullptr;
    uint64_t bufferAllocationSize = 0;

public:
    Deep2VramBridge(uint64_t targetPoolSizeBytes) : bufferAllocationSize(targetPoolSizeBytes) {
        // 1. Force an unmanaged virtual memory allocation matrix block
        hostRingBuffer = VirtualAlloc(
            NULL, 
            bufferAllocationSize, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        );

        if (!hostRingBuffer) {
            throw std::runtime_error("[-] Allocation Failure: Host streaming buffer could not be mapped.");
        }

        // 2. Lock the host memory region to physical RAM to prevent OS page faults
        if (!VirtualLock(hostRingBuffer, bufferAllocationSize)) {
            VirtualFree(hostRingBuffer, 0, MEM_RELEASE);
            throw std::runtime_error("[-] Core Privilege Error: Failed to hard-lock System RAM ring boundaries.");
        }

        std::cout << "[+] Bare-Metal Bridge: Locked " << (bufferAllocationSize / (1024 * 1024)) 
                  << " MB of System RAM into physical non-pageable memory blocks.\n";
    }

    /**
     * Binds your unmanaged context driver directly to the physical PCIe BAR memory space.
     * @param mappedGpuAddress Real-time physical MMIO pointer provided via hardware interface linkages.
     */
    void BindHardwareAperture(void* mappedGpuAddress) {
        if (!mappedGpuAddress) {
            throw std::invalid_argument("[-] Topology Linkage Error: Hardware pointer reference target is invalid.");
        }
        gpuBarAperture = mappedGpuAddress;
        std::cout << "[+] Hardware Aperture: Linked to GPU Resizable BAR Address: " << gpuBarAperture << "\n";
    }

    /**
     * Cycles data directly from System RAM straight to VRAM, completely bypassing intermediate OS layers.
     */
    void SynchronousCyclePipeline(uint64_t activeSliceBytes) {
        if (!hostRingBuffer || !gpuBarAperture) {
            throw std::runtime_error("[-] Execution Guard Failure: Pipeline components are unaligned.");
        }

        // Direct handoff to non-temporal AVX-512 register streaming routines
        uint64_t faultStatus = StreamRingBufferToVramAperture(hostRingBuffer, gpuBarAperture, activeSliceBytes);
        
        if (faultStatus != 0) {
            std::cerr << "[-] Streaming Jitter Encountered: Section block sync misaligned.\n";
        }
    }

    ~Deep2VramBridge() {
        if (hostRingBuffer) {
            VirtualUnlock(hostRingBuffer, bufferAllocationSize);
            VirtualFree(hostRingBuffer, 0, MEM_RELEASE);
        }
    }
};
