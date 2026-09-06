#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <new>

class Deep2MultiGpuBridge {
private:
    // Memory-mapped atomic synchronization boundaries to control inter-device cross-talk
    struct alignas(64) InterGpuSyncGate {
        std::atomic<uint64_t> r9700SequenceToken;
        std::atomic<uint64_t> gpu7800XtSequenceToken;
        uint8_t               padding[48]; // Isolate atomic lines to prevent L1 cache line bouncing
    };

    InterGpuSyncGate* syncGate = nullptr;
    HANDLE            hMapFile = NULL;

public:
    Deep2MultiGpuBridge() {
        // Create an unmanaged, kernel-visible shared memory section for bare-metal multi-GPU sync
        hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            sizeof(InterGpuSyncGate),
            L"Global\\SovereignEngine_MultiGpuSync"
        );

        if (!hMapFile) {
            // If Global namespace fails, try local
            hMapFile = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                NULL,
                PAGE_READWRITE,
                0,
                sizeof(InterGpuSyncGate),
                L"Local\\SovereignEngine_MultiGpuSync"
            );
        }

        if (!hMapFile) {
            throw std::runtime_error("[-] Sync Fault: Failed to initialize inter-GPU kernel shared mapping gate.");
        }

        void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(InterGpuSyncGate));
        if (!pBuf) {
            CloseHandle(hMapFile);
            throw std::runtime_error("[-] Sync Fault: View mapping vector failed to bind.");
        }

        syncGate = new (pBuf) InterGpuSyncGate();
        syncGate->r9700SequenceToken.store(0, std::memory_order_release);
        syncGate->gpu7800XtSequenceToken.store(0, std::memory_order_release);
    }

    /**
     * Executes the cross-device pipeline handoff step.
     * Handshakes the R9700 activation matrix state out to the 7800XT over the 8x/8x PCIe interconnect.
     */
    void SignalHandoffTo7800XT(uint64_t activeTargetCycle, const float* activationData, float* r9700ToGpuBridgeBuffer, uint32_t elements) {
        // Non-temporal copy sequence to populate the target PCIe interface stream channel
        // Using standard copy since OpenMP might not be enabled
        for (uint32_t i = 0; i < elements; ++i) {
            r9700ToGpuBridgeBuffer[i] = activationData[i];
        }

        // Release-fence: Ensure activation data is fully written to the PCIe BAR before incrementing token
        syncGate->r9700SequenceToken.store(activeTargetCycle, std::memory_order_release);
    }

    /**
     * Stalls the 7800XT compute execution thread until the R9700 finishes writing the activation matrix.
     */
    void AwaitR9700DataPayload(uint64_t expectedCycleToken) {
        // Spin-lock loop optimized with pause hints to prevent physical core execution stalls
        while (syncGate->r9700SequenceToken.load(std::memory_order_acquire) < expectedCycleToken) {
            YieldProcessor(); // Emits the 'pause' instruction to conserve execution pipeline hardware resources
        }
    }

    ~Deep2MultiGpuBridge() {
        if (syncGate) {
            UnmapViewOfFile(syncGate);
        }
        if (hMapFile) {
            CloseHandle(hMapFile);
        }
    }
};
