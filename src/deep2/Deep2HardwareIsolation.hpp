#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>

// Link directly to our low-level unmethoded assembly module
extern "C" {
    void ApplyHardwareIsolationTopology(void* ringContext, uint32_t hardwareCoreIndex);
    void FastInterleavedPrefetchFlush(const void* memoryTarget, uint64_t strideBytes);
    void SmtSiblingPrefetchLoop(const void* source, uint64_t stride, volatile uint32_t* stopFlag, volatile uint64_t* epoch);
    uint32_t SafeSmtPrefetchSweep(const void* source, uint64_t stride);
}

#include <thread>
#include <atomic>
#include <intrin.h>
#include "Deep2ProfilingHarness.hpp" // This is now Deep2MicroProfiler

class Deep2HardwareIsolation {
public:
    struct SmtPrefetchContext {
        std::thread worker;
        std::atomic<uint32_t> stopFlag{0};
        std::atomic<uint64_t> readyEpoch{0};
        std::atomic<uint64_t> beginTsc{0};
        std::atomic<uint64_t> firstReadyTsc{0};
        std::atomic<uint64_t> endTsc{0};
        const void* source = nullptr;
        uint64_t bytes = 0;
        Deep2MicroProfiler* profiler; 
    };

    static void PinCurrentThreadToCcx(uint32_t coreIndex, bool useSmtLane, Deep2MicroProfiler* profiler) {
        std::string threadType = useSmtLane ? "SMT Sibling" : "Primary";
        profiler->LogEvent("PinCurrentThreadToCcx: Entry for " + threadType + " on Core " + std::to_string(coreIndex));

        if (coreIndex >= 8) {
            throw std::out_of_range("Zen 4 Topology Error: Target core index exceeds physical 7800X3D CCD limits.");
        }

        uint32_t targetBit = (coreIndex * 2) + (useSmtLane ? 1 : 0);
        DWORD_PTR affinityMask = (static_cast<DWORD_PTR>(1) << targetBit);

        HANDLE currentThread = GetCurrentThread();
        DWORD_PTR previousAffinity = SetThreadAffinityMask(currentThread, affinityMask);

        if (previousAffinity == 0) {
            profiler->LogEvent("PinCurrentThreadToCcx: FAILED to set affinity mask for " + threadType);
            throw std::runtime_error("OS-Bypass Fault: Failed to enforce hard hardware thread affinity mask.");
        }
        profiler->LogEvent("PinCurrentThreadToCcx: Set affinity mask 0x" + std::to_string(affinityMask) + " for " + threadType);

        if (!SetThreadPriority(currentThread, THREAD_PRIORITY_TIME_CRITICAL)) {
            std::cerr << "[!] Warning: Failed to elevate processing thread to Time-Critical priority.\n";
            profiler->LogEvent("PinCurrentThreadToCcx: WARNING: Failed to elevate priority for " + threadType);
        }
        profiler->LogEvent("PinCurrentThreadToCcx: Exiting for " + threadType);
    }

    static void EnforceIsolateEcosystem(void* rawRingContext, uint32_t computeCore, Deep2MicroProfiler* profiler) {
        profiler->LogEvent("EnforceIsolateEcosystem: Entry");
        ApplyHardwareIsolationTopology(rawRingContext, computeCore);
        profiler->LogEvent("EnforceIsolateEcosystem: Applied hardware isolation topology");

        PinCurrentThreadToCcx(computeCore, false, profiler);
        
        std::cout << "[+] Hardware Interconnect Isolation Successfully Asserted on Core " 
                  << computeCore << ".\n";
        profiler->LogEvent("EnforceIsolateEcosystem: Exit");
    }

    static bool PinSmtSiblingBestEffort(uint32_t coreIndex) {
        if (coreIndex >= 8) {
            return false;
        }
        const uint32_t targetBit = (coreIndex * 2u) + 1u;
        const DWORD_PTR affinityMask = (static_cast<DWORD_PTR>(1) << targetBit);
        if (SetThreadAffinityMask(GetCurrentThread(), affinityMask) == 0) {
            return false;
        }
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
        return true;
    }

    static SmtPrefetchContext* StartSiblingPrefetcher(uint32_t computeCore, const void* source, uint64_t stride, Deep2MicroProfiler* profiler) {
        profiler->LogEvent("StartSiblingPrefetcher: Entry");
        auto* ctx = new SmtPrefetchContext();
        ctx->stopFlag = 0;
        ctx->source = source;
        ctx->bytes = stride;
        ctx->profiler = profiler;

        ctx->worker = std::thread([ctx, computeCore]() {
            ctx->beginTsc.store(__rdtsc(), std::memory_order_release);
            PinSmtSiblingBestEffort(computeCore);
            while (ctx->stopFlag.load(std::memory_order_acquire) == 0) {
                if (ctx->source != nullptr && ctx->bytes != 0) {
                    if (SafeSmtPrefetchSweep(ctx->source, ctx->bytes) == 0) {
                        ctx->stopFlag.store(1, std::memory_order_release);
                        break;
                    }
                }
                const uint64_t epoch = ctx->readyEpoch.fetch_add(1, std::memory_order_acq_rel) + 1;
                if (epoch == 1) {
                    ctx->firstReadyTsc.store(__rdtsc(), std::memory_order_release);
                }
                _mm_pause();
            }
            ctx->endTsc.store(__rdtsc(), std::memory_order_release);
        });
        profiler->LogEvent("StartSiblingPrefetcher: Worker thread launched");
        return ctx;
    }

    static bool WaitForPrefetchEpoch(SmtPrefetchContext* ctx, uint64_t minEpoch, uint32_t spinLimit) {
        if (!ctx) {
            return false;
        }
        for (uint32_t i = 0; i < spinLimit; ++i) {
            if (ctx->readyEpoch.load(std::memory_order_acquire) >= minEpoch) {
                return true;
            }
            _mm_pause();
            if ((i & 1023u) == 0) {
                SwitchToThread();
            }
        }
        return ctx->readyEpoch.load(std::memory_order_acquire) >= minEpoch;
    }

    static uint64_t StopSiblingPrefetcher(SmtPrefetchContext* ctx) {
        if (!ctx) {
            return 0;
        }
        Deep2MicroProfiler* profiler = ctx->profiler;
        ctx->stopFlag.store(1, std::memory_order_release);
        if (ctx->worker.joinable()) {
            ctx->worker.join();
        }
        const uint64_t endTsc = ctx->endTsc.load(std::memory_order_acquire);
        if (profiler) {
            profiler->LogEvent("StopSiblingPrefetcher: Worker thread joined");
        }
        delete ctx;
        return endTsc;
    }
};
