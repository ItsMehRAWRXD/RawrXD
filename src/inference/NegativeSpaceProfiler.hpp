// ============================================================================
// NegativeSpaceProfiler.hpp — Production Integration Header
// Drop-in instrumentation for RawrXD execution path
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <string>

namespace rawrxd {

// --- Extern C API to MASM profiler (linked from NegativeSpaceProfiler_v2.obj) ---
extern "C" {
    void Profiler_Initialize();
    void Profiler_SetBatchContext(unsigned long long batchSize);
    unsigned long long Profiler_GetBatchContext();
    unsigned long long Profiler_ReadTsc();
    void Profiler_TrackCall(unsigned long long startCycles);
    void Profiler_AnalyzeBottlenecks();
}

// --- RAII profiler guard for automatic call tracking ---
class ProfilerGuard {
public:
    explicit ProfilerGuard() {
        start_ = Profiler_ReadTsc();
    }
    ~ProfilerGuard() {
        Profiler_TrackCall(start_);
    }
private:
    unsigned long long start_;
};

// --- Batch context setter --- RAII: restores previous batch size on scope exit ---
class BatchContext {
public:
    explicit BatchContext(unsigned long long batchSize) {
        prev_ = Profiler_GetBatchContext();
        Profiler_SetBatchContext(batchSize);
    }
    ~BatchContext() {
        Profiler_SetBatchContext(prev_);
    }
private:
    unsigned long long prev_;
};

} // namespace rawrxd
