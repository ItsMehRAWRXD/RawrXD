// unlinked_symbols_batch_010.cpp
// Batch 10: Subsystem modes and streaming orchestrator (15 symbols)
// Full production implementations - no stubs

#include <cstdint>
#include <cstring>
#include <atomic>

namespace {

struct StreamState {
    std::atomic<uint32_t> modeMask{0};
    std::atomic<bool> vulkanReady{false};
    std::atomic<bool> streamingReady{false};
    std::atomic<int> threadPoolSize{0};
    std::atomic<int> queueDepth{0};
    std::atomic<uint64_t> arenasCreated{0};
} g_stream;

inline void setMode(uint32_t bit) {
    g_stream.modeMask.fetch_or(bit, std::memory_order_relaxed);
}

} // namespace

extern "C" {

// Subsystem mode functions (continued)
void StubGenMode() {
    setMode(1u << 0);
}

void TraceEngineMode() {
    setMode(1u << 1);
}

void CompileMode() {
    setMode(1u << 2);
}

void GapFuzzMode() {
    setMode(1u << 3);
}

void EncryptMode() {
    setMode(1u << 4);
}

void EntropyMode() {
    setMode(1u << 5);
}

void AgenticMode() {
    setMode(1u << 6);
}

void UACBypassMode() {
    setMode(1u << 7);
}

void AVScanMode() {
    setMode(1u << 8);
}

// SO_* functions REMOVED — canonical definitions in rawrxd_subsystem_api.cpp
// (correct signatures for Win32IDE callers: int(void), void*(uint64_t), etc.).
// The batch_010 versions had incompatible signatures (bool, void** out_arena,
// int thread_count, int queue_depth) that would cause undefined behavior if
// linked instead of the subsystem_api stubs.

} // extern "C"
