#include "ReapPhysicalBank.hpp"

#include <atomic>
#include <cstring>
#include <mutex>

namespace Deep2 {
namespace {
std::mutex gMu;
ReapPhysicalBankState gState{};
std::atomic<uint64_t> gRouteOk{0};
std::atomic<uint64_t> gRouteDenied{0};
std::atomic<uint64_t> gAcquireOk{0};
std::atomic<uint64_t> gAcquireDenied{0};
std::atomic<uint64_t> gTopKMismatch{0};
} // namespace

void ReapPhysicalBankInstall(const ReapPhysicalBankState& state) {
    std::lock_guard<std::mutex> lock(gMu);
    gState = state;
    gState.active = state.active && state.retainedPerLayer > 0;
    gRouteOk.store(0);
    gRouteDenied.store(0);
    gAcquireOk.store(0);
    gAcquireDenied.store(0);
    gTopKMismatch.store(0);
}

void ReapPhysicalBankClear() {
    std::lock_guard<std::mutex> lock(gMu);
    gState = {};
}

bool ReapPhysicalBankActive() {
    std::lock_guard<std::mutex> lock(gMu);
    return gState.active;
}

uint32_t ReapPhysicalRetainedPerLayer() {
    std::lock_guard<std::mutex> lock(gMu);
    return gState.retainedPerLayer;
}

bool ReapPhysicalExpertAllowed(uint32_t expertId) {
    std::lock_guard<std::mutex> lock(gMu);
    if (!gState.active) return true;
    return expertId < gState.retainedPerLayer;
}

const ReapPhysicalBankState& ReapPhysicalBankSnapshot() {
    static thread_local ReapPhysicalBankState copy{};
    std::lock_guard<std::mutex> lock(gMu);
    copy = gState;
    return copy;
}

void ReapPhysicalNoteRoute(uint32_t expertId, bool allowed) {
    if (allowed) gRouteOk.fetch_add(1);
    else gRouteDenied.fetch_add(1);
    (void)expertId;
}
void ReapPhysicalNoteAcquire(uint32_t expertId, bool allowed) {
    if (allowed) gAcquireOk.fetch_add(1);
    else gAcquireDenied.fetch_add(1);
    (void)expertId;
}
void ReapPhysicalNoteTopK(uint32_t count, uint32_t expected) {
    if (count != expected) gTopKMismatch.fetch_add(1);
}
uint64_t ReapPhysicalRouteOk() { return gRouteOk.load(); }
uint64_t ReapPhysicalRouteDenied() { return gRouteDenied.load(); }
uint64_t ReapPhysicalAcquireOk() { return gAcquireOk.load(); }
uint64_t ReapPhysicalAcquireDenied() { return gAcquireDenied.load(); }
uint64_t ReapPhysicalTopKMismatch() { return gTopKMismatch.load(); }

} // namespace Deep2
