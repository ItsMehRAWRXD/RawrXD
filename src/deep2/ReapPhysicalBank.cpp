#include "ReapPhysicalBank.hpp"

#include <cstring>
#include <mutex>

namespace Deep2 {
namespace {
std::mutex gMu;
ReapPhysicalBankState gState{};
} // namespace

void ReapPhysicalBankInstall(const ReapPhysicalBankState& state) {
    std::lock_guard<std::mutex> lock(gMu);
    gState = state;
    gState.active = state.active && state.retainedPerLayer > 0;
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
    // Caller must treat as ephemeral; copy under lock for safe reads.
    static thread_local ReapPhysicalBankState copy{};
    std::lock_guard<std::mutex> lock(gMu);
    copy = gState;
    return copy;
}

} // namespace Deep2
