#include "ReapPhysicalBank.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace Deep2 {
namespace {
std::mutex gMu;
ReapPhysicalBankState gState{};
uint64_t gAllow[kReapAllowMaxLayers][kReapAllowWords]{};
thread_local uint32_t gRouteLayer = 0;
std::atomic<uint64_t> gRouteOk{0};
std::atomic<uint64_t> gRouteDenied{0};
std::atomic<uint64_t> gAcquireOk{0};
std::atomic<uint64_t> gAcquireDenied{0};
std::atomic<uint64_t> gTopKMismatch{0};

bool bitAllowed(uint32_t layer, uint32_t expertId) {
    if (layer >= gState.allowlistLayers) return false;
    if (expertId >= gState.allowlistExperts) return false;
    if (expertId >= kReapAllowMaxExperts) return false;
    const uint32_t w = expertId >> 6;
    const uint32_t b = expertId & 63u;
    return (gAllow[layer][w] >> b) & 1ull;
}
} // namespace

void ReapPhysicalBankInstall(const ReapPhysicalBankState& state) {
    std::lock_guard<std::mutex> lock(gMu);
    gState = state;
    gState.active = state.active && state.retainedPerLayer > 0;
    gState.allowlistActive = false;
    gState.allowlistLayers = 0;
    gState.allowlistExperts = 0;
    std::snprintf(gState.allowlistStatus, sizeof(gState.allowlistStatus),
                  "INACTIVE");
    std::memset(gAllow, 0, sizeof(gAllow));
    gRouteOk.store(0);
    gRouteDenied.store(0);
    gAcquireOk.store(0);
    gAcquireDenied.store(0);
    gTopKMismatch.store(0);
}

void ReapPhysicalBankClear() {
    std::lock_guard<std::mutex> lock(gMu);
    gState = {};
    std::memset(gAllow, 0, sizeof(gAllow));
}

bool ReapPhysicalBankActive() {
    std::lock_guard<std::mutex> lock(gMu);
    return gState.active;
}

bool ReapPhysicalAllowlistActive() {
    std::lock_guard<std::mutex> lock(gMu);
    return gState.active && gState.allowlistActive;
}

uint32_t ReapPhysicalRetainedPerLayer() {
    std::lock_guard<std::mutex> lock(gMu);
    return gState.retainedPerLayer;
}

void ReapPhysicalSetRouteLayer(uint32_t layer) { gRouteLayer = layer; }

uint32_t ReapPhysicalRouteLayer() { return gRouteLayer; }

bool ReapPhysicalExpertAllowedAtLayer(uint32_t layer, uint32_t expertId) {
    std::lock_guard<std::mutex> lock(gMu);
    if (!gState.active) return true;
    if (gState.allowlistActive) return bitAllowed(layer, expertId);
    return expertId < gState.retainedPerLayer;
}

bool ReapPhysicalExpertAllowed(uint32_t expertId) {
    const uint32_t layer = gRouteLayer;
    std::lock_guard<std::mutex> lock(gMu);
    if (!gState.active) return true;
    if (gState.allowlistActive) return bitAllowed(layer, expertId);
    return expertId < gState.retainedPerLayer;
}

bool ReapPhysicalBankInstallAllowlist(const uint64_t* packedBits,
                                      uint32_t layerCount,
                                      uint32_t expertCap) {
    if (!packedBits || layerCount == 0 || expertCap == 0) return false;
    if (layerCount > kReapAllowMaxLayers) return false;
    if (expertCap > kReapAllowMaxExperts) return false;
    std::lock_guard<std::mutex> lock(gMu);
    if (!gState.active) return false;
    std::memset(gAllow, 0, sizeof(gAllow));
    for (uint32_t L = 0; L < layerCount; ++L) {
        for (uint32_t w = 0; w < kReapAllowWords; ++w)
            gAllow[L][w] = packedBits[L * kReapAllowWords + w];
    }
    gState.allowlistActive = true;
    gState.allowlistLayers = layerCount;
    gState.allowlistExperts = expertCap;
    std::snprintf(gState.allowlistStatus, sizeof(gState.allowlistStatus),
                  "CALIBRATED_ALLOWLIST_ACTIVE");
    std::snprintf(gState.selectionPolicy, sizeof(gState.selectionPolicy),
                  "CALIBRATED_ALLOWLIST_ACTIVE");
    return true;
}

void ReapPhysicalBankClearAllowlist() {
    std::lock_guard<std::mutex> lock(gMu);
    gState.allowlistActive = false;
    gState.allowlistLayers = 0;
    gState.allowlistExperts = 0;
    std::snprintf(gState.allowlistStatus, sizeof(gState.allowlistStatus),
                  "INACTIVE");
    std::memset(gAllow, 0, sizeof(gAllow));
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
