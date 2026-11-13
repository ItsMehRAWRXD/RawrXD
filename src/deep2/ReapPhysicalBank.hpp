#pragma once

// Process-local physical REAP expert bank (source GGUF immutable).
// Prefix mode: experts [0, retained). Allowlist mode: per-layer bitmasks.
// PROMOTE=0.

#include <cstdint>

namespace Deep2 {

static constexpr uint32_t kReapAllowMaxLayers = 128;
static constexpr uint32_t kReapAllowMaxExperts = 512;
static constexpr uint32_t kReapAllowWords =
    (kReapAllowMaxExperts + 63u) / 64u;

struct ReapPhysicalBankState {
    bool active = false;
    bool allowlistActive = false;
    uint32_t retainedPerLayer = 0;
    uint32_t allowlistLayers = 0;
    uint32_t allowlistExperts = 0;
    uint64_t originalModelBytes = 0;
    uint64_t originalExpertCount = 0;
    uint64_t retainedSlices = 0;
    uint64_t prunedParamEstimate = 0;
    uint64_t repackedModelBytes = 0;
    uint64_t topK = 0;
    char mode[32] = "NONE";
    char selectionPolicy[48] = "NONE";
    char allowlistStatus[40] = "INACTIVE";
};

void ReapPhysicalBankInstall(const ReapPhysicalBankState& state);
void ReapPhysicalBankClear();
bool ReapPhysicalBankActive();
bool ReapPhysicalAllowlistActive();
uint32_t ReapPhysicalRetainedPerLayer();

/* Route sites: set layer before ExpertAllowed / score masks. */
void ReapPhysicalSetRouteLayer(uint32_t layer);
uint32_t ReapPhysicalRouteLayer();

bool ReapPhysicalExpertAllowed(uint32_t expertId);
bool ReapPhysicalExpertAllowedAtLayer(uint32_t layer, uint32_t expertId);

/* Fixed bitmask install: bits[layer * words + word], LSB = expert 0. */
bool ReapPhysicalBankInstallAllowlist(const uint64_t* packedBits,
                                      uint32_t layerCount,
                                      uint32_t expertCap);
void ReapPhysicalBankClearAllowlist();

const ReapPhysicalBankState& ReapPhysicalBankSnapshot();

void ReapPhysicalNoteRoute(uint32_t expertId, bool allowed);
void ReapPhysicalNoteAcquire(uint32_t expertId, bool allowed);
void ReapPhysicalNoteTopK(uint32_t count, uint32_t expected);
uint64_t ReapPhysicalRouteOk();
uint64_t ReapPhysicalRouteDenied();
uint64_t ReapPhysicalAcquireOk();
uint64_t ReapPhysicalAcquireDenied();
uint64_t ReapPhysicalTopKMismatch();

} // namespace Deep2
