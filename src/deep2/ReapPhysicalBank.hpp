#pragma once

// Process-local physical REAP expert bank (source GGUF immutable).
// When active, only experts [0, retained) may route or acquire.

#include <cstdint>

namespace Deep2 {

struct ReapPhysicalBankState {
    bool active = false;
    uint32_t retainedPerLayer = 0;
    uint64_t originalModelBytes = 0;
    uint64_t originalExpertCount = 0;
    uint64_t retainedSlices = 0;
    uint64_t prunedParamEstimate = 0;
    uint64_t repackedModelBytes = 0;
    uint64_t topK = 0;
    char mode[32] = "NONE";
    char selectionPolicy[48] = "NONE";
};

void ReapPhysicalBankInstall(const ReapPhysicalBankState& state);
void ReapPhysicalBankClear();
bool ReapPhysicalBankActive();
uint32_t ReapPhysicalRetainedPerLayer();
bool ReapPhysicalExpertAllowed(uint32_t expertId);
const ReapPhysicalBankState& ReapPhysicalBankSnapshot();

/* Streaming-correctness counters (Gate3). */
void ReapPhysicalNoteRoute(uint32_t expertId, bool allowed);
void ReapPhysicalNoteAcquire(uint32_t expertId, bool allowed);
void ReapPhysicalNoteTopK(uint32_t count, uint32_t expected);
uint64_t ReapPhysicalRouteOk();
uint64_t ReapPhysicalRouteDenied();
uint64_t ReapPhysicalAcquireOk();
uint64_t ReapPhysicalAcquireDenied();
uint64_t ReapPhysicalTopKMismatch();

} // namespace Deep2
