// ============================================================================
// ResidencyTrace.hpp
// C++ interface to ResidencyTrace.asm
// ============================================================================

#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize tracer. Returns 1 on success, 0 on failure.
int TraceInit(const char* filename);

// Shutdown tracer and flush remaining events.
void TraceShutdown(void);

// Reserve a ring slot and record operation start.
// Returns pointer to event, or nullptr if ring full.
struct ResidencyEvent;
ResidencyEvent* TraceBegin(
    uint32_t token,
    uint32_t layer,
    uint32_t tensorId,
    uint64_t sizeBytes,
    uint32_t sourceTier,
    uint32_t requestedTier
);

// Set destination metadata on an event.
void TraceSetDestination(
    ResidencyEvent* ev,
    uint32_t actualTier,
    uint64_t cpuAddress,
    uint64_t vkBuffer,
    uint64_t vkMemory,
    uint32_t memoryType,
    uint32_t heapIndex
);

// Mark operation complete.
void TraceComplete(ResidencyEvent* ev, uint64_t fence, uint64_t queue, int success);

// Flush events to disk.
void TraceFlush(void);

#ifdef __cplusplus
}
#endif
