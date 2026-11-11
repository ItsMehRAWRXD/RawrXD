#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

// Exact field subset mirrored from the current Deep2GpuForward.hpp.
// Production integration should pass Deep2Engine::gpuForwardCounters()
// through the templated capture() function below.
struct B71CounterSnapshot {
    uint64_t forwardLayers = 0;
    uint64_t forwardSlot0 = 0;
    uint64_t forwardSlot1 = 0;
    uint64_t hostSyncBoundaries = 0;
    uint64_t hostMaterializations = 0;
    uint64_t ownershipTransfers = 0;
    uint64_t intraSlotHostTransfers = 0;
    uint64_t liveDecodeResidentTokens = 0;
    uint64_t liveDecodeTokens = 0;
    uint64_t hostForwardLayerCalls = 0;
    uint64_t plannedCpuLayerCalls = 0;
    uint64_t gpuLayersLastToken = 0;
    uint64_t layerSubmits = 0;
    uint64_t opSubmits = 0;
    uint64_t q4kPackedOps = 0;
    uint64_t q6kPackedOps = 0;
    uint64_t q2kPackedOps = 0;
    uint64_t cpuF32Expands = 0;
};

struct B71Delta {
    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;
    uint64_t hostSyncBoundaries = 0;
    uint64_t hostMaterializations = 0;
    uint64_t ownershipTransfers = 0;
    uint64_t intraSlotHostTransfers = 0;
    uint64_t hostForwardLayerCalls = 0;
    uint64_t layerSubmits = 0;
    uint64_t opSubmits = 0;
    uint64_t q4kPackedOps = 0;
    uint64_t q6kPackedOps = 0;
    uint64_t q2kPackedOps = 0;
    uint64_t cpuF32Expands = 0;
    bool bothGpusLive = false;
    bool residentForward = false;
};

class B71GpuCounterAdapter {
    static uint64_t sub(uint64_t a,uint64_t b) noexcept {
        return a>=b?a-b:0;
    }
public:
    template<class C>
    static B71CounterSnapshot capture(const C& c) noexcept {
        B71CounterSnapshot s{};
        s.forwardLayers=c.forwardLayers;
        s.forwardSlot0=c.forwardSlot[0];
        s.forwardSlot1=c.forwardSlot[1];
        s.hostSyncBoundaries=c.hostSyncBoundaries;
        s.hostMaterializations=c.hostMaterializations;
        s.ownershipTransfers=c.ownershipTransfers;
        s.intraSlotHostTransfers=c.intraSlotHostTransfers;
        s.liveDecodeResidentTokens=c.liveDecodeResidentTokens;
        s.liveDecodeTokens=c.liveDecodeTokens;
        s.hostForwardLayerCalls=c.hostForwardLayerCalls;
        s.plannedCpuLayerCalls=c.plannedCpuLayerCalls;
        s.gpuLayersLastToken=c.gpuLayersLastToken;
        s.layerSubmits=c.layerSubmits;
        s.opSubmits=c.opSubmits;
        s.q4kPackedOps=c.q4kPackedOps;
        s.q6kPackedOps=c.q6kPackedOps;
        s.q2kPackedOps=c.q2kPackedOps;
        s.cpuF32Expands=c.cpuF32Expands;
        return s;
    }

    static B71Delta delta(const B71CounterSnapshot& before,
                          const B71CounterSnapshot& after) noexcept;
};

} // namespace Deep2
