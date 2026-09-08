#pragma once
// Choreographer owns sequencing only — never weight arenas or slot recycling.
#include "SovereignLaneRuntime.hpp"
#include <algorithm>
#include <cstdio>

namespace Deep2 {
namespace dual_lane {

enum class ChoreoMode : uint8_t {
    DualModel = 0,   // Model A @ GPU A, Model B @ GPU B
    SplitDomain = 1, // One model, layer domains; activation handoff only
};

struct ChoreoRequest {
    const char* prompt = nullptr;
    uint32_t maxTokensA = 256;
    uint32_t maxTokensB = 256;
    int requireJoin = 0; // 0 = async receipts; 1 = join_wall = max(A,B)
};

struct ChoreoResult {
    LaneReceipt a{};
    LaneReceipt b{};
    double joinWallMs = 0.0;
    int dualModel = 0;
    int independentProgress = 1;
    int weightCrossAttempts = 0;
    int weightCrossRefused = 0;
    int dualGenerateStreamLive = 0;
    int weightsCrossLanes = 0;
    int activationsOnlyCross = 1;
};

struct DualLaneChoreographer {
    DualLaneContract contract = DefaultContract();
    SovereignLane laneA{};
    SovereignLane laneB{};
    ChoreoMode mode = ChoreoMode::DualModel;

    DualLaneChoreographer() {
        laneA.id = LaneId::A;
        laneB.id = LaneId::B;
    }

    int armDualModel(int gpuA, const char* nameA, uint64_t vramA,
                     uint32_t modelA, const char* pathA, int gpuB,
                     const char* nameB, uint64_t vramB, uint32_t modelB,
                     const char* pathB) {
        mode = ChoreoMode::DualModel;
        laneA.open = laneA.bindDevice(gpuA, nameA, vramA) &&
                     laneA.bindModel(modelA, pathA, nullptr);
        laneB.open = laneB.bindDevice(gpuB, nameB, vramB) &&
                     laneB.bindModel(modelB, pathB, nullptr);
        return laneA.open && laneB.open && ContractHolds(contract) ? 1 : 0;
    }

    int armSplitDomain(int gpuA, const char* nameA, uint64_t vramA, int gpuB,
                       const char* nameB, uint64_t vramB, uint32_t modelId,
                       const char* path, uint32_t splitLayer) {
        mode = ChoreoMode::SplitDomain;
        laneA.open = laneA.bindDevice(gpuA, nameA, vramA) &&
                     laneA.bindModel(modelId, path, nullptr);
        laneB.open = laneB.bindDevice(gpuB, nameB, vramB) &&
                     laneB.bindModel(modelId, path, nullptr);
        laneA.setLayerDomain(0, splitLayer);
        laneB.setLayerDomain(splitLayer, 0xFFFFFFFFu);
        return laneA.open && laneB.open && ContractHolds(contract) ? 1 : 0;
    }

    ChoreoResult run(const ChoreoRequest& req);
    void emit(FILE* f, const ChoreoResult& r) const;
};

} // namespace dual_lane
} // namespace Deep2
