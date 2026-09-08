#pragma once
// One sovereign 800B-class streamer/loader per GPU. Owns all weight memory.
#include "DualLaneContract.hpp"
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>

namespace Deep2 {
namespace dual_lane {

struct LaneModelMap {
    char modelPath[512]{};
    char shardDir[512]{};
    uint32_t modelId = 0;
    uint32_t layerBegin = 0;
    uint32_t layerEnd = 0; // exclusive; 0/0 = full model on this lane
};

struct LaneGpuResidency {
    int deviceIndex = -1;
    char deviceName[128]{};
    uint64_t vramBudgetBytes = 0;
    uint64_t weightBytesResident = 0;
};

// Private to the lane — choreographer must not allocate here.
struct SovereignLane {
    LaneId id = LaneId::A;
    LaneModelMap map{};
    LaneGpuResidency gpu{};
    uint32_t weightSlotCount = 0;
    uint32_t pinnedSlotCount = 0;
    uint64_t generation = 0;
    uint64_t leaseCount = 0;
    std::atomic<uint64_t> fence{0};
    int open = 0;
    void* generateEngine = nullptr;

    void bindGenerate(void* engine) { generateEngine = engine; }

    bool bindDevice(int index, const char* name, uint64_t vram) {
        gpu.deviceIndex = index;
        gpu.vramBudgetBytes = vram;
        if (name)
            std::snprintf(gpu.deviceName, sizeof(gpu.deviceName), "%s", name);
        return index >= 0;
    }

    bool bindModel(uint32_t mid, const char* path, const char* shards) {
        map.modelId = mid;
        if (path) std::snprintf(map.modelPath, sizeof(map.modelPath), "%s", path);
        if (shards)
            std::snprintf(map.shardDir, sizeof(map.shardDir), "%s", shards);
        return path && path[0];
    }

    // Domain split (mode 2): layers [begin, end) — weights stay on this GPU.
    void setLayerDomain(uint32_t begin, uint32_t end) {
        map.layerBegin = begin;
        map.layerEnd = end;
    }

    // Hard refuse: cannot free / recycle another lane's slots.
    static int mayTouchPeerSlots(LaneId self, LaneId peer) {
        return self == peer ? 1 : 0;
    }

    LaneReceipt beginGeneration() {
        ++generation;
        ++leaseCount;
        LaneReceipt r{};
        r.lane = id;
        r.modelId = map.modelId;
        r.generation = generation;
        r.ok = open;
        return r;
    }

    void complete(LaneReceipt& r, uint32_t tokens, double wallMs, uint64_t outH) {
        r.tokensEmitted = tokens;
        r.wallMs = wallMs;
        r.outputHandle = outH;
        r.completionFence = fence.fetch_add(1, std::memory_order_acq_rel) + 1;
        r.ok = 1;
    }
};

} // namespace dual_lane
} // namespace Deep2
