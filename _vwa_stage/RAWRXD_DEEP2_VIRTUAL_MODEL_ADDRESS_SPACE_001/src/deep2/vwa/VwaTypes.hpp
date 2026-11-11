// VwaTypes.hpp — canonical VWA metadata plus sparse packed residency
#pragma once
#include "../VirtualTensorDesc.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Deep2 { namespace vwa {
enum class VwaState : uint8_t { NotResident, Requested, Reading, Staged,
    Dequantizing, GpuResident, InUse, Hot, Evictable };
enum class VwaTier : uint8_t { Rom, Staging, Device };
struct BlockRange { TensorId id = 0; uint32_t first = 0, count = 0; };
struct PhysicalRange { uint32_t shard = 0; uint64_t offset = 0, bytes = 0; TensorId id = 0; };

// Actual allocation is one *requested range*, never a whole logical tensor.
// Device is packed GGUF bytes, not a hidden full-tensor float expansion.
struct ResidentRange {
    uint32_t first = 0, count = 0;
    size_t bytes = 0;
    void* device = nullptr;
    uint32_t pins = 0;
    uint32_t generation = 0;
    uint64_t lastUse = 0;
    uint8_t gpu = 0;
    bool inFlight = false;
    bool Covers(BlockRange b) const {
        return device && b.first >= first &&
            static_cast<uint64_t>(b.first) + b.count <=
            static_cast<uint64_t>(first) + count;
    }
};
struct VirtualTensorRef {
    VirtualTensorDesc desc{};
    uint32_t blockElements = 0, blockBytes = 0;
    uint64_t numElements = 0;
    uint32_t numBlocks = 0, expertCount = 0;
    uint64_t expertStrideBytes = 0;
    VwaState state = VwaState::NotResident;
    uint32_t generation = 0, pins = 0;
    void* host = nullptr;     // legacy ABI; sparse scheduler does not populate
    void* device = nullptr;   // legacy ABI; use an acquired range pointer
    size_t hostBytes = 0, deviceBytes = 0;
    uint64_t lastUse = 0;
    uint32_t classId = 2;
};
struct VirtualTensor : VirtualTensorRef {
    uint32_t nextUseOp = UINT32_MAX, refCount = 0;
    VwaTier tier = VwaTier::Rom;
    uint8_t gpu = 0;
    bool pinned = false, inFlight = false;
    std::vector<ResidentRange> ranges;
};
struct VwaBudget {
    size_t maxHostBytes = 64ull << 20, maxDeviceBytes = 32ull << 20;
    size_t usedHost = 0, usedDevice = 0;
};
struct VwaStats {
    uint64_t bytesRequested = 0, bytesRead = 0, coalesceMerges = 0;
    uint64_t physicalIos = 0, prefetchHits = 0, prefetchMisses = 0;
    uint64_t dmaBytes = 0, stallUs = 0, computeOverlapUs = 0, evictions = 0;
    uint32_t expertPlans = 0;
    uint64_t packedWeightBytes = 0, fullTensorF32Materializations = 0;
    uint64_t hostToGpuBytes = 0, peakDeviceBytes = 0, logicalModelBytes = 0;
    uint64_t opPrepares = 0, opReleases = 0, irPrefetches = 0;
};
struct OpLease { BlockRange range{}; void* packedData = nullptr; uint32_t generation = 0; uint8_t gpu = 0; };
} }
