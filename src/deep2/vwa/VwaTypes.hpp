// vwa/VwaTypes.hpp — VWA residency + block request types
#pragma once
#include "../VirtualTensorDesc.hpp"
#include <cstdint>

namespace Deep2 {
namespace vwa {

enum class VwaState : uint8_t {
    NotResident = 0,
    Requested,
    Reading,
    Staged,
    Dequantizing,
    GpuResident,
    InUse,
    Hot,
    Evictable,
};

struct BlockRange {
    TensorId id = 0;
    uint32_t first = 0;
    uint32_t count = 0;
};

struct PhysicalRange {
    uint32_t shard = 0;
    uint64_t offset = 0;
    uint64_t bytes = 0;
    TensorId id = 0;
};

struct VirtualTensorRef {
    VirtualTensorDesc desc{};
    uint32_t blockElements = 0;
    uint32_t blockBytes = 0;
    uint64_t numElements = 0;
    uint32_t numBlocks = 0;
    uint32_t expertCount = 0;     // 0 = dense
    uint64_t expertStrideBytes = 0;
    VwaState state = VwaState::NotResident;
    uint32_t generation = 0;
    uint32_t pins = 0;
    void* host = nullptr;
    void* device = nullptr;
    size_t hostBytes = 0;
    size_t deviceBytes = 0;
    uint64_t lastUse = 0;
    uint32_t classId = 2; // A=0 B=1 C=2 D=3
};

struct VwaBudget {
    size_t maxHostBytes = 64ull << 20;
    size_t maxDeviceBytes = 32ull << 20;
    size_t usedHost = 0;
    size_t usedDevice = 0;
};

struct VwaStats {
    uint64_t bytesRequested = 0;
    uint64_t bytesRead = 0;
    uint64_t coalesceMerges = 0;
    uint64_t physicalIos = 0;
    uint64_t prefetchHits = 0;
    uint64_t prefetchMisses = 0;
    uint64_t dmaBytes = 0;
    uint64_t stallUs = 0;
    uint64_t computeOverlapUs = 0;
    uint64_t evictions = 0;
    uint32_t expertPlans = 0;
};

} // namespace vwa
} // namespace Deep2
