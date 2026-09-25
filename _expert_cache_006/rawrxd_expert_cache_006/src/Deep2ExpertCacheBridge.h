#pragma once
#include "ExpertCache.h"
#include "ExpertTensorCatalog.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace rawrxd::deep2 {

// One device allocation containing the concatenated tensors of a single expert.
// Deep2 can bind offsets[] to its existing Vulkan GEMV/GEMM path.
struct CachedExpertBinding {
    ExpertKey key{};
    void* deviceHandle = nullptr;
    size_t totalBytes = 0;
    std::vector<size_t> tensorOffsets;
    bool cacheHit = false;
    explicit operator bool() const noexcept { return deviceHandle != nullptr; }
};

struct BridgeReceipt {
    uint64_t catalogExperts = 0;
    uint64_t registeredExperts = 0;
    uint64_t registerFailures = 0;
    uint64_t acquireFailures = 0;
    uint64_t strictViolations = 0;
    uint64_t prefetchIssued = 0;
    uint64_t prefetchFailures = 0;
    ExpertCacheStats cache{};
};

// Owns contiguous host backing for per-expert tensor groups and registers each expert with ExpertCache.
// The bridge never computes an expert on CPU. A failed acquire is a strict GPU-path failure when
// strictGpuOnly is true.
class Deep2ExpertCacheBridge final {
public:
    Deep2ExpertCacheBridge(ExpertCacheConfig cfg, ExpertTransport transport, bool strictGpuOnly = true);

    bool importCatalog(const ExpertTensorCatalog& catalog);
    CachedExpertBinding acquire(ExpertKey key, uint64_t tokenIndex);
    void noteRouterScores(uint32_t layer,
                          const uint32_t* expertIds,
                          const float* probabilities,
                          size_t count,
                          uint64_t tokenIndex);
    size_t prefetchTopK(uint32_t layer,
                        const uint32_t* expertIds,
                        const float* probabilities,
                        size_t count,
                        size_t topK,
                        uint64_t tokenIndex);

    BridgeReceipt receipt() const;
    ExpertCache& cache() noexcept { return cache_; }
    const ExpertCache& cache() const noexcept { return cache_; }

private:
    struct OwnedExpertBacking {
        ExpertKey key{};
        std::vector<uint8_t> bytes;
        std::vector<size_t> offsets;
    };

    OwnedExpertBacking* findBacking(ExpertKey key);
    const OwnedExpertBacking* findBacking(ExpertKey key) const;

    bool strictGpuOnly_ = true;
    ExpertCache cache_;
    std::vector<OwnedExpertBacking> backing_;
    BridgeReceipt receipt_{};
};

} // namespace rawrxd::deep2
