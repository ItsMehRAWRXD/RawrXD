#pragma once
#include "ExpertCache.h"
#include "ExpertTensorCatalog.h"
#include "ExpertScheduler.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace rawrxd::deep2 {

struct MultiGpuExpertDeviceConfig {
    ExpertCacheConfig cache{};
    ExpertTransport transport{};
    bool available{true};
};

struct MultiGpuExpertRuntimeConfig {
    bool enabled{true};
    bool strictGpuOnly{true};
    bool evictSourceAfterMigration{true};
    uint32_t prefetchDepth{1};
};

struct RoutedExpertHint {
    ExpertKey key{};
    float probability{0.0f};
};

struct MultiGpuExpertBinding {
    ExpertKey key{};
    void* deviceHandle{nullptr};
    size_t totalBytes{0};
    std::vector<size_t> tensorOffsets;
    uint32_t deviceOrdinal{0};
    bool cacheHit{false};
    bool migrated{false};
    explicit operator bool() const noexcept { return deviceHandle != nullptr; }
};

struct MultiGpuDeviceReceipt {
    uint32_t deviceOrdinal{0};
    uint64_t recentComputeUs{0};
    uint64_t recentTransferUs{0};
    uint64_t ownedExperts{0};
    ExpertCacheStats cache{};
};

struct MultiGpuExpertReceipt {
    uint64_t catalogExperts{0};
    uint64_t registeredExperts{0};
    uint64_t registerFailures{0};
    uint64_t schedulerDecisions{0};
    uint64_t migrations{0};
    uint64_t rejectedNoCapacity{0};
    uint64_t prefetchIssued{0};
    uint64_t prefetchFailures{0};
    uint64_t acquireFailures{0};
    uint64_t strictGpuViolations{0};
    uint64_t cpuExpertCompute{0};
    uint64_t releaseEvictions{0};
    std::vector<MultiGpuDeviceReceipt> devices;
};

// Multi-device authority above the Batch-004 per-device ExpertCache transports.
// Host expert bytes are owned exactly once and registered with every device cache.
class Deep2MultiGpuExpertCache final {
public:
    Deep2MultiGpuExpertCache(std::vector<MultiGpuExpertDeviceConfig> devices,
                             MultiGpuExpertRuntimeConfig cfg = {});
    ~Deep2MultiGpuExpertCache() = default;

    Deep2MultiGpuExpertCache(const Deep2MultiGpuExpertCache&) = delete;
    Deep2MultiGpuExpertCache& operator=(const Deep2MultiGpuExpertCache&) = delete;

    bool importCatalog(const ExpertTensorCatalog& catalog);

    // Feed rolling device pressure measured by the existing Deep2 execution path.
    void updateDevicePressure(uint32_t deviceOrdinal,
                              uint64_t recentComputeUs,
                              uint64_t recentTransferUs,
                              bool available = true);

    // Predictive path. Intended to be called while current-token GPU work is executing.
    size_t prefetchPredicted(const RoutedExpertHint* hints,
                             size_t count,
                             uint64_t tokenIndex);

    // Demand path. Returned handle is ready for GPU GEMV/GEMM.
    MultiGpuExpertBinding acquire(RoutedExpertHint hint, uint64_t tokenIndex);

    // Call after the expert GEMV/GEMM completes. In cache-off mode this evicts the
    // just-used expert, making the next access a real upload rather than a cache hit.
    void release(const MultiGpuExpertBinding& binding);

    size_t warmStart(const std::vector<RoutedExpertHint>& hotExperts, uint64_t tokenIndex = 0);
    MultiGpuExpertReceipt receipt() const;

private:
    struct OwnedExpertBacking {
        ExpertKey key{};
        std::vector<uint8_t> bytes;
        std::vector<size_t> tensorOffsets;
    };
    struct DeviceRuntime {
        uint32_t ordinal{0};
        uint64_t recentComputeUs{0};
        uint64_t recentTransferUs{0};
        bool available{true};
        std::unique_ptr<ExpertCache> cache;
    };

    using OwnerMap = std::unordered_map<ExpertKey, uint32_t, ExpertKeyHash>;
    using IndexMap = std::unordered_map<ExpertKey, size_t, ExpertKeyHash>;

    DeviceRuntime* findDevice(uint32_t ordinal);
    const DeviceRuntime* findDevice(uint32_t ordinal) const;
    const OwnedExpertBacking* findBacking(ExpertKey key) const;
    int32_t readyOwner(ExpertKey key) const;
    int32_t placementHint(ExpertKey key) const;
    rawrxd::ExpertPlacementDecision chooseDevice(ExpertKey key, float probability) const;
    std::vector<rawrxd::ExpertDeviceState> schedulerStates() const;

    MultiGpuExpertRuntimeConfig cfg_{};
    rawrxd::ExpertScheduler scheduler_{};
    std::vector<DeviceRuntime> devices_;
    std::vector<OwnedExpertBacking> backing_;
    IndexMap backingIndex_;
    OwnerMap readyOwners_;
    OwnerMap plannedOwners_;
    mutable MultiGpuExpertReceipt counters_{};
};

} // namespace rawrxd::deep2
