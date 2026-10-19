#pragma once
/*
 * EnterpriseDualStickLocality.hpp
 * Pure C++17, no third-party dependencies.
 *
 * Purpose:
 *   - bounded (layer,expert) bundle cache for Gate/Up/Down physical slices
 *   - stable host staging pointers so pinned GPU weight caches can actually hit
 *   - whole-bundle stick residency / eviction
 *   - hot-stick retention; placer stick remains authoritative for cold experts
 *   - stick-grouped top-k execution with a single join/reduction boundary
 *   - compulsory/reload/hit byte accounting
 *   - fail-closed performance authority receipts
 *
 * Quality law:
 *   Router expert IDs and router weights are immutable input. Scheduling may only
 *   reorder execution. Thrash never drops an expert.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {
namespace enterprise_moe {

static constexpr uint32_t kMaxSticks = 2;
static constexpr uint32_t kMaxTopK = 16;
static constexpr uint32_t kInvalidStick = 0xffffffffu;

struct ExpertKey {
    uint32_t layer = 0;
    uint32_t expert = 0;
    bool operator==(const ExpertKey& o) const noexcept {
        return layer == o.layer && expert == o.expert;
    }
};

struct ExpertKeyHash {
    std::size_t operator()(const ExpertKey& k) const noexcept {
        const uint64_t v = (static_cast<uint64_t>(k.layer) << 32) | k.expert;
        return static_cast<std::size_t>(v ^ (v >> 33) ^ (v << 11));
    }
};

struct TensorBytes {
    std::vector<uint8_t> bytes;
    int32_t ggmlType = -1;
    uint64_t sourceOffset = 0;
    uint64_t sourceIdentity = 0;
};

struct LoadedExpertBundle {
    TensorBytes gate;
    TensorBytes up;
    TensorBytes down;
    uint32_t hiddenDim = 0;
    uint32_t intermediateDim = 0;

    uint64_t ByteSize() const noexcept;
    bool Valid() const noexcept;
};

struct ExpertBundleView {
    const uint8_t* gate = nullptr;
    size_t gateBytes = 0;
    int32_t gateType = -1;
    const uint8_t* up = nullptr;
    size_t upBytes = 0;
    int32_t upType = -1;
    const uint8_t* down = nullptr;
    size_t downBytes = 0;
    int32_t downType = -1;
    uint32_t hiddenDim = 0;
    uint32_t intermediateDim = 0;
};

struct DeviceBundleHandle {
    uint64_t opaque[4] = {0, 0, 0, 0};
    bool valid = false;
};

struct BackendDelta {
    uint64_t h2dBytes = 0;
    uint64_t d2hBytes = 0;
    uint64_t gpuWorkNs = 0;
    uint64_t joinWaitNs = 0;
    uint64_t gpuSubmits = 0;
    uint64_t gpuWaits = 0;
    uint64_t gpuGemvCalls = 0;
    uint64_t hostGemvCalls = 0;
};

struct BackendOps {
    void* user = nullptr;

    uint32_t (*DeviceCount)(void* user) = nullptr;
    bool (*DualStickArmed)(void* user) = nullptr;

    /*
     * EnsureBundle must make this bundle usable on the requested stick.
     * On a cache hit the core does not call EnsureBundle again.
     * A backend may return opaque handles or use stable host pointers + pin IDs.
     */
    bool (*EnsureBundle)(void* user, uint32_t stick, const ExpertKey& key,
                         const ExpertBundleView& src,
                         DeviceBundleHandle& handle,
                         BackendDelta& delta,
                         std::string& error) = nullptr;

    void (*ReleaseBundle)(void* user, uint32_t stick, const ExpertKey& key,
                          DeviceBundleHandle& handle) = nullptr;

    /* One begin/one end per routed MoE layer, not per expert. */
    bool (*BeginLayer)(void* user, uint32_t layer, uint32_t hiddenDim,
                       std::string& error) = nullptr;

    /*
     * SubmitExpert must preserve routerWeight exactly. The backend may enqueue
     * asynchronously. It must accumulate this expert into the stick-local partial.
     */
    bool (*SubmitExpert)(void* user, uint32_t stick, const ExpertKey& key,
                         const ExpertBundleView& src,
                         const DeviceBundleHandle& handle,
                         const float* hidden, size_t hiddenCount,
                         float routerWeight, BackendDelta& delta,
                         std::string& error) = nullptr;

    /* Join once after both stick groups have been submitted. */
    bool (*EndLayerReduce)(void* user, uint32_t layer, float* routedOut,
                           size_t hiddenCount, BackendDelta& delta,
                           std::string& error) = nullptr;

    /* Optional cleanup for a partially submitted layer. Must not throw. */
    void (*AbortLayer)(void* user, uint32_t layer) = nullptr;
};

struct LoaderOps {
    void* user = nullptr;
    bool (*LoadBundle)(void* user, const ExpertKey& key,
                       LoadedExpertBundle& out, std::string& error) = nullptr;
};

struct Config {
    uint32_t stickCount = 2;
    uint32_t maxTopK = 8;

    /* Device-residency budget tracked by this cache. */
    uint64_t stickBudgetBytes[kMaxSticks] = {8ull << 30, 8ull << 30};

    /* Stable host staging cache. 0 = unbounded (not recommended in production). */
    uint64_t hostStagingBudgetBytes = 8ull << 30;

    /* Governing pre-DualStick baseline. 0 means unavailable. */
    uint64_t baselineMissBytesPerToken = 0;

    /* Keep the external placer authoritative for cold assignments. */
    bool retainResidentStick = true;
    bool respectPlacerStickForCold = true;

    /* Whole expert bundle (Gate+Up+Down) is the residency unit. */
    bool bundleAtomicity = true;

    /*
     * Fail-closed product authority switch. Leave false in tests/mocks.
     * Set true only in the RawrXD live adapter after MOCK_BACKEND=0 and
     * real device callbacks are bound. This never changes PROMOTE (always 0).
     */
    bool productBackendAttested = false;
};

struct RoutedExpert {
    uint32_t expertId = 0;
    float routerWeight = 0.0f;
    uint32_t preferredStick = 0; /* supplied by residency placer */
    uint32_t routerOrdinal = 0;  /* preserves quality-order provenance */
};

struct LayerRequest {
    uint32_t layer = 0;
    const RoutedExpert* selected = nullptr;
    uint32_t selectedCount = 0;
    const float* hidden = nullptr;
    size_t hiddenCount = 0;
    float* routedOut = nullptr;
};

struct Stats {
    uint64_t moeLayerCalls = 0;
    uint64_t layerFailures = 0;
    uint64_t tokensObserved = 0;

    uint64_t expertsSelected = 0;
    uint64_t expertsExecuted = 0;
    uint64_t acquireOk = 0;
    uint64_t acquireFail = 0;

    uint64_t bundleLookups = 0;
    uint64_t bundleHits = 0;
    uint64_t bundleMisses = 0;
    uint64_t bundleEvictions = 0;
    uint64_t hostStageLoads = 0;
    uint64_t hostStageHits = 0;
    uint64_t hostStageEvictions = 0;

    uint64_t compulsoryMissBytes = 0;
    uint64_t reloadMissBytes = 0;
    uint64_t hitBytes = 0;

    uint64_t stickRetains = 0;
    uint64_t stickAssignments = 0;
    uint64_t stickExperts[kMaxSticks] = {0, 0};

    uint64_t h2dBytes = 0;
    uint64_t d2hBytes = 0;
    uint64_t gpuWorkNs[kMaxSticks] = {0, 0};
    uint64_t joinWaitNs = 0;
    uint64_t gpuSubmits = 0;
    uint64_t gpuWaits = 0;
    uint64_t gpuGemvCalls = 0;
    uint64_t gpuGemvCallsByStick[kMaxSticks] = {0, 0};
    uint64_t hostGemvCalls = 0;

    uint64_t routerHashBefore = 0;
    uint64_t routerHashAfter = 0;
    uint64_t routerMutationFaults = 0;
    uint64_t topkDropFaults = 0;

    uint64_t thrashLayers = 0;
    uint64_t currentResidentBytes[kMaxSticks] = {0, 0};
    uint64_t peakResidentBytes[kMaxSticks] = {0, 0};
    uint64_t hostStagingBytes = 0;
    uint64_t hostStagingPeakBytes = 0;
};

struct PerformanceObservation {
    uint64_t generatedTokens = 0;
    uint32_t layerDepth = 0;
    uint64_t wallNs = 0;

    /* Matched host comparison only. */
    bool matchedHostAvailable = false;
    uint32_t matchedHostLayerDepth = 0;
    uint64_t matchedHostGeneratedTokens = 0;
    uint64_t matchedHostWallNs = 0;
};

struct AuthorityResult {
    bool structuralParity = false;
    bool bothSticksExecuted = false;
    bool reloadMetricMeasured = false;
    bool missMetricImproved = false;
    bool matchedWallAuthority = false;
    bool wallImproved = false;
    bool productBackendAttested = false;
    bool performanceAuthority = false;
    bool promote = false; /* intentionally fail-closed in this drop */
    std::string disposition;
};

class EnterpriseDualStickLocality {
public:
    EnterpriseDualStickLocality();
    ~EnterpriseDualStickLocality();
    EnterpriseDualStickLocality(const EnterpriseDualStickLocality&) = delete;
    EnterpriseDualStickLocality& operator=(const EnterpriseDualStickLocality&) = delete;

    bool Initialize(const Config& cfg, const LoaderOps& loader,
                    const BackendOps& backend, std::string& error);

    /* Call once per generated token before its first MoE layer. */
    void BeginToken();

    /* Router set+weights are immutable. Execution order may be grouped by stick. */
    bool ExecuteLayer(const LayerRequest& req, std::string& error);

    /* Optional next-layer warming. Never changes router selection. */
    bool Prefetch(uint32_t layer, const RoutedExpert* selected,
                  uint32_t selectedCount, std::string& error);

    Stats Snapshot() const;
    AuthorityResult Evaluate(const PerformanceObservation& perf) const;

    bool WriteReceipt(FILE* f, const PerformanceObservation& perf,
                      const char* gateName) const;

    void ResetRuntimeStats();
    void ClearCaches();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/* Standalone helpers for receipts/tests. */
uint64_t RouterFingerprint(const RoutedExpert* selected, uint32_t count) noexcept;
const char* Bool01(bool v) noexcept;

} // namespace enterprise_moe
} // namespace Deep2
