#pragma once
// ============================================================================
// MARSController — Dual-GPU VRAM orchestration with tensor placement,
// hotpatch, rebalance, fault recovery.
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace Deep2 {

struct VRAMLease {
    uint64_t id = 0;
    size_t bytes = 0;
    int gpu = 0;        // 0 or 1; -1 = host resident
    float priority = 1.0f;
    std::string name;
    bool resident = false;
    bool migrating = false;
};

struct HotpatchResult {
    bool ok = false;
    uint64_t leaseId = 0;
    int fromGpu = -1;
    int toGpu = -1;
    size_t bytesMoved = 0;
    double latencyUs = 0.0;
};

struct DynamicParity {
    float gpu0Util = 0.0f;
    float gpu1Util = 0.0f;
    size_t gpu0Bytes = 0;
    size_t gpu1Bytes = 0;
    size_t hostBytes = 0;
    uint64_t leaseCount = 0;
    bool balanced = false;
};

struct MARSConfig {
    size_t gpu0Budget = 0;
    size_t gpu1Budget = 0;
    float rebalanceThreshold = 0.10f; // trigger if imbalance > 10%
};

struct MARSStats {
    uint64_t placements = 0;
    uint64_t redirects = 0;
    uint64_t rebalances = 0;
    uint64_t faultsRecovered = 0;
    uint64_t gpuFailuresHandled = 0;
    uint64_t oomEvents = 0;
};

class MARSController {
public:
    MARSController() = default;
    explicit MARSController(const MARSConfig& cfg);
    ~MARSController();

    MARSController(const MARSController&) = delete;
    MARSController& operator=(const MARSController&) = delete;

    bool initialize(size_t gpu0Budget, size_t gpu1Budget);
    bool isInitialized() const { return initialized_.load(); }
    void shutdown();

    // Submit work unit (opaque tag)
    bool submit(const std::string& workTag);
    bool synchronize();

    // Tensor placement: choose GPU by least-utilized + capacity
    VRAMLease* placeTensor(uint64_t tensorId, const std::string& name,
                           size_t bytes, float priority = 1.0f);

    // Inventory placement: batch place
    size_t placeAllTensors(const std::vector<std::tuple<uint64_t, std::string, size_t, float>>& items);

    // Hotpatch redirect tensor to target GPU
    HotpatchResult redirectTensor(uint64_t tensorId, int targetGPU);

    // Rebalance VRAM across GPUs
    bool rebalance();

    // Current parity
    DynamicParity getDynamicParity() const;

    // Fault recovery: mark tensor host-resident, attempt re-placement
    bool handleTensorFault(uint64_t tensorId);

    // GPU failure: migrate all tensors off failed GPU
    bool handleGPUFailure(int gpu);

    // Lease lookup
    VRAMLease* getLease(uint64_t tensorId);
    const VRAMLease* getLease(uint64_t tensorId) const;

    // Stats
    MARSStats stats() const;
    void resetStats();

    // Parity test: verify dual-GPU load within tolerance
    bool parityTest(float tolerance = 0.20f) const;

private:
    MARSConfig cfg_;
    std::atomic<bool> initialized_{false};
    mutable std::mutex mtx_;
    std::unordered_map<uint64_t, std::unique_ptr<VRAMLease>> leases_;
    size_t gpu0Used_ = 0;
    size_t gpu1Used_ = 0;
    size_t hostUsed_ = 0;
    mutable std::mutex statsMtx_;
    MARSStats stats_;
    uint64_t nextLeaseId_ = 1;

    int chooseGpu(size_t bytes, float priority) const;
    bool canFit(int gpu, size_t bytes) const;
    void updateUsed(int gpu, size_t bytes, bool add);
};

} // namespace Deep2
