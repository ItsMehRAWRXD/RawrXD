// ============================================================================
// MARS.hpp - Memory Allocation + Routing System
// Dynamic dual-GPU VRAM allocator with tensor leases
// Replaces static GPU parity with runtime tensor placement decisions
// ============================================================================
// Hardware target:
//   GPU0: Sapphire R9700 AI Pro  32GB VRAM (primary)
//   GPU1: RX 7800 XT             16GB VRAM (secondary)
//
// No permanent GPU ownership. No fixed layer split. No one-way migration.
// Tensors are leased, not owned. The system continuously decides:
//   - where tensors live
//   - when VRAM is reclaimed
//   - when blocks are restored
//   - which GPU executes the next workload
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Tensor Lease — dynamic GPU ownership (not permanent assignment)
// ============================================================================
struct VRAMLease {
    uint64_t    tensorId = 0;
    std::string tensorName;

    int         currentGPU = -1;      // Where tensor currently lives
    int         preferredGPU = -1;    // Preferred placement hint
    int         originalGPU = -1;     // First placement (for rollback)

    size_t      bytes = 0;
    float       priority = 0.0f;      // Higher = less likely to evict
    bool        hotpatchable = true;  // Can be moved without reload
    bool        resident = false;     // Currently in VRAM
    bool        recoverable = true;   // Can be rebuilt from GGUF

    void*       devicePtr = nullptr;  // GPU-side pointer
    void*       hostPtr = nullptr;    // Host-mapped pointer (if any)

    enum class State {
        HostOnly,       // Not on GPU
        GPU_A,          // On GPU 0
        GPU_B,          // On GPU 1
        Mirrored,       // On both GPUs
        Dropped,        // GPU copy released
        Recovered,      // Restored from GGUF
        Migrating       // In transit
    } state = State::HostOnly;
};

// ============================================================================
// GPU Agent — independent execution agent
// ============================================================================
struct GPUAgent {
    int     id = -1;
    size_t  totalVRAM = 0;
    size_t  freeVRAM = 0;
    float   tps = 0.0f;           // Tokens/sec capability
    float   load = 0.0f;          // Current utilization 0..1
    float   bandwidth = 0.0f;     // GB/s memory bandwidth
    bool    active = false;
    bool    healthy = true;

    bool initialize();
    bool execute(const void* tensor, size_t bytes);
    bool canAccept(size_t bytes) const;
};

// ============================================================================
// Dynamic Parity — runtime GPU state for balancing decisions
// ============================================================================
struct DynamicParity {
    size_t  vramFree[2] = {0, 0};
    float   load[2] = {0.0f, 0.0f};
    float   bandwidth[2] = {0.0f, 0.0f};
    bool    canMoveTensor = true;

    void Update(const GPUAgent& gpu0, const GPUAgent& gpu1);
    int SelectBestGPU(size_t bytes, float priority) const;
};

// ============================================================================
// VRAM Block — tracked allocation unit
// ============================================================================
struct VRAMBlock {
    uint64_t tensorId = 0;
    uint64_t offset = 0;
    size_t   bytes = 0;
    int      ownerGPU = -1;       // 0 or 1
    bool     resident = false;
    bool     recoverable = true;  // GGUF source still valid
};

// ============================================================================
// Dual GPU Split — result of tensor placement planning
// ============================================================================
struct DualGPUSplit {
    std::vector<VRAMBlock> gpu0;
    std::vector<VRAMBlock> gpu1;
    size_t                 vramUsed0 = 0;
    size_t                 vramUsed1 = 0;

    bool Validate(size_t vram0, size_t vram1) const;
};

// ============================================================================
// Tensor Recovery Record
// ============================================================================
struct TensorRecovery {
    uint64_t            tensorId = 0;
    VRAMLease::State    previous = VRAMLease::State::HostOnly;
    VRAMLease::State    current  = VRAMLease::State::HostOnly;
    std::string         reason;
};

// ============================================================================
// MARS Controller — dynamic orchestration layer
// ============================================================================
class Controller {
public:
    Controller();
    ~Controller();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(size_t gpu0TotalVRAM, size_t gpu1TotalVRAM);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Tensor lease management
    // ------------------------------------------------------------------------
    VRAMLease* CreateLease(
        uint64_t    tensorId,
        const std::string& name,
        size_t      bytes,
        float       priority,
        int         preferredGPU = -1
    );

    bool ReleaseLease(uint64_t tensorId);
    bool ReleaseLease(VRAMLease* lease);

    // ------------------------------------------------------------------------
    // Dynamic placement — the core MARS decision engine
    // ------------------------------------------------------------------------
    int ResolvePlacement(
        size_t  bytes,
        float   priority,
        int     hintGPU = -1
    );

    bool RedirectLease(VRAMLease& lease, int targetGPU);
    bool MigrateTensor(uint64_t tensorId, int targetGPU);
    bool EvictToHost(uint64_t tensorId);
    bool RestoreToGPU(uint64_t tensorId, int targetGPU = -1);

    // ------------------------------------------------------------------------
    // Rebalancing — continuous optimization
    // ------------------------------------------------------------------------
    void RebalanceAll();
    void RebalancePressure();   // Move under pressure
    void RebalanceIdle();       // Move to idle GPU
    void RebalanceBandwidth();  // Optimize for bandwidth

    // ------------------------------------------------------------------------
    // Hotpatch VRAM — redirect ownership at runtime
    // ------------------------------------------------------------------------
    bool HotpatchRedirect(VRAMLease& lease, int targetGPU);
    bool HotpatchRollback(VRAMLease& lease);
    bool HotpatchVerify(VRAMLease& lease);

    // ------------------------------------------------------------------------
    // Recovery — reverse tensor drop/undrop
    // ------------------------------------------------------------------------
    bool DropVRAMBlock(VRAMBlock& block);
    bool UndropVRAMBlock(VRAMBlock& block);
    bool RecoverTensor(uint64_t tensorId);

    // ------------------------------------------------------------------------
    // Split planner — initial placement for GGUF load
    // ------------------------------------------------------------------------
    DualGPUSplit PlanSplit(
        const std::vector<std::pair<uint64_t, size_t>>& tensorSizes,
        size_t gpu0VRAM,
        size_t gpu1VRAM
    );

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    size_t GetFreeVRAM(int gpu) const;
    size_t GetUsedVRAM(int gpu) const;
    float  GetGPUUtilization(int gpu) const;
    size_t GetLeaseCount() const;
    VRAMLease* GetLease(uint64_t tensorId);
    const std::vector<TensorRecovery>& GetRecoveryLog() const;

    // ------------------------------------------------------------------------
    // Callbacks
    // ------------------------------------------------------------------------
    using LeaseMovedCallback = std::function<void(const VRAMLease&, int fromGPU, int toGPU)>;
    using LeaseDroppedCallback = std::function<void(const VRAMLease&)>;
    using LeaseRecoveredCallback = std::function<void(const VRAMLease&)>;

    void SetLeaseMovedCallback(LeaseMovedCallback cb);
    void SetLeaseDroppedCallback(LeaseDroppedCallback cb);
    void SetLeaseRecoveredCallback(LeaseRecoveredCallback cb);

private:
    bool initialized_ = false;

    GPUAgent gpu0_;
    GPUAgent gpu1_;
    DynamicParity parity_;

    mutable std::mutex leasesMutex_;
    std::unordered_map<uint64_t, std::unique_ptr<VRAMLease>> leases_;
    std::vector<TensorRecovery> recoveryLog_;

    size_t vramUsed0_ = 0;
    size_t vramUsed1_ = 0;
    size_t vramTotal0_ = 0;
    size_t vramTotal1_ = 0;

    LeaseMovedCallback    onMoved_;
    LeaseDroppedCallback  onDropped_;
    LeaseRecoveredCallback onRecovered_;

    // Internal
    bool CanFit(size_t bytes, int gpu) const;
    int  SelectTargetGPU(size_t bytes, float priority, int hint) const;
    void RecordRecovery(const VRAMLease& lease, VRAMLease::State prev, VRAMLease::State cur, const char* reason);
    bool CopyTensor(int fromGPU, int toGPU, uint64_t tensorId, size_t bytes);
    bool UploadFromHost(int gpu, uint64_t tensorId, const void* data, size_t bytes);
};

// ============================================================================
// Free helpers
// ============================================================================
DualGPUSplit SplitGGUFTensors(
    const std::vector<std::pair<std::string, size_t>>& namedSizes,
    size_t gpu0VRAM,
    size_t gpu1VRAM
);

} // namespace MARS
} // namespace Deep2
