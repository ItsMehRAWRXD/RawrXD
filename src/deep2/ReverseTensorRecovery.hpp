// ============================================================================
// ReverseTensorRecovery.hpp - Tensor Drop / Recovery System
// ============================================================================
// Recovery path for corrupted or evicted VRAM blocks.
//
// Sequence:
//   Tensor Fault → Reverse Hotpatch → Find available VRAM →
//   Rehydrate block → Resume backend
//
// Never drop GGUF source data. Drop only GPU-resident copies.
// ============================================================================

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <functional>

namespace Deep2 {

// Forward declarations
struct TensorInfo;
struct VRAMBlock;
class TensorGraph;
class DualGPUHook;

// ============================================================================
// Tensor State
// ============================================================================
enum class TensorState {
    HostOnly,    // Never uploaded to GPU
    GPU_A,       // Resident on GPU 0
    GPU_B,       // Resident on GPU 1
    Mirrored,    // Present on both GPUs
    Dropped,     // GPU copy released, GGUF source intact
    Recovered,   // Re-uploaded from GGUF after drop
    Failed       // Recovery failed
};

// ============================================================================
// Tensor Recovery Record
// ============================================================================
struct TensorRecovery {
    uint64_t    tensorId   = 0;
    TensorState previous   = TensorState::HostOnly;
    TensorState current    = TensorState::HostOnly;
    uint64_t    timestamp  = 0;
    std::string reason;
};

// ============================================================================
// Reverse Tensor Backend
// ============================================================================
class ReverseTensorBackend {
public:
    ReverseTensorBackend();
    ~ReverseTensorBackend();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(DualGPUHook* hook);
    void Shutdown();

    // ------------------------------------------------------------------------
    // Core operations
    // ------------------------------------------------------------------------
    bool Undrop(VRAMBlock& block);   // Re-upload from GGUF source
    bool Drop(VRAMBlock& block);     // Release GPU copy only
    bool Rebuild(VRAMBlock& block);  // Reconstruct from shards / quant blocks

    // ------------------------------------------------------------------------
    // Recovery pipeline
    // ------------------------------------------------------------------------
    bool RecoverTensor(
        uint64_t tensorId,
        TensorGraph& graph,
        int preferredGPU = -1);

    bool RecoverAllDropped(TensorGraph& graph);

    // ------------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------------
    bool VerifyGGUFSource(uint64_t tensorId);
    bool VerifyGPUCopy(uint64_t tensorId, int gpu);

    // ------------------------------------------------------------------------
    // History / rollback
    // ------------------------------------------------------------------------
    const std::vector<TensorRecovery>& GetHistory() const;
    bool Rollback(uint64_t tensorId);
    void ClearHistory();

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using RecoveryCallback = std::function<void(const TensorRecovery&)>;
    void SetRecoveryCallback(RecoveryCallback cb);

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    struct Stats {
        uint64_t tensorsDropped    = 0;
        uint64_t tensorsRecovered  = 0;
        uint64_t tensorsFailed     = 0;
        uint64_t bytesRehydrated   = 0;
        uint64_t rollbackCount     = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    bool initialized_ = false;
    DualGPUHook* hook_ = nullptr;

    mutable std::mutex historyMutex_;
    std::vector<TensorRecovery> history_;

    RecoveryCallback onRecovery_;

    Stats stats_;
    mutable std::mutex statsMutex_;

    // Internal
    bool RehydrateFromGGUF(uint64_t tensorId, int targetGPU);
    void RecordRecovery(uint64_t id, TensorState prev, TensorState cur, const char* reason);
};

// ============================================================================
// Free helpers
// ============================================================================
inline const char* TensorStateName(TensorState s) {
    switch (s) {
        case TensorState::HostOnly:  return "HostOnly";
        case TensorState::GPU_A:     return "GPU_A";
        case TensorState::GPU_B:     return "GPU_B";
        case TensorState::Mirrored:  return "Mirrored";
        case TensorState::Dropped:   return "Dropped";
        case TensorState::Recovered: return "Recovered";
        case TensorState::Failed:    return "Failed";
        default:                     return "Unknown";
    }
}

} // namespace Deep2
