//============================================================================
// nevm_residency.hpp
// RawrXD N-EVM Residency State Machine
// Explicit tensor block lifecycle management
//============================================================================

#pragma once

#include "nevm_isa.hpp"
#include <atomic>
#include <condition_variable>

namespace RawrXD {
namespace NEVM {

using ISA::VirtualTensorAddress;
using ISA::PrecisionMode;
using ISA::ResidencyTarget;

//============================================================================
// Residency States
// Explicit state machine for tensor block lifecycle
//============================================================================

enum class ResidencyState {
    INVALID = 0,           // No data, not allocated
    COLD = 1,              // On disk, not mapped
    MAPPED = 2,            // Memory mapped, not accessed
    COMPRESSED = 3,        // In RAM, compressed format (Q4/Q2)
    CONVERTING = 4,        // Decompression in progress
    PREFETCHING = 5,       // Async load in progress
    RESIDENT_FAST = 6,     // Hot path: FP16/Q8 in L3/VRAM
    UPGRADING = 7,         // Precision upgrade in progress
    DOWNGRADING = 8,       // Precision downgrade in progress
    EVICTING = 9,          // Being evicted to lower tier
    PINNED = 10            // Locked, cannot evict
};

const char* ResidencyStateToString(ResidencyState state);

//============================================================================
// State Transition Rules
// Prevents invalid transitions that cause races
//============================================================================

class ResidencyStateMachine {
public:
    // Check if transition is valid
    static bool CanTransition(ResidencyState from, ResidencyState to);
    
    // Get valid next states
    static std::vector<ResidencyState> GetValidTransitions(ResidencyState from);
    
    // Check if state allows read access
    static bool IsReadable(ResidencyState state);
    
    // Check if state allows write access
    static bool IsWritable(ResidencyState state);
    
    // Check if state is transitional (async operation in progress)
    static bool IsTransitional(ResidencyState state);
    
    // Check if state is stable (can serve requests)
    static bool IsStable(ResidencyState state);
};

//============================================================================
// Tensor Block Residency Descriptor
// Thread-safe state management with wait/notify
//============================================================================

struct TensorBlockResidency {
    VirtualTensorAddress vta;
    
    // Current state (atomic for thread safety)
    std::atomic<ResidencyState> state;
    
    // Target state (for transitions)
    ResidencyState target_state;
    
    // Current representation
    PrecisionMode current_format;
    PrecisionMode target_format;
    
    // Physical location
    ResidencyTarget physical_tier;
    void* physical_ptr;
    size_t physical_size;
    
    // Transition synchronization
    std::mutex transition_mutex;
    std::condition_variable transition_cv;
    bool transition_complete;
    
    // Access statistics
    std::atomic<uint64_t> access_count;
    std::atomic<uint64_t> last_access_tick;
    std::atomic<float> importance_score;
    
    // Pending operations (for queue management)
    std::atomic<uint32_t> pending_reads;
    std::atomic<uint32_t> pending_writes;
    
    // Constructor
    TensorBlockResidency() 
        : state(ResidencyState::INVALID)
        , target_state(ResidencyState::INVALID)
        , current_format(PrecisionMode::FP32)
        , target_format(PrecisionMode::FP32)
        , physical_tier(ResidencyTarget::COLD)
        , physical_ptr(nullptr)
        , physical_size(0)
        , transition_complete(false)
        , access_count(0)
        , last_access_tick(0)
        , importance_score(0.0f)
        , pending_reads(0)
        , pending_writes(0)
    {}
    
    // Wait for transition to complete
    bool WaitForTransition(uint64_t timeout_ms);
    
    // Notify transition complete
    void NotifyTransitionComplete();
};

//============================================================================
// Residency Manager
// Coordinates state transitions across all blocks
//============================================================================

class ResidencyManager {
public:
    ResidencyManager();
    ~ResidencyManager();
    
    // Register a new block
    bool RegisterBlock(VirtualTensorAddress vta);
    
    // Unregister a block
    bool UnregisterBlock(VirtualTensorAddress vta);
    
    // Request state transition
    // Returns: true if transition initiated or already in target state
    //          false if transition cannot proceed
    bool RequestTransition(VirtualTensorAddress vta, 
                          ResidencyState target_state,
                          PrecisionMode target_format = PrecisionMode::FP32);
    
    // Get current state
    ResidencyState GetState(VirtualTensorAddress vta) const;
    
    // Wait for block to reach readable state
    // Returns: pointer to physical memory, or nullptr on timeout
    void* WaitForReadable(VirtualTensorAddress vta, uint64_t timeout_ms);
    
    // Check if block is in readable state (non-blocking)
    bool IsReadable(VirtualTensorAddress vta) const;
    
    // Pin block (prevent eviction)
    bool PinBlock(VirtualTensorAddress vta);
    bool UnpinBlock(VirtualTensorAddress vta);
    
    // Record access
    void RecordAccess(VirtualTensorAddress vta, bool is_write);
    
    // Get block info
    const TensorBlockResidency* GetBlockInfo(VirtualTensorAddress vta) const;
    
    // Statistics
    struct Stats {
        uint64_t transitions_requested;
        uint64_t transitions_completed;
        uint64_t transitions_failed;
        uint64_t transition_waits;      // Number of times threads waited
        uint64_t total_wait_ms;
        
        // State distribution
        std::unordered_map<ResidencyState, uint64_t> state_counts;
    };
    Stats GetStats() const;
    
private:
    std::unordered_map<uint64_t, std::unique_ptr<TensorBlockResidency>> blocks_;
    mutable std::shared_mutex blocks_mutex_;
    
    Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Private methods
    TensorBlockResidency* GetBlock(VirtualTensorAddress vta);
    bool ExecuteTransition(TensorBlockResidency* block, ResidencyState target);
    uint64_t GetTick() const;
};

//============================================================================
// Dependency Graph Prefetcher
// Prefetch by tensor dependencies, not just layer sequence
//============================================================================

class DependencyGraphPrefetcher {
public:
    struct TensorDependency {
        VirtualTensorAddress vta;
        std::vector<VirtualTensorAddress> depends_on;  // Must be ready first
        std::vector<VirtualTensorAddress> required_by; // These need this
        uint32_t compute_stage;  // Which stage of forward pass
        float criticality;       // 0.0-1.0, higher = more critical
    };
    
    // Build dependency graph from model architecture
    bool BuildGraph(const std::vector<TensorDependency>& dependencies);
    
    // Get prefetch candidates for current execution point
    std::vector<VirtualTensorAddress> GetPrefetchCandidates(
        const std::vector<VirtualTensorAddress>& currently_executing,
        uint32_t horizon_distance = 2  // How many stages ahead
    );
    
    // Get critical path (must be ready before execution can proceed)
    std::vector<VirtualTensorAddress> GetCriticalPath(
        VirtualTensorAddress target
    );
    
    // Update criticality based on runtime feedback
    void UpdateCriticality(VirtualTensorAddress vta, float measured_impact);
    
private:
    std::unordered_map<uint64_t, TensorDependency> graph_;
    std::mutex graph_mutex_;
    
    // Topological sort for dependency ordering
    std::vector<VirtualTensorAddress> TopologicalSort(
        const std::vector<VirtualTensorAddress>& roots
    );
};

} // namespace NEVM
} // namespace RawrXD
