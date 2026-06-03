#pragma once

#include "arena.h"

#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <array>
#include <cmath>

/**
 * @file polymorphic_loader.h
 * @brief Format-agnostic, tier-adaptive, fixed-memory model loading architecture
 * 
 * Scales from 70B to 700B+ models while maintaining fixed 2-3 GB active window.
 * Supports GGUF, sharded blobs, mixed-quantization formats through unified descriptor.
 * Features time-travel (jump/rewind), rank-folding, and tier morphing without replanning.
 */

// ============================================================================
// SECTION 1: Universal Tensor Descriptor (UTD) - Format Abstraction
// ============================================================================

enum class TensorRole : uint8_t {
    ATTN_Q = 0,
    ATTN_K = 1,
    ATTN_V = 2,
    ATTN_O = 3,
    MLP_UP = 4,
    MLP_DOWN = 5,
    NORM = 6,
    EMB = 7,
    KV_CACHE = 8,
    MISC = 9
};

enum class QuantizationType : uint8_t {
    F32 = 0,
    F16 = 1,
    Q8_0 = 2,
    Q4_K_M = 3,
    Q2_K = 4,
    Q1_5 = 5,
    SPARSE = 6,
    DROPPED = 7
};

/**
 * @struct TensorDesc
 * @brief Universal descriptor for any tensor in any model format
 * 
 * All formats (GGUF, blobs, sharded, etc.) normalize to this structure.
 * No format-specific logic needed in hot paths.
 */
struct TensorDesc {
    uint64_t file_offset;           // Offset in backing file
    uint32_t byte_length;           // Bytes to stream
    uint16_t layer_id;              // Layer/block index
    TensorRole role;                // What this tensor does
    QuantizationType quant;         // Current quantization
    uint8_t rank_hint;              // Low-rank fold factor (0=dense)
    uint16_t stripe_id;             // For sharded models
    uint32_t shape[4];              // Dimensions (H, W, D, ...)
    float criticality;              // Importance for tier-morphing (0-1)
    uint32_t reuse_count;           // How many times used per token
};

// ============================================================================
// SECTION 2: Format Adapters - Format-Agnostic Interface
// ============================================================================

/**
 * @interface IFormatAdapter
 * @brief Adapter pattern: normalize any model format to TensorDesc
 */
class IFormatAdapter {
public:
    virtual ~IFormatAdapter() = default;
    
    /**
     * Enumerate all tensors in the model file.
     * One-time pass during indexing.
     */
    virtual std::vector<TensorDesc> enumerate(const std::string& path) = 0;
    
    /**
     * Get model metadata (context length, embedding dim, layer count, etc.)
     */
    virtual std::unordered_map<std::string, std::string> getMetadata() = 0;
    
    /**
     * Validate format and check integrity.
     */
    virtual bool validate(const std::string& path) = 0;
};

/**
 * @class GGUFAdapter
 * @brief Standard GGUF format support
 */
class GGUFAdapter : public IFormatAdapter {
public:
    std::vector<TensorDesc> enumerate(const std::string& path) override;
    std::unordered_map<std::string, std::string> getMetadata() override;
    bool validate(const std::string& path) override;

private:
    void parseTensorMetadata(const std::string& path);
};

/**
 * @class ShardedBlobAdapter
 * @brief Multi-file sharded model support
 */
class ShardedBlobAdapter : public IFormatAdapter {
public:
    std::vector<TensorDesc> enumerate(const std::string& path) override;
    std::unordered_map<std::string, std::string> getMetadata() override;
    bool validate(const std::string& path) override;

private:
    std::vector<std::string> detectShards(const std::string& base_path);
};

/**
 * @class MixedTierAdapter
 * @brief Mixed-quantization format (different layers at different quants)
 */
class MixedTierAdapter : public IFormatAdapter {
public:
    std::vector<TensorDesc> enumerate(const std::string& path) override;
    std::unordered_map<std::string, std::string> getMetadata() override;
    bool validate(const std::string& path) override;
};

// ============================================================================
// SECTION 3: Slot Lattice Memory - Fixed-Size, Polymorphic
// ============================================================================

enum class SlotType : uint8_t {
    ATTENTION = 0,
    MLP = 1,
    KV_CACHE = 2,
    AUXILIARY = 3
};

/**
 * @struct Slot
 * @brief Fixed-size memory slot with semantic interpretation
 * 
 * Memory is NOT allocated/freed; slots are overwritten.
 * Same bytes can represent different tensors at different times.
 */
struct Slot {
    void* base;                     // Fixed base address
    uint32_t capacity_bytes;        // Never changes
    SlotType type;                  // Role-based budget
    SlotType home_type;             // Original role bucket for this slot
    uint32_t flags;                 // Slot policy flags (e.g., protected ATTN ring)
    uint64_t last_written_step;     // For LRU / verification
    uint64_t last_access_step;      // Last observed use for locality-sensitive eviction
    uint64_t last_eviction_step;    // Last step this slot was evicted
    uint32_t active_bytes;          // Current usage (< capacity)
};

/**
 * @struct ActiveWindowBudget
 * @brief π-partitioned, compile-time fixed budget
 * 
 * All memory is divided by role. Attempt to exceed triggers:
 * - Tier morphing (Q4 → Q2)
 * - Rank reduction
 * - KV window shrinkage
 */
struct ActiveWindowBudget {
    // Total active working set (configurable, default 2.5 GB)
    static constexpr size_t TOTAL_BYTES = 2500ull * 1024ull * 1024ull;
    
    // π-based partition ratios (compile-time)
    static constexpr double PI = 3.14159265358979323846;
    static constexpr double WEIGHT_ATTN = PI / 8.0;
    static constexpr double WEIGHT_MLP = PI / 5.0;
    static constexpr double WEIGHT_KV = PI / 16.0;
    static constexpr double WEIGHT_SUM = WEIGHT_ATTN + WEIGHT_MLP + WEIGHT_KV;

    // Normalize weights so partitions always sum to TOTAL_BYTES.
    static constexpr size_t ATTN_BYTES = static_cast<size_t>(TOTAL_BYTES * (WEIGHT_ATTN / WEIGHT_SUM));
    static constexpr size_t MLP_BYTES = static_cast<size_t>(TOTAL_BYTES * (WEIGHT_MLP / WEIGHT_SUM));
    static constexpr size_t KV_BYTES = static_cast<size_t>(TOTAL_BYTES * (WEIGHT_KV / WEIGHT_SUM));
    static constexpr size_t MISC_BYTES = TOTAL_BYTES - (ATTN_BYTES + MLP_BYTES + KV_BYTES);
    static constexpr uint32_t BURST_STEPS = 16;
    static constexpr uint32_t BURST_ATTN_MULTIPLIER = 2;
    static constexpr double BURST_RECLAIM_RATE = 0.125;
    static constexpr double BURST_SIGMOID_GAIN = 6.0;
    static constexpr double MIN_RECLAIM_FLOOR = 0.15;
    
    // Runtime tracking
    mutable std::atomic<size_t> attn_used{0};
    mutable std::atomic<size_t> mlp_used{0};
    mutable std::atomic<size_t> kv_used{0};
    mutable std::atomic<size_t> misc_used{0};
    mutable std::atomic<size_t> burst_attn_bytes{0};
    mutable std::atomic<double> burst_reclaim_progress{0.0};
    mutable std::atomic<double> sigmoid_reclaim_value{0.0};
    mutable std::atomic<uint64_t> hysteresis_holds{0};
    
    // Hard cap enforcement
    bool canAllocate(SlotType type, size_t bytes) const;
    void recordUsage(SlotType type, size_t bytes) const;
    void releaseUsage(SlotType type, size_t bytes) const;
    void updateBurstBudget(uint64_t step_id) const;
    size_t getEffectiveLimit(SlotType type) const;
    size_t getBurstBytesActive() const;
    double getReclaimProgress() const;
    double getSigmoidReclaimValue() const;
    uint64_t getHysteresisHolds() const;
    bool isBurstActive() const;
};

/**
 * @class SlotLattice
 * @brief Fixed-size memory pool with polymorphic semantics
 */
class SlotLattice {
public:
    static constexpr uint32_t SLOT_FLAG_PROTECTED_ATTN = 0x1;
    static constexpr uint32_t ATTN_PROTECTED_SLOTS = 4;
    static constexpr uint32_t SLOT_LRU_BUCKETS = 16;
    static constexpr uint64_t EVICTION_AGE_THRESHOLD = 2;
    static constexpr uint64_t ATTN_LOCALITY_WINDOW = 2;
    static constexpr uint32_t MAX_SCAN_ATTEMPTS = 10;
    static constexpr uint32_t MAX_RETRIES = 3;

    explicit SlotLattice(const ActiveWindowBudget& budget, size_t slot_count = 256);
    ~SlotLattice();
    
    /**
     * Acquire a slot for writing (overwrites previous content).
     * Never allocates new memory—only reuses existing slots.
     */
    Slot* acquireSlot(SlotType type, uint32_t bytes_needed, uint64_t step_id);
    
    /**
     * Release a slot back to the pool (semantic only—memory unchanged).
     */
    void releaseSlot(Slot* slot);
    
    /**
     * Get total memory usage across all slots.
     */
    size_t getTotalUsage() const;
    
    /**
     * Get usage for a specific slot type.
     */
    size_t getUsageByType(SlotType type) const;
    
    /**
     * Check if memory budget exceeded.
     */
    bool isBudgetExceeded() const;
    
    /**
     * List all slots for debugging/monitoring.
     */
    std::vector<Slot*> getAllSlots() const;

    /**
     * Get count of active (in-use) slots.
     */
    uint32_t getActiveCount() const;

    /**
     * Find the first slot matching a given role/type.
     */
    Slot* findSlot(SlotType type) const;

    uint64_t getEvictionCount() const;
    uint64_t getEvictionAgeSum() const;
    uint64_t getEvictionBytes() const;
    uint64_t getEvictionsByRole(SlotType type) const;
    uint64_t getSelfEvictionBlockedCount() const;
    uint64_t getProtectedHitCount() const;
    uint64_t getProtectedScanCount() const;
    uint64_t getFastPathHitCount() const;
    uint64_t getUnprotectedEvictionCount() const;
    uint32_t getAdaptiveWindowValue() const;

private:
    std::vector<Slot> slots_;
    std::vector<Slot*> free_slots_;
    const ActiveWindowBudget& budget_;
    FastArena arena_;               // Zero-syscall arena allocator
    std::atomic<size_t> total_usage_{0};
    std::atomic<uint64_t> eviction_count_total_{0};
    std::atomic<uint64_t> eviction_age_sum_total_{0};
    std::atomic<uint64_t> eviction_bytes_total_{0};
    std::array<std::atomic<uint64_t>, 4> eviction_by_role_{};
    std::atomic<uint64_t> self_eviction_blocked_total_{0};
    std::atomic<uint64_t> protected_hit_total_{0};
    std::atomic<uint64_t> protected_scan_total_{0};
    std::atomic<uint64_t> fast_path_hit_total_{0};
    std::atomic<uint64_t> unprotected_eviction_total_{0};
    std::atomic<uint32_t> adaptive_window_last_{0};
};

// ============================================================================
// SECTION 4: Polymorphic Math - Projection + Rank Folding + Tier Morphing
// ============================================================================

/**
 * @struct ProjectionOperator
 * @brief Mathematical operation: project model into active window
 * 
 * Memory(t) = Σ wi * Πi(Model, t)
 * where wi = fixed partition weight, Πi = role projection
 */
struct ProjectionOperator {
    TensorRole role;
    float partition_weight;         // wi (fixed, π-derived)
    std::vector<size_t> indices;    // Which logical tensors participate
};

/**
 * @class PolymorphicMathEngine
 * @brief Execute by projection, not storage
 */
class PolymorphicMathEngine {
public:
    /**
     * Apply rank folding: Layer ≈ U · Vᵀ
     * U lives in slots, Vᵀ streams and discards.
     * Multiplies logical width without memory growth.
     */
    static void rankFold(
        void* U_slot,
        const std::string& model_path,
        uint64_t V_offset,
        uint32_t U_rows, uint32_t U_cols, uint32_t V_cols,
        float* output
    );
    
    /**
     * Tier morphing: change quantization without replanning.
     * Q4 → Q2 under memory pressure.
     */
    static void morphTier(
        void* tensor_slot,
        uint32_t tensor_bytes,
        QuantizationType from_quant,
        QuantizationType to_quant
    );
    
    /**
     * Create projection operators for role-based partitioning.
     */
    static std::vector<ProjectionOperator> createProjections(
        const std::vector<TensorDesc>& all_tensors
    );
};

// ============================================================================
// SECTION 5: Stream Plan - Deterministic, Precomputed Execution
// ============================================================================

/**
 * @struct StreamStep
 * @brief Represents one execution step (token or batch)
 * 
 * Specifies exactly which micro-zones to load, where to put them,
 * and which operations to execute. No decisions at runtime.
 */
struct StreamStep {
    uint32_t step_id;                           // Unique identifier
    std::vector<TensorDesc> zones_to_load;      // What to stream
    std::array<Slot*, 128> slot_assignments;    // Where to put them
    uint32_t zone_count;
    uint64_t total_bytes;
    std::vector<uint16_t> layers;               // Logical layers involved
    float expected_flops;                       // For workload estimation
};

/**
 * @class GlobalStreamPlan
 * @brief Precomputed execution schedule for the entire model
 * 
 * Computed once at model index time. Replay deterministically at runtime.
 */
class GlobalStreamPlan {
public:
    /**
     * Build plan from enumerated tensors and fixed π-budget.
     */
    bool buildFromTensors(
        const std::vector<TensorDesc>& all_tensors,
        const ActiveWindowBudget& budget,
        uint32_t max_active_layers = 2
    );
    
    /**
     * Load plan from binary cache (for fast startup).
     */
    bool loadFromDisk(const std::string& cache_path);
    
    /**
     * Save plan to binary cache for reuse.
     */
    bool saveToDisk(const std::string& cache_path) const;
    
    /**
     * Get step by index.
     */
    const StreamStep& getStep(uint32_t step_id) const;
    
    /**
     * Total steps in this plan.
     */
    uint32_t getTotalSteps() const { return static_cast<uint32_t>(plan_.size()); }
    
    /**
     * Verify plan respects budget constraints.
     */
    bool verify() const;

private:
    std::vector<StreamStep> plan_;
};

// ============================================================================
// SECTION 6: Execution Controller - Time-Travel Semantics
// ============================================================================

/**
 * @class ExecutionController
 * @brief Stateful execution with jump/rewind (time-travel)
 * 
 * Works identically for 70B or 700B—only plan length changes.
 */
class ExecutionController {
public:
    explicit ExecutionController(const GlobalStreamPlan& plan, SlotLattice& slots);
    
    /**
     * Get current execution step (what to load/compute now).
     */
    const StreamStep& currentStep() const;
    
    /**
     * Advance to next step in sequence.
     */
    void advance();
    
    /**
     * Jump to arbitrary step (time travel forward).
     * Requires checkpointed state at target or earlier.
     */
    void jumpToStep(uint32_t target_step);
    
    /**
     * Rewind to earlier step (time travel backward).
     */
    void spinBackToStep(uint32_t target_step);
    
    /**
     * Fast-forward from start to step (initialize state).
     */
    void spinUpToStep(uint32_t target_step);
    
    /**
     * Get current step ID.
     */
    uint32_t getCurrentStepId() const { return current_step_; }
    
    /**
     * Check if at end of plan.
     */
    bool isComplete() const;

private:
    const GlobalStreamPlan& plan_;
    SlotLattice& slots_;
    uint32_t current_step_;
    
    // Checkpoints for time-travel (every N steps)
    struct Checkpoint {
        uint32_t step_id;
        std::vector<uint8_t> compressed_kv;
        std::vector<uint8_t> compressed_activations;
        std::vector<uint8_t> compressed_data;
        size_t original_size = 0;
    };
    std::unordered_map<uint32_t, Checkpoint> checkpoints_;
    
    void createCheckpoint(uint32_t step_id);
    void restoreCheckpoint(uint32_t step_id);
};

// ============================================================================
// SECTION 7: Polymorphic Loader - Main Orchestrator
// ============================================================================

/**
 * @class PolymorphicLoader
 * @brief Main controller: format → UTD → slots → execution
 * 
 * Transparently handles GGUF, blobs, sharded models.
 * Maintains fixed 2-3GB active window regardless of model size.
 */
class PolymorphicLoader {
public:
    enum class SlotAcquireFailure : uint32_t {
        NONE = 0,
        SLOT_COUNT_EXHAUSTED = 1,
        BYTE_BUDGET_EXCEEDED = 2,
        FRAGMENTATION = 3,
        ROLE_LIMIT_EXCEEDED = 4,
        UNSUPPORTED_ROLE = 5,
        IO_ERROR = 6
    };

    explicit PolymorphicLoader(size_t active_window_bytes = 2500 * 1024 * 1024);
    ~PolymorphicLoader();
    
    /**
     * Index and prepare model for execution.
     * One-time pass: generates GlobalStreamPlan and cache.
     */
    bool indexModel(const std::string& model_path);
    
    /**
     * Begin execution: load plan, initialize slots.
     */
    bool beginExecution(const std::string& model_path);
    
    /**
     * Execute one step: stream zones, set up compute.
     */
    bool executeStep();
    
    /**
     * Get current step data (for GPU upload, SIMD, etc.).
     */
    const StreamStep& getCurrentStep() const;
    
    /**
     * Advance to next step.
     */
    void advanceStep();
    
    /**
     * Time-travel: jump to any step.
     */
    void jumpToStep(uint32_t step_id);
    
    /**
     * Get performance metrics.
     */
    struct PerformanceMetrics {
        float tokens_per_second;
        float mb_per_second;
        size_t active_memory_bytes;
        uint32_t total_steps;
        uint32_t current_step;
        double avg_step_ms;
        double p95_step_ms;
        double step_stddev_ms;
        uint32_t timed_steps;
        uint32_t last_step_zone_count;
        uint32_t last_step_loaded_zones;
        uint32_t last_step_skipped_zones;
        double last_step_skip_ratio;
        uint64_t last_step_bytes_loaded;
        uint64_t last_step_bytes_evicted;
        uint32_t last_step_evictions;
        double last_step_eviction_age_avg;
        uint64_t last_step_victim_search_ns;
        uint64_t last_step_materialization_ns;
        double last_step_victim_search_ratio;
        double last_step_materialization_ratio;
        uint32_t last_step_batch_count;
        double last_step_avg_zones_per_batch;
        uint32_t last_step_evictions_misc;
        uint32_t last_step_evictions_mlp;
        uint32_t last_step_evictions_attn;
        uint64_t burst_bytes_active;
        double reclaim_progress;
        double sigmoid_reclaim_value;
        uint32_t adaptive_window_value;
        uint32_t last_step_self_eviction_blocked;
        uint32_t last_step_protected_hits;
        uint32_t last_step_protected_scan_count;
        uint32_t last_step_fast_path_hits;
        uint32_t last_step_unprotected_evictions;
        uint64_t cumulative_self_eviction_blocked;
        uint64_t cumulative_protected_hits;
        uint64_t cumulative_protected_scan_count;
        uint64_t cumulative_fast_path_hits;
        uint64_t cumulative_unprotected_evictions;
        uint64_t hysteresis_holds;
        uint32_t last_slot_failure_code;
        uint64_t cumulative_zone_count;
        uint64_t cumulative_loaded_zones;
        uint64_t cumulative_skipped_zones;
        double cumulative_skip_ratio;
        uint64_t cumulative_bytes_loaded;
        uint64_t cumulative_bytes_evicted;
        uint64_t cumulative_evictions;
        double cumulative_eviction_age_avg;
        uint64_t cumulative_victim_search_ns;
        uint64_t cumulative_materialization_ns;
        uint64_t cumulative_batch_count;
        uint64_t cumulative_zones_per_batch;
        uint64_t cumulative_evictions_misc;
        uint64_t cumulative_evictions_mlp;
        uint64_t cumulative_evictions_attn;
    };
    
    PerformanceMetrics getMetrics() const;
    
    /**
     * Detect model format automatically and load with appropriate adapter.
     */
    static std::unique_ptr<IFormatAdapter> detectAndLoadAdapter(const std::string& path);

    static const char* slotAcquireFailureToString(SlotAcquireFailure reason);

private:
    ActiveWindowBudget budget_;
    std::unique_ptr<SlotLattice> slots_;
    std::unique_ptr<GlobalStreamPlan> plan_;
    std::unique_ptr<ExecutionController> controller_;
    std::unique_ptr<IFormatAdapter> adapter_;
    
    std::string current_model_path_;
    PerformanceMetrics metrics_;
    std::vector<double> step_latencies_ms_;
    double step_latency_sum_ms_ = 0.0;
    double step_latency_sum_sq_ms_ = 0.0;
    
    // Streaming I/O
    void* model_file_handle_;
    bool ensureModelFileHandle();
    bool startAsyncLoad(const TensorDesc& zone, Slot* target_slot = nullptr);

    void updateStepTimingMetrics(double elapsed_ms, size_t step_bytes, uint32_t zone_count, uint32_t skipped_zones);
};

