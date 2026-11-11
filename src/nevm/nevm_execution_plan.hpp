//============================================================================
// nevm_execution_plan.hpp
// Compiled execution plan for NEVM operations
// Caches kernel selections, residency decisions, and prefetch schedules
//============================================================================

#pragma once

#include "nevm_kernel_bridge.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Execution Plan Node
// Single operation in the compiled plan
//============================================================================

struct ExecutionNode {
    enum class Type {
        KERNEL,         // Execute kernel
        PREFETCH,       // Prefetch data
        BARRIER,        // Synchronization point
        COPY,           // Data movement
        PRECISION_CHANGE // Format conversion
    };
    
    Type type;
    uint32_t stream_id;     // Execution stream (0 = default)
    uint32_t dependencies;  // Bitmask of dependent nodes
    
    // For KERNEL type
    struct KernelInfo {
        Kernels::QuantType quant;
        Kernels::KernelCaps isa;
        void* kernel_entry;
        VirtualTensorAddress vta_a;
        VirtualTensorAddress vta_b;
        VirtualTensorAddress vta_out;
        size_t m, n, k;
        float estimated_latency_ms;
    } kernel;
    
    // For PREFETCH type
    struct PrefetchInfo {
        VirtualTensorAddress vta;
        size_t offset;
        size_t size;
        uint32_t distance;  // How many nodes ahead to prefetch
    } prefetch;
    
    // Telemetry
    uint64_t actual_cycles;
    float actual_latency_ms;
    bool executed;
};

//============================================================================
// Execution Plan
// Compiled sequence of operations
//============================================================================

// Plan version info for invalidation detection
struct PlanVersion {
    uint64_t plan_id;              // Unique plan identifier
    uint64_t model_hash;           // Hash of model weights
    uint64_t graph_hash;           // Hash of compute graph
    uint64_t kernel_registry_ver;  // Kernel registry version
    uint64_t compiler_version;     // Compiler that built the code
    uint64_t planner_version;      // Planner algorithm version
    uint64_t compiled_at;          // Timestamp
    
    bool IsValid(uint64_t current_registry_ver, 
                  uint64_t current_compiler_ver,
                  uint64_t current_planner_ver) const {
        return kernel_registry_ver == current_registry_ver &&
               compiler_version == current_compiler_ver &&
               planner_version == current_planner_ver;
    }
    
    // Combined version for simple checks
    uint64_t CombinedVersion() const {
        return kernel_registry_ver ^ (compiler_version << 1) ^ (planner_version << 2);
    }
};

// Mutable execution state (per-run)
struct ExecutionState {
    // Residency (mutable)
    std::vector<TensorExecutionDescriptor::ResidencyTier> residency_tiers;
    std::vector<void*> host_pointers;
    std::vector<void*> device_pointers;
    
    // Precision (mutable)
    std::vector<ISA::PrecisionMode> precision_modes;
    
    // Telemetry (mutable)
    std::vector<uint64_t> actual_cycles;
    std::vector<float> actual_latency_ms;
    
    // Runtime flags
    uint32_t stream_id;
    bool cancelled;
};

class ExecutionPlan {
public:
    ExecutionPlan() = default;
    ~ExecutionPlan() = default;
    
    // Disable copy, enable move
    ExecutionPlan(const ExecutionPlan&) = delete;
    ExecutionPlan& operator=(const ExecutionPlan&) = delete;
    ExecutionPlan(ExecutionPlan&&) = default;
    ExecutionPlan& operator=(ExecutionPlan&&) = default;
    
    // Builder API
    void AddKernel(const ExecutionNode::KernelInfo& kernel);
    void AddPrefetch(const ExecutionNode::PrefetchInfo& prefetch);
    void AddBarrier(uint32_t stream_mask);
    void AddPrecisionChange(VirtualTensorAddress vta, ISA::PrecisionMode from, ISA::PrecisionMode to);
    
    // Set dependency between nodes
    void SetDependency(size_t node_idx, size_t depends_on_idx);
    
    // Execution
    void Execute();
    void ExecuteAsync(uint32_t stream_id);
    void WaitForCompletion();
    
    // Optimization
    void Optimize();  // Fuse operations, reorder for locality
    void CacheResidencyDecisions();  // Pin frequently accessed data
    
    // Telemetry
    struct Stats {
        size_t total_nodes;
        size_t kernel_nodes;
        size_t prefetch_nodes;
        float estimated_total_ms;
        float actual_total_ms;
        uint64_t total_cycles;
        size_t cache_hits;
        size_t cache_misses;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Versioning
    PlanVersion version_;
    uint64_t GetRegistryVersion() const;
    bool IsValid() const { return version_.IsValid(GetRegistryVersion()); }
    
    // Separate mutable state for reuse
    mutable ExecutionState state_;
    void ResetState();
    
    // Serialization for caching
    std::vector<uint8_t> Serialize() const;
    bool Deserialize(const std::vector<uint8_t>& data);

private:
    std::vector<ExecutionNode> nodes_;
    std::vector<std::vector<size_t>> dependency_graph_;
    Stats stats_;
    bool optimized_;
    
    void ExecuteNode(size_t idx);
    bool DependenciesSatisfied(size_t idx) const;
};

//============================================================================
// Execution Planner
// Compiles NEVM instructions into optimized execution plans
//============================================================================

class ExecutionPlanner {
public:
    struct Config {
        bool enable_prefetch{true};
        bool enable_kernel_fusion{true};
        bool enable_stream_parallelism{true};
        uint32_t max_streams{4};
        float latency_budget_ms{10.0f};
    };
    
    static Config DefaultConfig();
    
    explicit ExecutionPlanner(const Config& config);
    ~ExecutionPlanner();
    
    // Compile single instruction
    ExecutionPlan Compile(const InstructionDispatcher::Instruction& inst);
    
    // Compile batch of instructions
    ExecutionPlan CompileBatch(const std::vector<InstructionDispatcher::Instruction>& batch);
    
    // Compile transformer layer (high-level)
    ExecutionPlan CompileTransformerLayer(
        const std::vector<VirtualTensorAddress>& inputs,
        const std::vector<VirtualTensorAddress>& weights,
        const std::vector<VirtualTensorAddress>& outputs
    );
    
    // Cache management
    void CachePlan(uint64_t hash, ExecutionPlan plan);
    std::optional<ExecutionPlan> GetCachedPlan(uint64_t hash);
    void ClearCache();

private:
    Config config_;
    std::unordered_map<uint64_t, ExecutionPlan> plan_cache_;
    std::mutex cache_mutex_;
    
    uint64_t HashInstruction(const InstructionDispatcher::Instruction& inst) const;
    void AddPrefetchNodes(ExecutionPlan& plan);
    void OptimizeDependencies(ExecutionPlan& plan);
};

//============================================================================
// Plan Executor
// Executes compiled plans with scheduling
//============================================================================

class PlanExecutor {
public:
    struct Stream {
        uint32_t id;
        std::queue<size_t> pending_nodes;
        bool busy;
    };
    
    explicit PlanExecutor(uint32_t num_streams);
    ~PlanExecutor();
    
    // Execute plan
    void Execute(const ExecutionPlan& plan);
    void ExecuteAsync(const ExecutionPlan& plan);
    
    // Stream management
    uint32_t AcquireStream();
    void ReleaseStream(uint32_t stream_id);
    void WaitAll();
    
    // Telemetry
    struct ExecutionStats {
        uint64_t plans_executed;
        uint64_t nodes_executed;
        float avg_latency_ms;
        float max_latency_ms;
        uint32_t stream_utilization[8];  // Per-stream
    };
    ExecutionStats GetStats() const;

private:
    std::vector<Stream> streams_;
    std::mutex stream_mutex_;
    ExecutionStats stats_;
    
    void ExecuteOnStream(const ExecutionPlan& plan, uint32_t stream_id);
};

} // namespace NEVM
} // namespace RawrXD
