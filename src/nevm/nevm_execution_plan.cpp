//============================================================================
// nevm_execution_plan.cpp
// Compiled execution plan implementation
//============================================================================

#include "nevm_execution_plan.hpp"
#include <algorithm>
#include <cstring>

namespace RawrXD {
namespace NEVM {

//============================================================================
// ExecutionPlan Implementation
//============================================================================

void ExecutionPlan::AddKernel(const ExecutionNode::KernelInfo& kernel) {
    ExecutionNode node;
    node.type = ExecutionNode::Type::KERNEL;
    node.stream_id = 0;
    node.dependencies = 0;
    node.kernel = kernel;
    node.executed = false;
    node.actual_cycles = 0;
    node.actual_latency_ms = 0.0f;
    
    nodes_.push_back(node);
    dependency_graph_.emplace_back();
}

void ExecutionPlan::AddPrefetch(const ExecutionNode::PrefetchInfo& prefetch) {
    ExecutionNode node;
    node.type = ExecutionNode::Type::PREFETCH;
    node.stream_id = 0;
    node.dependencies = 0;
    node.prefetch = prefetch;
    node.executed = false;
    node.actual_cycles = 0;
    node.actual_latency_ms = 0.0f;
    
    nodes_.push_back(node);
    dependency_graph_.emplace_back();
}

void ExecutionPlan::AddBarrier(uint32_t stream_mask) {
    ExecutionNode node;
    node.type = ExecutionNode::Type::BARRIER;
    node.stream_id = stream_mask;
    node.dependencies = 0;
    node.executed = false;
    node.actual_cycles = 0;
    node.actual_latency_ms = 0.0f;
    
    nodes_.push_back(node);
    dependency_graph_.emplace_back();
}

void ExecutionPlan::SetDependency(size_t node_idx, size_t depends_on_idx) {
    if (node_idx < nodes_.size() && depends_on_idx < nodes_.size()) {
        dependency_graph_[node_idx].push_back(depends_on_idx);
    }
}

void ExecutionPlan::Execute() {
    // Simple topological execution
    std::vector<bool> completed(nodes_.size(), false);
    size_t completed_count = 0;
    
    while (completed_count < nodes_.size()) {
        bool made_progress = false;
        
        for (size_t i = 0; i < nodes_.size(); ++i) {
            if (completed[i]) continue;
            if (!DependenciesSatisfied(i)) continue;
            
            ExecuteNode(i);
            completed[i] = true;
            completed_count++;
            made_progress = true;
        }
        
        if (!made_progress && completed_count < nodes_.size()) {
            // Cycle detected or stuck
            break;
        }
    }
}

void ExecutionPlan::ExecuteNode(size_t idx) {
    if (idx >= nodes_.size()) return;
    
    auto& node = nodes_[idx];
    auto start = std::chrono::high_resolution_clock::now();
    
    switch (node.type) {
        case ExecutionNode::Type::KERNEL: {
            // Execute kernel through bridge
            KernelBridge::ExecutionContext ctx;
            ctx.vta_a = node.kernel.vta_a;
            ctx.vta_b = node.kernel.vta_b;
            ctx.vta_out = node.kernel.vta_out;
            ctx.precision = ISA::PrecisionMode::Q4;  // TODO: map from quant
            ctx.m = node.kernel.m;
            ctx.n = node.kernel.n;
            ctx.k = node.kernel.k;
            ctx.latency_budget_ms = node.kernel.estimated_latency_ms;
            
            // TODO: Resolve VTAs to actual pointers
            void* a = nullptr;
            void* b = nullptr;
            void* out = nullptr;
            
            KernelBridge::DispatchMatMul(ctx, a, b, out);
            break;
        }
        
        case ExecutionNode::Type::PREFETCH: {
            // TODO: Implement prefetch
            // _mm_prefetch(...);
            break;
        }
        
        case ExecutionNode::Type::BARRIER: {
            // TODO: Implement barrier
            // std::atomic_thread_fence(std::memory_order_seq_cst);
            break;
        }
        
        default:
            break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    node.actual_latency_ms = duration.count() / 1e6f;
    node.actual_cycles = duration.count();  // Approximate
    node.executed = true;
}

bool ExecutionPlan::DependenciesSatisfied(size_t idx) const {
    if (idx >= dependency_graph_.size()) return true;
    
    for (size_t dep_idx : dependency_graph_[idx]) {
        if (dep_idx < nodes_.size() && !nodes_[dep_idx].executed) {
            return false;
        }
    }
    return true;
}

ExecutionPlan::Stats ExecutionPlan::GetStats() const {
    Stats stats = {};
    stats.total_nodes = nodes_.size();
    
    for (const auto& node : nodes_) {
        switch (node.type) {
            case ExecutionNode::Type::KERNEL:
                stats.kernel_nodes++;
                stats.estimated_total_ms += node.kernel.estimated_latency_ms;
                break;
            case ExecutionNode::Type::PREFETCH:
                stats.prefetch_nodes++;
                break;
            default:
                break;
        }
        
        if (node.executed) {
            stats.actual_total_ms += node.actual_latency_ms;
            stats.total_cycles += node.actual_cycles;
        }
    }
    
    return stats;
}

void ExecutionPlan::ResetStats() {
    for (auto& node : nodes_) {
        node.executed = false;
        node.actual_cycles = 0;
        node.actual_latency_ms = 0.0f;
    }
}

void ExecutionPlan::Optimize() {
    if (optimized_) return;
    
    // TODO: Implement optimizations:
    // - Fuse adjacent kernels
    // - Reorder for cache locality
    // - Insert prefetch nodes
    // - Balance across streams
    
    optimized_ = true;
}

//============================================================================
// ExecutionPlanner Implementation
//============================================================================

ExecutionPlanner::Config ExecutionPlanner::DefaultConfig() {
    Config config;
    config.enable_prefetch = true;
    config.enable_kernel_fusion = true;
    config.enable_stream_parallelism = true;
    config.max_streams = 4;
    config.latency_budget_ms = 10.0f;
    return config;
}

ExecutionPlanner::ExecutionPlanner(const Config& config) : config_(config) {}

ExecutionPlanner::~ExecutionPlanner() = default;

ExecutionPlan ExecutionPlanner::Compile(const InstructionDispatcher::Instruction& inst) {
    ExecutionPlan plan;
    
    // Check cache first
    uint64_t hash = HashInstruction(inst);
    auto cached = GetCachedPlan(hash);
    if (cached.has_value()) {
        return std::move(cached.value());
    }
    
    // Compile based on opcode
    switch (inst.opcode) {
        case InstructionDispatcher::OpCode::MATMUL: {
            // Determine precision
            ISA::PrecisionMode precision = ISA::PrecisionMode::Q4;  // Default
            
            // Build kernel info
            ExecutionNode::KernelInfo kernel;
            kernel.quant = KernelBridge::PrecisionToQuant(precision);
            kernel.isa = Kernels::KernelCaps::AVX512F | Kernels::KernelCaps::AVX512VL;
            kernel.kernel_entry = Kernels::KernelRegistry::GetQ4DotKernel();
            kernel.vta_a = inst.src_a;
            kernel.vta_b = inst.src_b;
            kernel.vta_out = inst.dst;
            kernel.m = (inst.param.int_param >> 16) & 0xFFFF;
            kernel.n = inst.param.int_param & 0xFFFF;
            kernel.k = 64;  // TODO: proper dimension
            kernel.estimated_latency_ms = 0.001f;  // ~1us per block
            
            plan.AddKernel(kernel);
            
            // Add prefetch if enabled
            if (config_.enable_prefetch) {
                ExecutionNode::PrefetchInfo prefetch;
                prefetch.vta = inst.src_b;
                prefetch.offset = 0;
                prefetch.size = 64 * sizeof(float);
                prefetch.distance = 1;
                plan.AddPrefetch(prefetch);
            }
            
            break;
        }
        
        default:
            // TODO: Handle other opcodes
            break;
    }
    
    // Optimize the plan
    plan.Optimize();
    
    // Cache the compiled plan
    CachePlan(hash, plan);
    
    return plan;
}

ExecutionPlan ExecutionPlanner::CompileBatch(
    const std::vector<InstructionDispatcher::Instruction>& batch) {
    
    ExecutionPlan plan;
    
    for (const auto& inst : batch) {
        ExecutionPlan single = Compile(inst);
        
        // Merge single plan into batch plan
        // TODO: Implement proper merging with dependency tracking
    }
    
    return plan;
}

uint64_t ExecutionPlanner::HashInstruction(const InstructionDispatcher::Instruction& inst) const {
    // Simple hash combining opcode, addresses, and dimensions
    uint64_t hash = static_cast<uint64_t>(inst.opcode);
    hash = hash * 31 + inst.src_a;
    hash = hash * 31 + inst.src_b;
    hash = hash * 31 + inst.dst;
    hash = hash * 31 + inst.param.int_param;
    return hash;
}

void ExecutionPlanner::CachePlan(uint64_t hash, ExecutionPlan plan) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    plan_cache_[hash] = std::move(plan);
}

std::optional<ExecutionPlan> ExecutionPlanner::GetCachedPlan(uint64_t hash) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = plan_cache_.find(hash);
    if (it != plan_cache_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void ExecutionPlanner::ClearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    plan_cache_.clear();
}

} // namespace NEVM
} // namespace RawrXD
