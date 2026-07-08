// executor.cpp
// Layer 2: Node Executor Implementation

#include "executor.h"
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <thread>
#include <future>
#include <fstream>

namespace rawrxd::executor {

// ═══════════════════════════════════════════════════════════════════════════════
// Internal Implementation
// ═══════════════════════════════════════════════════════════════════════════════

struct ExecutionContext {
    NodeSpec spec;
    ExecutionState state;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::chrono::microseconds execution_time;
    size_t memory_used;
    size_t memory_peak;
    std::string error_message;
    std::optional<std::string> checkpoint_path;
    
    ProgressCallback progress_cb;
    CompletionCallback completion_cb;
    std::thread execution_thread;
};

struct KernelRegistration {
    KernelType type;
    std::function<void(void*)> func;
};

class ExecutorImpl {
public:
    std::map<NodeId, std::unique_ptr<ExecutionContext>> executions_;
    std::map<KernelId, KernelRegistration> kernels_;
    mutable std::mutex mutex_;
    
    // Memory pool
    size_t memory_pool_size_ = 16ULL * 1024 * 1024 * 1024; // 16GB default
    size_t memory_allocated_ = 0;
    size_t memory_peak_ = 0;
    std::mutex memory_mutex_;
    
    // Configuration
    uint32_t max_concurrent_executions_ = 32;
    std::string checkpoint_dir_ = "./checkpoints";
    
    // Statistics
    std::atomic<uint64_t> total_executions_{0};
    std::atomic<uint64_t> successful_executions_{0};
    std::atomic<uint64_t> failed_executions_{0};
    std::atomic<uint64_t> cancelled_executions_{0};
    std::atomic<uint64_t> checkpoints_created_{0};
    std::atomic<uint64_t> checkpoints_restored_{0};
    std::vector<std::chrono::microseconds> execution_times_;
    std::mutex stats_mutex_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// NodeExecutor Implementation
// ═══════════════════════════════════════════════════════════════════════════════

NodeExecutor::NodeExecutor() : impl_(std::make_unique<ExecutorImpl>()) {}
NodeExecutor::~NodeExecutor() = default;

std::optional<MemoryAllocation> NodeExecutor::AllocateMemory(
    size_t size, uint32_t alignment, bool device_memory) {
    
    std::lock_guard<std::mutex> lock(impl_->memory_mutex_);
    
    if (impl_->memory_allocated_ + size > impl_->memory_pool_size_) {
        return std::nullopt; // Out of memory
    }
    
    // Simple allocation (in production, use proper memory pool)
    void* ptr = nullptr;
    if (device_memory) {
        // GPU allocation would go here
        ptr = aligned_alloc(alignment, size);
    } else {
        ptr = aligned_alloc(alignment, size);
    }
    
    if (!ptr) {
        return std::nullopt;
    }
    
    impl_->memory_allocated_ += size;
    impl_->memory_peak_ = std::max(impl_->memory_peak_, impl_->memory_allocated_);
    
    MemoryAllocation alloc;
    alloc.ptr = ptr;
    alloc.size = size;
    alloc.alignment = alignment;
    alloc.device_memory = device_memory;
    
    return alloc;
}

void NodeExecutor::FreeMemory(const MemoryAllocation& alloc) {
    std::lock_guard<std::mutex> lock(impl_->memory_mutex_);
    
    if (alloc.ptr) {
        free(alloc.ptr);
        impl_->memory_allocated_ -= alloc.size;
    }
}

MemoryPool NodeExecutor::GetMemoryPool() const {
    std::lock_guard<std::mutex> lock(impl_->memory_mutex_);
    
    MemoryPool pool;
    pool.total_allocated = impl_->memory_allocated_;
    pool.peak_allocated = impl_->memory_peak_;
    pool.available = impl_->memory_pool_size_ - impl_->memory_allocated_;
    pool.pool_size = impl_->memory_pool_size_;
    
    return pool;
}

void NodeExecutor::ResetMemoryPool() {
    std::lock_guard<std::mutex> lock(impl_->memory_mutex_);
    
    // In production, would properly free all tracked allocations
    impl_->memory_allocated_ = 0;
}

bool NodeExecutor::RegisterKernel(KernelId id, KernelType type, 
                                   std::function<void(void*)> kernel_func) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->kernels_.find(id) != impl_->kernels_.end()) {
        return false; // Already registered
    }
    
    KernelRegistration reg;
    reg.type = type;
    reg.func = kernel_func;
    impl_->kernels_[id] = reg;
    
    return true;
}

void NodeExecutor::UnregisterKernel(KernelId id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->kernels_.erase(id);
}

bool NodeExecutor::IsKernelRegistered(KernelId id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->kernels_.find(id) != impl_->kernels_.end();
}

bool NodeExecutor::Execute(const NodeSpec& spec) {
    return ExecuteAsync(spec, nullptr, nullptr);
}

bool NodeExecutor::ExecuteAsync(const NodeSpec& spec,
                                 ProgressCallback progress_cb,
                                 CompletionCallback completion_cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    // Check if kernel is registered
    if (impl_->kernels_.find(spec.kernel_id) == impl_->kernels_.end()) {
        return false;
    }
    
    // Check concurrent execution limit
    size_t running = 0;
    for (const auto& [id, ctx] : impl_->executions_) {
        if (ctx->state == ExecutionState::Running) {
            running++;
        }
    }
    
    if (running >= impl_->max_concurrent_executions_) {
        return false; // At capacity
    }
    
    // Create execution context
    auto ctx = std::make_unique<ExecutionContext>();
    ctx->spec = spec;
    ctx->state = ExecutionState::Pending;
    ctx->progress_cb = progress_cb;
    ctx->completion_cb = completion_cb;
    ctx->memory_used = 0;
    ctx->memory_peak = 0;
    
    impl_->executions_[spec.id] = std::move(ctx);
    
    // Start execution in background thread
    impl_->executions_[spec.id]->execution_thread = std::thread([this, id = spec.id]() {
        auto& ctx = *impl_->executions_[id];
        
        ctx.state = ExecutionState::Running;
        ctx.start_time = std::chrono::steady_clock::now();
        
        impl_->total_executions_++;
        
        // Get kernel function
        KernelRegistration kernel;
        {
            std::lock_guard<std::mutex> lock(impl_->mutex_);
            kernel = impl_->kernels_[ctx.spec.kernel_id];
        }
        
        // Execute kernel (simplified - real implementation would handle inputs/outputs)
        try {
            // Allocate input/output memory
            for (const auto& input : ctx.spec.inputs) {
                ctx.memory_used += input.size;
            }
            for (const auto& output : ctx.spec.outputs) {
                ctx.memory_used += output.size;
            }
            ctx.memory_peak = ctx.memory_used;
            
            // Call kernel
            kernel.func(nullptr); // Would pass actual data
            
            // Report progress
            if (ctx.progress_cb) {
                ctx.progress_cb(id, 1.0f);
            }
            
            ctx.state = ExecutionState::Completed;
            ctx.end_time = std::chrono::steady_clock::now();
            ctx.execution_time = std::chrono::duration_cast<std::chrono::microseconds>(
                ctx.end_time - ctx.start_time);
            
            impl_->successful_executions_++;
            
        } catch (const std::exception& e) {
            ctx.state = ExecutionState::Failed;
            ctx.error_message = e.what();
            ctx.end_time = std::chrono::steady_clock::now();
            impl_->failed_executions_++;
        }
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(impl_->stats_mutex_);
            impl_->execution_times_.push_back(ctx.execution_time);
        }
        
        // Call completion callback
        if (ctx.completion_cb) {
            ExecutionResult result;
            result.node_id = id;
            result.state = ctx.state;
            result.execution_time = ctx.execution_time;
            result.start_time = ctx.start_time;
            result.end_time = ctx.end_time;
            result.memory_used = ctx.memory_used;
            result.memory_peak = ctx.memory_peak;
            result.success = (ctx.state == ExecutionState::Completed);
            result.error_message = ctx.error_message;
            
            ctx.completion_cb(result);
        }
    });
    
    impl_->executions_[spec.id]->execution_thread.detach();
    
    return true;
}

std::optional<ExecutionResult> NodeExecutor::GetResult(NodeId id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->executions_.find(id);
    if (it == impl_->executions_.end()) {
        return std::nullopt;
    }
    
    const auto& ctx = *it->second;
    
    // Only return if completed/failed/cancelled
    if (ctx.state != ExecutionState::Completed &&
        ctx.state != ExecutionState::Failed &&
        ctx.state != ExecutionState::Cancelled) {
        return std::nullopt;
    }
    
    ExecutionResult result;
    result.node_id = id;
    result.state = ctx.state;
    result.execution_time = ctx.execution_time;
    result.start_time = ctx.start_time;
    result.end_time = ctx.end_time;
    result.memory_used = ctx.memory_used;
    result.memory_peak = ctx.memory_peak;
    result.success = (ctx.state == ExecutionState::Completed);
    result.error_message = ctx.error_message;
    result.checkpoint_path = ctx.checkpoint_path;
    
    return result;
}

std::optional<ExecutionResult> NodeExecutor::WaitForResult(
    NodeId id, std::chrono::milliseconds timeout) {
    
    auto start = std::chrono::steady_clock::now();
    
    while (std::chrono::steady_clock::now() - start < timeout) {
        auto result = GetResult(id);
        if (result.has_value()) {
            return result;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return std::nullopt;
}

bool NodeExecutor::Cancel(NodeId id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->executions_.find(id);
    if (it == impl_->executions_.end()) {
        return false;
    }
    
    auto& ctx = *it->second;
    if (ctx.state == ExecutionState::Running) {
        ctx.state = ExecutionState::Cancelled;
        impl_->cancelled_executions_++;
        return true;
    }
    
    return false;
}

ExecutionState NodeExecutor::GetState(NodeId id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->executions_.find(id);
    if (it == impl_->executions_.end()) {
        return ExecutionState::Failed;
    }
    
    return it->second->state;
}

std::optional<Checkpoint> NodeExecutor::Checkpoint(const NodeId& id, const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->executions_.find(id);
    if (it == impl_->executions_.end()) {
        return std::nullopt;
    }
    
    auto& ctx = *it->second;
    
    // Create checkpoint
    Checkpoint cp;
    cp.node_id = id;
    cp.path = path;
    cp.timestamp = std::chrono::steady_clock::now();
    cp.state = ctx.state;
    cp.memory_size = ctx.memory_used;
    
    ctx.checkpoint_path = path;
    impl_->checkpoints_created_++;
    
    return cp;
}

bool NodeExecutor::RestoreFromCheckpoint(const Checkpoint& checkpoint) {
    // In production, would restore actual state
    impl_->checkpoints_restored_++;
    return true;
}

std::vector<Checkpoint> NodeExecutor::ListCheckpoints(NodeId id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<Checkpoint> checkpoints;
    
    auto it = impl_->executions_.find(id);
    if (it != impl_->executions_.end() && it->second->checkpoint_path.has_value()) {
        Checkpoint cp;
        cp.node_id = id;
        cp.path = *it->second->checkpoint_path;
        cp.timestamp = std::chrono::steady_clock::now();
        cp.state = it->second->state;
        cp.memory_size = it->second->memory_used;
        checkpoints.push_back(cp);
    }
    
    return checkpoints;
}

void NodeExecutor::DeleteCheckpoint(const Checkpoint& checkpoint) {
    // In production, would delete actual file
}

NodeExecutor::Statistics NodeExecutor::GetStatistics() const {
    Statistics stats;
    stats.total_executions = impl_->total_executions_.load();
    stats.successful_executions = impl_->successful_executions_.load();
    stats.failed_executions = impl_->failed_executions_.load();
    stats.cancelled_executions = impl_->cancelled_executions_.load();
    stats.total_checkpoints_created = impl_->checkpoints_created_.load();
    stats.total_checkpoints_restored = impl_->checkpoints_restored_.load();
    
    {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex_);
        if (!impl_->execution_times_.empty()) {
            auto sum = std::chrono::microseconds::zero();
            for (const auto& t : impl_->execution_times_) {
                sum += t;
            }
            stats.avg_execution_time_ms = 
                (sum.count() / impl_->execution_times_.size()) / 1000.0;
            
            auto sorted = impl_->execution_times_;
            std::sort(sorted.begin(), sorted.end());
            size_t p99_idx = sorted.size() * 99 / 100;
            stats.p99_execution_time_ms = sorted[p99_idx].count() / 1000.0;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock(impl_->memory_mutex_);
        stats.total_memory_allocated = impl_->memory_allocated_;
        stats.peak_memory_used = impl_->memory_peak_;
    }
    
    return stats;
}

void NodeExecutor::ResetStatistics() {
    impl_->total_executions_ = 0;
    impl_->successful_executions_ = 0;
    impl_->failed_executions_ = 0;
    impl_->cancelled_executions_ = 0;
    impl_->checkpoints_created_ = 0;
    impl_->checkpoints_restored_ = 0;
    
    std::lock_guard<std::mutex> lock(impl_->stats_mutex_);
    impl_->execution_times_.clear();
}

void NodeExecutor::SetMemoryPoolSize(size_t size) {
    impl_->memory_pool_size_ = size;
}

void NodeExecutor::SetMaxConcurrentExecutions(uint32_t max) {
    impl_->max_concurrent_executions_ = max;
}

void NodeExecutor::SetCheckpointDirectory(const std::string& path) {
    impl_->checkpoint_dir_ = path;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

static std::unique_ptr<NodeExecutor> g_executor;
static std::once_flag g_init_flag;

NodeExecutor& GetExecutor() {
    std::call_once(g_init_flag, []() {
        g_executor = std::make_unique<NodeExecutor>();
    });
    return *g_executor;
}

bool InitializeExecutor(const std::string& config_path) {
    GetExecutor();
    return true;
}

void ShutdownExecutor() {
    g_executor.reset();
}

} // namespace rawrxd::executor
