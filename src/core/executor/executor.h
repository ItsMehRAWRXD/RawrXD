// executor.h
// Layer 2: Node Executor
// Pure execution engine - no knowledge of scheduling, routing, or policy
//
// CRITICAL INVARIANT: This layer knows NOTHING about:
//   - Scheduling (credits, time slices, preemption)
//   - Routing (backend selection, load balancing)
//   - Policy learning or recommendations
//
// It ONLY knows: kernel dispatch, memory allocation, result production, checkpointing

#pragma once

#include <cstdint>
#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd::executor {

// Forward declarations
class ExecutorImpl;

// ═══════════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════════

using NodeId = uint64_t;
using KernelId = uint32_t;

enum class ExecutionState : uint8_t {
    Pending = 0,
    Running = 1,
    Suspended = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5
};

enum class KernelType : uint8_t {
    Inference = 0,
    Embedding = 1,
    Attention = 2,
    MatMul = 3,
    Custom = 255
};

// ═══════════════════════════════════════════════════════════════════════════════
// Memory Management
// ═══════════════════════════════════════════════════════════════════════════════

struct MemoryAllocation {
    void* ptr;
    size_t size;
    uint32_t alignment;
    bool device_memory;  // GPU vs CPU
};

struct MemoryPool {
    size_t total_allocated;
    size_t peak_allocated;
    size_t available;
    size_t pool_size;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Node Specification
// ═══════════════════════════════════════════════════════════════════════════════

struct NodeSpec {
    NodeId id;
    KernelType kernel_type;
    KernelId kernel_id;
    
    // Input/output buffers
    std::vector<MemoryAllocation> inputs;
    std::vector<MemoryAllocation> outputs;
    
    // Execution parameters
    uint32_t batch_size;
    uint32_t sequence_length;
    uint32_t hidden_dim;
    
    // Checkpoint configuration
    bool checkpoint_enabled;
    uint32_t checkpoint_interval_ms;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Execution Result
// ═══════════════════════════════════════════════════════════════════════════════

struct ExecutionResult {
    NodeId node_id;
    ExecutionState state;
    
    // Timing
    std::chrono::microseconds execution_time;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
    // Resource usage
    size_t memory_used;
    size_t memory_peak;
    uint32_t compute_units_used;
    
    // Output
    bool success;
    std::string error_message;
    std::vector<MemoryAllocation> outputs;
    
    // Checkpoint info
    std::optional<std::string> checkpoint_path;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Checkpoint State
// ═══════════════════════════════════════════════════════════════════════════════

struct Checkpoint {
    NodeId node_id;
    std::string path;
    std::chrono::steady_clock::time_point timestamp;
    ExecutionState state;
    size_t memory_size;
    
    bool IsValid() const;
    bool Restore(NodeExecutor& executor);
};

// ═══════════════════════════════════════════════════════════════════════════════
// Progress Callback
// ═══════════════════════════════════════════════════════════════════════════════

using ProgressCallback = std::function<void(NodeId, float progress)>;
using CompletionCallback = std::function<void(const ExecutionResult&)>;

// ═══════════════════════════════════════════════════════════════════════════════
// Executor Interface
// ═══════════════════════════════════════════════════════════════════════════════

class NodeExecutor {
public:
    NodeExecutor();
    ~NodeExecutor();

    // Disable copy/move
    NodeExecutor(const NodeExecutor&) = delete;
    NodeExecutor& operator=(const NodeExecutor&) = delete;
    NodeExecutor(NodeExecutor&&) = delete;
    NodeExecutor& operator=(NodeExecutor&&) = delete;

    // ═══════════════════════════════════════════════════════════════════════════
    // Memory Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Allocate memory for execution
    std::optional<MemoryAllocation> AllocateMemory(
        size_t size,
        uint32_t alignment = 64,
        bool device_memory = false
    );

    // Free allocated memory
    void FreeMemory(const MemoryAllocation& alloc);

    // Get memory pool statistics
    MemoryPool GetMemoryPool() const;

    // Reset memory pool (free all allocations)
    void ResetMemoryPool();

    // ═══════════════════════════════════════════════════════════════════════════
    // Kernel Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Register a kernel for execution
    bool RegisterKernel(KernelId id, KernelType type, std::function<void(void*)> kernel_func);

    // Unregister a kernel
    void UnregisterKernel(KernelId id);

    // Check if kernel is registered
    bool IsKernelRegistered(KernelId id) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════════

    // Execute a node specification
    // Returns immediately with a future-like handle (poll with GetResult)
    bool Execute(const NodeSpec& spec);

    // Execute with callbacks
    bool ExecuteAsync(
        const NodeSpec& spec,
        ProgressCallback progress_cb,
        CompletionCallback completion_cb
    );

    // Get execution result (non-blocking)
    std::optional<ExecutionResult> GetResult(NodeId id) const;

    // Wait for execution to complete (blocking)
    std::optional<ExecutionResult> WaitForResult(NodeId id, std::chrono::milliseconds timeout);

    // Cancel execution
    bool Cancel(NodeId id);

    // Get current execution state
    ExecutionState GetState(NodeId id) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Checkpointing
    // ═══════════════════════════════════════════════════════════════════════════

    // Create a checkpoint for a running node
    std::optional<Checkpoint> Checkpoint(const NodeId& id, const std::string& path);

    // Restore from checkpoint
    bool RestoreFromCheckpoint(const Checkpoint& checkpoint);

    // List available checkpoints
    std::vector<Checkpoint> ListCheckpoints(NodeId id) const;

    // Delete checkpoint
    void DeleteCheckpoint(const Checkpoint& checkpoint);

    // ═══════════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════════

    struct Statistics {
        uint64_t total_executions;
        uint64_t successful_executions;
        uint64_t failed_executions;
        uint64_t cancelled_executions;
        
        double avg_execution_time_ms;
        double p99_execution_time_ms;
        
        size_t total_memory_allocated;
        size_t peak_memory_used;
        
        uint64_t total_checkpoints_created;
        uint64_t total_checkpoints_restored;
    };

    Statistics GetStatistics() const;
    void ResetStatistics();

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════

    void SetMemoryPoolSize(size_t size);
    void SetMaxConcurrentExecutions(uint32_t max);
    void SetCheckpointDirectory(const std::string& path);

private:
    std::unique_ptr<ExecutorImpl> impl_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Executor Instance
// ═══════════════════════════════════════════════════════════════════════════════

NodeExecutor& GetExecutor();
bool InitializeExecutor(const std::string& config_path);
void ShutdownExecutor();

} // namespace rawrxd::executor
