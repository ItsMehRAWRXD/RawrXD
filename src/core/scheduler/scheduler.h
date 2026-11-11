// scheduler.h
// Layer 0: Credit-Based Scheduler
// Pure time/credit allocator - no knowledge of execution semantics
//
// CRITICAL INVARIANT: This layer knows NOTHING about:
//   - Model types or architectures
//   - Routing policies or backend selection
//   - Execution internals or kernels
//   - Policy recommendations or learning
//
// It ONLY knows: token budgets, latency SLOs, queue depths, time slices

#pragma once

#include <cstdint>
#include <chrono>
#include <optional>
#include <string>

namespace rawrxd::scheduler {

// Forward declarations - minimal dependencies
class SchedulerImpl;

// ═══════════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════════

enum class NodeType : uint8_t {
    Inference,      // Standard model inference
    Embedding,      // Embedding generation
    Tokenization,   // Text tokenization
    Detokenization, // Token detokenization
    Scheduling,     // Meta: scheduler overhead
    Unknown = 255
};

enum class Priority : uint8_t {
    Critical = 0,   // User-facing, blocking
    High = 1,     // Important background
    Normal = 2,   // Standard work
    Low = 3,      // Best-effort
    Background = 4 // Deferred work
};

using NodeId = uint64_t;
using TokenCredits = uint32_t;
using TimeSlice = std::chrono::microseconds;

// ═══════════════════════════════════════════════════════════════════════════════
// Credit Allocation
// ═══════════════════════════════════════════════════════════════════════════════

struct CreditAllocation {
    TokenCredits granted;
    TokenCredits reserved;      // Guaranteed minimum
    TokenCredits burst;         // Temporary overage allowed
    std::chrono::milliseconds replenish_interval;
    bool throttled;             // True if over budget
};

struct TimeAllocation {
    TimeSlice granted;
    std::chrono::steady_clock::time_point deadline;
    bool preemptible;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Queue State
// ═══════════════════════════════════════════════════════════════════════════════

struct QueueMetrics {
    size_t depth;
    size_t max_depth;
    std::chrono::microseconds avg_wait_time;
    std::chrono::microseconds p99_wait_time;
    float utilization;  // 0.0 - 1.0
};

// ═══════════════════════════════════════════════════════════════════════════════
// Scheduler Interface
// ═══════════════════════════════════════════════════════════════════════════════

class CreditBasedScheduler {
public:
    CreditBasedScheduler();
    ~CreditBasedScheduler();

    // Disable copy/move - scheduler is a singleton resource
    CreditBasedScheduler(const CreditBasedScheduler&) = delete;
    CreditBasedScheduler& operator=(const CreditBasedScheduler&) = delete;
    CreditBasedScheduler(CreditBasedScheduler&&) = delete;
    CreditBasedScheduler& operator=(CreditBasedScheduler&&) = delete;

    // ═══════════════════════════════════════════════════════════════════════════
    // Credit Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Allocate credits for a node execution
    // Returns nullopt if no credits available (backpressure)
    std::optional<CreditAllocation> AllocateCredits(
        NodeType type,
        Priority prio,
        TokenCredits requested
    );

    // Replenish credits (called periodically)
    void ReplenishCredits(NodeType type, TokenCredits amount);

    // Return unused credits
    void ReturnCredits(NodeType type, TokenCredits amount);

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Allocate a time slice for execution
    // Returns nullopt if scheduler is saturated
    std::optional<TimeAllocation> AllocateTimeSlice(
        NodeId id,
        Priority prio,
        TimeSlice requested
    );

    // Check if current execution should be preempted
    // Returns true if candidate should preempt current
    bool ShouldPreempt(NodeId current, NodeId candidate);

    // Yield remaining time slice
    void YieldTimeSlice(NodeId id);

    // ═══════════════════════════════════════════════════════════════════════════
    // Queue Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Enqueue work item
    bool Enqueue(NodeId id, NodeType type, Priority prio);

    // Dequeue next work item (returns nullopt if empty)
    std::optional<NodeId> Dequeue();

    // Peek at next item without dequeuing
    std::optional<NodeId> Peek() const;

    // Get queue metrics for a node type
    QueueMetrics GetQueueMetrics(NodeType type) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // SLO Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Set latency SLO for a node type
    void SetLatencySLO(NodeType type, std::chrono::milliseconds target);

    // Check if SLO is being met
    bool IsSLOMet(NodeType type) const;

    // Get current latency for a node type
    std::chrono::microseconds GetCurrentLatency(NodeType type) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Backpressure Signals
    // ═══════════════════════════════════════════════════════════════════════════

    // Check if scheduler is under pressure
    bool IsUnderPressure() const;

    // Get pressure level (0.0 = idle, 1.0 = saturated)
    float GetPressureLevel() const;

    // Get recommended throttle rate (0.0 = full speed, 1.0 = stop)
    float GetRecommendedThrottle() const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════════

    struct Statistics {
        uint64_t total_allocations;
        uint64_t total_rejections;      // Backpressure
        uint64_t total_preemptions;
        uint64_t total_yields;
        double avg_queue_depth;
        double avg_latency_ms;
        double p99_latency_ms;
    };

    Statistics GetStatistics() const;
    void ResetStatistics();

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════

    void SetMaxQueueDepth(NodeType type, size_t max_depth);
    void SetCreditLimit(NodeType type, TokenCredits limit);
    void SetTimeSliceLimit(NodeType type, TimeSlice limit);

private:
    std::unique_ptr<SchedulerImpl> impl_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Scheduler Instance
// ═══════════════════════════════════════════════════════════════════════════════

// Returns the singleton scheduler instance
// Thread-safe after first call
CreditBasedScheduler& GetScheduler();

// Initialize scheduler with configuration
// Must be called before first use
bool InitializeScheduler(const std::string& config_path);

// Shutdown scheduler gracefully
void ShutdownScheduler();

} // namespace rawrxd::scheduler
