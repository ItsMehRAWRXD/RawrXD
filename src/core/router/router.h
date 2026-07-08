// router.h
// Layer 1: Capability Router
// Pure placement logic - no knowledge of scheduling or execution internals
//
// CRITICAL INVARIANT: This layer knows NOTHING about:
//   - Scheduling internals (credits, time slices, preemption)
//   - Execution semantics (kernels, memory allocation)
//   - Policy learning or recommendations
//
// It ONLY knows: capability→backend mapping, load state, latency tracking

#pragma once

#include <cstdint>
#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <memory>

namespace rawrxd::router {

// Forward declarations - minimal dependencies
class RouterImpl;

// ═══════════════════════════════════════════════════════════════════════════════
// Core Types
// ═══════════════════════════════════════════════════════════════════════════════

using BackendId = uint32_t;
using CapabilityHash = uint64_t;

enum class BackendState : uint8_t {
    Healthy = 0,
    Degraded = 1,
    Unhealthy = 2,
    Offline = 3
};

enum class RoutingStrategy : uint8_t {
    LatencyOptimized,    // Minimize latency
    ThroughputOptimized, // Maximize throughput
    CostOptimized,       // Minimize cost
    ReliabilityOptimized // Maximize success rate
};

// ═══════════════════════════════════════════════════════════════════════════════
// Capability Token (Opaque to Router)
// ═══════════════════════════════════════════════════════════════════════════════

struct CapabilityToken {
    CapabilityHash hash;
    uint32_t permissions;
    std::chrono::steady_clock::time_point expiry;
    
    bool IsValid() const {
        return std::chrono::steady_clock::now() < expiry;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// Work Specification (Opaque to Router)
// ═══════════════════════════════════════════════════════════════════════════════

struct WorkSpec {
    std::string model_architecture;  // "llama2", "qwen2", etc.
    uint32_t estimated_tokens;
    uint32_t priority;               // 0-255, lower = higher priority
    RoutingStrategy strategy;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Backend Information
// ═══════════════════════════════════════════════════════════════════════════════

struct BackendInfo {
    BackendId id;
    std::string name;
    BackendState state;
    
    // Capabilities
    std::vector<std::string> supported_architectures;
    uint32_t max_batch_size;
    uint64_t memory_available;
    
    // Performance metrics (rolling averages)
    std::chrono::microseconds avg_latency;
    std::chrono::microseconds p99_latency;
    float success_rate;           // 0.0 - 1.0
    float current_load;           // 0.0 - 1.0
    
    // Cost metrics
    float cost_per_token;
    float cost_per_request;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Routing Decision
// ═══════════════════════════════════════════════════════════════════════════════

struct RoutingDecision {
    BackendId backend;
    std::string backend_name;
    float confidence;             // 0.0 - 1.0
    std::string reason;           // Human-readable routing rationale
    
    // Alternative backends (for fallback)
    std::vector<BackendId> alternatives;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Router Interface
// ═══════════════════════════════════════════════════════════════════════════════

class CapabilityRouter {
public:
    CapabilityRouter();
    ~CapabilityRouter();

    // Disable copy/move
    CapabilityRouter(const CapabilityRouter&) = delete;
    CapabilityRouter& operator=(const CapabilityRouter&) = delete;
    CapabilityRouter(CapabilityRouter&&) = delete;
    CapabilityRouter& operator=(CapabilityRouter&&) = delete;

    // ═══════════════════════════════════════════════════════════════════════════
    // Backend Management
    // ═══════════════════════════════════════════════════════════════════════════

    // Register a new backend
    bool RegisterBackend(const BackendInfo& info);
    
    // Unregister a backend
    void UnregisterBackend(BackendId id);
    
    // Update backend metrics (called periodically)
    void UpdateBackendMetrics(BackendId id, const BackendInfo& metrics);
    
    // Get backend info
    std::optional<BackendInfo> GetBackendInfo(BackendId id) const;
    
    // List all healthy backends
    std::vector<BackendId> ListHealthyBackends() const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Routing
    // ═══════════════════════════════════════════════════════════════════════════

    // Route work to a backend based on capability and work spec
    // Returns nullopt if no suitable backend found
    std::optional<RoutingDecision> Route(
        const CapabilityToken& cap,
        const WorkSpec& work
    );

    // Route with explicit strategy override
    std::optional<RoutingDecision> RouteWithStrategy(
        const CapabilityToken& cap,
        const WorkSpec& work,
        RoutingStrategy strategy
    );

    // Check if a capability can be satisfied
    bool CanRoute(const CapabilityToken& cap, const WorkSpec& work) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Latency Feedback
    // ═══════════════════════════════════════════════════════════════════════════

    // Report latency for a routing decision (used for future routing)
    void ReportLatency(BackendId backend, std::chrono::microseconds latency);
    
    // Report success/failure for a routing decision
    void ReportOutcome(BackendId backend, bool success);

    // ═══════════════════════════════════════════════════════════════════════════
    // Load Balancing
    // ═══════════════════════════════════════════════════════════════════════════

    // Get current load distribution across backends
    std::map<BackendId, float> GetLoadDistribution() const;
    
    // Check if backend is overloaded
    bool IsOverloaded(BackendId backend) const;
    
    // Get recommended load shift (positive = add load, negative = reduce)
    float GetRecommendedLoadShift(BackendId backend) const;

    // ═══════════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════════

    struct Statistics {
        uint64_t total_routes;
        uint64_t successful_routes;
        uint64_t failed_routes;       // No backend available
        uint64_t fallback_routes;     // Used alternative backend
        double avg_routing_time_us;
        double avg_backend_latency_ms;
    };

    Statistics GetStatistics() const;
    void ResetStatistics();

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════

    void SetDefaultStrategy(RoutingStrategy strategy);
    void SetLatencyWeight(float weight);      // 0.0 - 1.0
    void SetCostWeight(float weight);         // 0.0 - 1.0
    void SetReliabilityWeight(float weight);   // 0.0 - 1.0

private:
    std::unique_ptr<RouterImpl> impl_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Router Instance
// ═══════════════════════════════════════════════════════════════════════════════

CapabilityRouter& GetRouter();
bool InitializeRouter(const std::string& config_path);
void ShutdownRouter();

} // namespace rawrxd::router
