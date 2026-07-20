/*===========================================================================
 * SovereignRPC_Scheduler.hpp
 *
 * Distributed RPC scheduler with VRAM-aware load balancing
 *
 * Architecture:
 *   - Control Plane: gRPC (node management, health checks)
 *   - Data Plane: ZeroMQ (inference requests, <1ms overhead)
 *   - Local Fabric: Shared Memory (multi-GPU on same node)
 *
 * Scheduling Strategy:
 *   1. Format-aware routing (Q6_K requires Q6-capable node)
 *   2. VRAM-aware placement (70B Q6 needs ~42GB VRAM)
 *   3. Latency-optimized selection (closest node with capacity)
 *   4. Automatic fallback (Q6→Q5→Q4 or reject)
 *
 * Example:
 *   Request: 70B model, Q6_K
 *   Nodes:
 *     Node A: 48GB VRAM, Q4/Q5/Q6 capable, 80% loaded
 *     Node B: 24GB VRAM, Q4/Q5 capable, 20% loaded
 *   Decision: Route to Node A (only Q6-capable node)
 *===========================================================================*/

#pragma once

#include "../bridge/Deep2_Quantized.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <memory>
#include <functional>
#include <unordered_map>
#include <chrono>

namespace RawrXD {
namespace RPC {

/*===========================================================================
 * Node Capabilities
 * Broadcast by each worker node during registration
 *===========================================================================*/
struct NodeCapabilities {
    std::string nodeId;
    std::string address;
    uint32_t numGPUs;
    uint64_t totalVRAM_MB;
    uint64_t freeVRAM_MB;
    uint32_t numCPUThreads;
    std::vector<Deep2::QuantType> supportedFormats;
    std::vector<std::string> loadedModels;  // Currently loaded model hashes
    float currentLoad;  // 0.0 - 1.0 (CPU+GPU utilization)
    uint64_t tokensPerSecond;  // Current throughput
    std::chrono::steady_clock::time_point lastHeartbeat;
    bool healthy;

    // Check if node can handle specific quantization
    bool SupportsFormat(Deep2::QuantType type) const {
        for (auto fmt : supportedFormats) {
            if (fmt == type) return true;
        }
        return false;
    }

    // Estimate VRAM needed for model
    static uint64_t EstimateVRAM_MB(uint64_t modelParams, Deep2::QuantType type) {
        float bytesPerParam = 0.0f;
        switch (type) {
            case Deep2::QuantType::Q4_K_M: bytesPerParam = 0.5f; break;  // 4.5 bits
            case Deep2::QuantType::Q5_K_M: bytesPerParam = 0.625f; break; // 5.5 bits
            case Deep2::QuantType::Q6_K:   bytesPerParam = 0.75f; break;   // 6.5 bits
            case Deep2::QuantType::Q8_0:   bytesPerParam = 1.0f; break;    // 8 bits
            case Deep2::QuantType::FP16:   bytesPerParam = 2.0f; break;
            case Deep2::QuantType::FP32:   bytesPerParam = 4.0f; break;
            default: bytesPerParam = 4.0f;
        }
        // Model weights + KV cache (assume 4K context)
        uint64_t modelSize = static_cast<uint64_t>(modelParams * bytesPerParam);
        uint64_t kvCacheSize = modelParams / 25;  // Rough estimate
        return (modelSize + kvCacheSize) / (1024 * 1024);
    }

    // Check if node has enough VRAM
    bool HasEnoughVRAM(uint64_t modelParams, Deep2::QuantType type) const {
        uint64_t needed = EstimateVRAM_MB(modelParams, type);
        return freeVRAM_MB >= needed;
    }
};

/*===========================================================================
 * Scheduling Request
 *===========================================================================*/
struct InferenceRequest {
    std::string requestId;
    std::string modelHash;
    uint64_t modelParams;
    Deep2::QuantType preferredFormat;
    Deep2::QuantType minimumFormat;  // Fallback threshold
    std::vector<uint8_t> inputTokens;
    uint32_t maxTokens;
    float temperature;
    uint32_t topK;
    std::chrono::steady_clock::time_point deadline;  // Latency SLO
    uint32_t priority;  // 0 = highest (user-facing), 10 = lowest (batch)
};

/*===========================================================================
 * Inference Result
 *===========================================================================*/
struct InferenceResult {
    bool success;
    std::string errorMessage;
    std::vector<uint8_t> outputTokens;
    uint32_t tokensGenerated;
    uint64_t inferenceTimeUs;
    Deep2::QuantType executedFormat;
};

/*===========================================================================
 * Scheduling Decision
 *===========================================================================*/
struct SchedulingDecision {
    enum class Action {
        Route,      // Send to specific node
        Fallback,   // Downgrade quantization
        Reject,     // No capacity
        Queue       // Delay and retry
    };

    Action action;
    std::string targetNodeId;  // For Route
    Deep2::QuantType selectedFormat;  // For Route/Fallback
    std::string reason;  // Human-readable explanation
    uint32_t estimatedLatencyMs;
    uint32_t queuePosition;  // For Queue action
};

/*===========================================================================
 * Fallback Policy
 *===========================================================================*/
enum class FallbackPolicy {
    Reject,           // Fail if preferred format unavailable
    Downgrade,        // Try Q6→Q5→Q4
    UpgradeVRAM,      // Request node with more VRAM (if elastic)
    QueueAndWait      // Block until capacity available
};

/*===========================================================================
 * RPC Scheduler
 * Central coordinator for distributed inference
 *===========================================================================*/
class RPCScheduler {
public:
    static RPCScheduler& Instance();

    // Initialize scheduler
    void Initialize(FallbackPolicy policy = FallbackPolicy::Downgrade);

    // Node management (called by gRPC control plane)
    void RegisterNode(const NodeCapabilities& caps);
    void UpdateNode(const std::string& nodeId, const NodeCapabilities& caps);
    void RemoveNode(const std::string& nodeId);
    void NodeHeartbeat(const std::string& nodeId);

    // Core scheduling algorithm
    SchedulingDecision Schedule(const InferenceRequest& request);

    // Batch scheduling for efficiency
    std::vector<SchedulingDecision> ScheduleBatch(const std::vector<InferenceRequest>& requests);

    // Get cluster status
    struct ClusterStatus {
        uint32_t totalNodes;
        uint32_t healthyNodes;
        uint64_t totalVRAM_MB;
        uint64_t freeVRAM_MB;
        uint64_t aggregateTPS;
        std::vector<std::string> loadedModels;
    };
    ClusterStatus GetClusterStatus() const;

    // Set scheduling policy
    void SetFallbackPolicy(FallbackPolicy policy) { fallbackPolicy_ = policy; }
    FallbackPolicy GetFallbackPolicy() const { return fallbackPolicy_; }

    // Metrics
    struct SchedulerMetrics {
        uint64_t totalRequests;
        uint64_t routedRequests;
        uint64_t fallbackRequests;
        uint64_t rejectedRequests;
        uint64_t queuedRequests;
        double avgSchedulingLatencyUs;
        double avgInferenceLatencyMs;
    };
    SchedulerMetrics GetMetrics() const { return metrics_; }

private:
    RPCScheduler() = default;

    // Internal scoring function for node selection
    double ScoreNode(const NodeCapabilities& node, const InferenceRequest& request);

    // Find best node for request
    std::string FindBestNode(const InferenceRequest& request, Deep2::QuantType format);

    // Try fallback formats
    SchedulingDecision TryFallback(const InferenceRequest& request);

    // Cleanup stale nodes
    void CleanupStaleNodes();

    std::unordered_map<std::string, NodeCapabilities> nodes_;
    FallbackPolicy fallbackPolicy_ = FallbackPolicy::Downgrade;
    SchedulerMetrics metrics_ = {};
    mutable std::mutex mutex_;
};

/*===========================================================================
 * ZeroMQ Transport Layer
 * Low-latency message transport
 *===========================================================================*/
class ZeroMQTransport {
public:
    static ZeroMQTransport& Instance();

    // Initialize ZeroMQ sockets
    bool Initialize(const std::string& bindAddress);

    // Send inference request to node
    bool SendRequest(const std::string& nodeAddress, const InferenceRequest& request);

    // Receive result from node
    struct InferenceResult {
        bool success;
        std::string errorMessage;
        std::vector<uint8_t> outputTokens;
        uint32_t tokensGenerated;
        uint64_t inferenceTimeUs;
    };
    InferenceResult ReceiveResult(const std::string& nodeAddress, uint32_t timeoutMs);

    // Broadcast KV cache update (for multi-node consistency)
    bool BroadcastKVUpdate(const std::string& modelHash, uint32_t layerId,
                             const std::vector<uint8_t>& kvData);

private:
    ZeroMQTransport() = default;
    void* context_ = nullptr;
    std::unordered_map<std::string, void*> sockets_;  // node -> socket
};

/*===========================================================================
 * gRPC Control Plane
 * Structured communication for node management
 *===========================================================================*/
class GRPCControlPlane {
public:
    static GRPCControlPlane& Instance();

    // Start gRPC server (for worker nodes to connect)
    bool StartServer(const std::string& bindAddress);

    // Connect to worker node
    bool ConnectNode(const std::string& nodeAddress);

    // Send heartbeat to all nodes
    void BroadcastHeartbeat();

    // Request node to load model
    bool RequestModelLoad(const std::string& nodeId, const std::string& modelHash,
                          Deep2::QuantType format);

    // Request node to unload model
    bool RequestModelUnload(const std::string& nodeId, const std::string& modelHash);

private:
    GRPCControlPlane() = default;
};

} // namespace RPC
} // namespace RawrXD

/*===========================================================================
 * C API for Integration
 *===========================================================================*/

extern "C" {

// Initialize RPC scheduler
__declspec(dllexport)
int SovereignRPC_Init(const char* bindAddress, int fallbackPolicy);

// Register worker node
__declspec(dllexport)
int SovereignRPC_RegisterNode(const char* nodeId, const char* address,
                               uint64_t vramMB, int* supportedFormats, int numFormats);

// Schedule inference request
__declspec(dllexport)
int SovereignRPC_Schedule(const char* modelHash, uint64_t modelParams,
                          int preferredFormat, int minFormat,
                          char* outNodeId, size_t nodeIdSize,
                          int* outSelectedFormat);

// Get cluster status
__declspec(dllexport)
void SovereignRPC_GetClusterStatus(uint32_t* outTotalNodes, uint32_t* outHealthyNodes,
                                   uint64_t* outTotalVRAM, uint64_t* outFreeVRAM);

} // extern "C"
