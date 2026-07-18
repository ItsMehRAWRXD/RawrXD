// ============================================================================
// InferenceRuntimeGGMLBridge.hpp
// Bridge between distributed InferenceRuntime and actual GGML backend
// ============================================================================
// This is the critical integration layer that connects:
//   - Distributed RPC layer (InferenceRuntime)
//   - Real GGML inference backend (GGMLBackend)
//
// VAL-018: Distributed Inference Pipeline
// Evidence: request.json -> runtime.log -> stream.log -> completion.json
//
// Copyright (c) 2026 RawrXD Team
// ============================================================================

#pragma once

#include "../distributed/InferenceRuntime.hpp"
#include "../inference/GGMLBackend.h"
#include <memory>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace Integration {

// ============================================================================
// Bridge Configuration
// ============================================================================

struct BridgeConfig {
    // GGML backend settings
    Inference::GGMLBackendConfig ggmlConfig;
    
    // Bridge behavior
    bool enableStreaming = true;
    bool enableMetrics = true;
    uint32_t maxConcurrentInferences = 4;
    uint32_t tokenBufferSize = 1024;
    
    // Paths
    std::string modelPath;
    std::string validationOutputDir = "validation/val-018";
};

// ============================================================================
// Inference Metrics (for VAL-018 evidence)
// ============================================================================

struct InferenceMetrics {
    uint64_t requestId;
    
    // Timing (microseconds)
    uint64_t enqueueTimeUs;
    uint64_t dispatchTimeUs;
    uint64_t firstTokenTimeUs;
    uint64_t completionTimeUs;
    
    // Counts
    uint32_t tokensGenerated;
    uint32_t tokensPerSecond;
    uint64_t bytesTransferred;
    
    // Status
    bool success;
    std::string errorMessage;
    
    // Serialization for evidence
    std::string ToJson() const;
};

// ============================================================================
// GGML Bridge
// ============================================================================

class InferenceRuntimeGGMLBridge {
public:
    explicit InferenceRuntimeGGMLBridge(const BridgeConfig& config);
    ~InferenceRuntimeGGMLBridge();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Core integration: Connect runtime to backend
    void AttachToRuntime(Distributed::InferenceRuntime* runtime);
    void DetachFromRuntime();
    
    // Model management
    bool LoadModel(const std::string& path);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Statistics
    size_t GetCompletedRequestCount() const { return completedRequests_.load(); }
    size_t GetFailedRequestCount() const { return failedRequests_.load(); }
    InferenceMetrics GetLastMetrics() const;
    
    // VAL-018: Export evidence
    bool ExportTrace(const std::string& requestId);
    std::vector<InferenceMetrics> GetAllMetrics() const;

private:
    BridgeConfig config_;
    std::atomic<bool> running_{false};
    
    // Components
    Distributed::InferenceRuntime* runtime_{nullptr};
    std::unique_ptr<Inference::GGMLBackend> backend_;
    
    // Request handling
    void OnRequestSubmitted(uint64_t requestId);
    void OnTokenGenerated(uint64_t requestId, uint32_t token);
    void OnRequestCompleted(uint64_t requestId, const std::vector<uint32_t>& tokens);
    void OnRequestFailed(uint64_t requestId, const std::string& error);
    
    // Execution
    void ExecuteInference(std::shared_ptr<Distributed::InferenceRequest> request);
    std::thread workerThread_;
    void WorkerLoop();
    
    // Metrics
    mutable std::mutex metricsMutex_;
    std::vector<InferenceMetrics> metrics_;
    InferenceMetrics currentMetrics_;
    std::atomic<uint64_t> completedRequests_{0};
    std::atomic<uint64_t> failedRequests_{0};
    
    // Validation output
    void WriteRequestLog(const Distributed::InferenceRequest& request);
    void WriteTokenLog(uint64_t requestId, uint32_t token, uint32_t tokenIndex);
    void WriteCompletionLog(uint64_t requestId, const std::vector<uint32_t>& tokens);
};

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<InferenceRuntimeGGMLBridge> CreateBridge(
    const BridgeConfig& config = BridgeConfig{});

} // namespace Integration
} // namespace RawrXD
