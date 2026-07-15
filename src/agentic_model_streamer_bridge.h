// ============================================================================
// agentic_model_streamer_bridge.h
// ============================================================================
// Bridges AgenticEngine with StreamingGGUFLoader for unified model management.
// Provides agentic control over model loading, streaming, and inference.
//
// Copyright (c) 2025-2026 RawrXD Project
// ============================================================================

#pragma once

#include "agentic_engine.h"
#include "streaming_gguf_loader.h"
#include "RawrXD_Interfaces.h"
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

namespace RawrXD {
namespace Agentic {

// Forward declarations
class StreamingModelInferenceEngine;

// ============================================================================
// Model Load Request - Agentic task for model operations
// ============================================================================
struct ModelLoadRequest {
    std::string modelPath;
    std::string priority;           // "critical", "high", "normal", "low"
    uint64_t maxMemoryMB;           // Memory budget for this model
    bool enableStreaming;           // Use streaming loader vs full load
    bool preloadZones;              // Preload tensor zones
    std::vector<std::string> requiredZones; // Specific zones to load first
    std::function<void(bool success, const std::string& error)> callback;
    
    // Agentic context
    std::string taskId;
    std::string agentId;
    std::chrono::steady_clock::time_point requestTime;
};

// ============================================================================
// Model Streamer Status - Real-time model loading status
// ============================================================================
struct ModelStreamerStatus {
    bool isLoading = false;
    bool isLoaded = false;
    std::string currentModelPath;
    std::string currentOperation;   // "parsing_header", "loading_metadata", "building_index", 
                                    // "loading_zones", "ready", "error"
    float progressPercent = 0.0f;   // 0-100
    uint64_t bytesLoaded = 0;
    uint64_t totalBytes = 0;
    uint64_t memoryUsedMB = 0;
    uint64_t memoryBudgetMB = 0;
    std::vector<std::string> loadedZones;
    std::string lastError;
    
    // Agentic metrics
    int activeInferenceCount = 0;
    float avgInferenceTimeMs = 0.0f;
    float tokensPerSecond = 0.0f;
};

// ============================================================================
// Agentic Model Streamer Bridge
// ============================================================================
// Connects AgenticEngine with StreamingGGUFLoader to provide:
// - Agentic-controlled model loading with priorities
// - Streaming tensor zone management
// - Memory-aware loading with budgets
// - Async model operations with callbacks
// - Integration with agentic task planning
// ============================================================================
class AgenticModelStreamerBridge {
public:
    AgenticModelStreamerBridge();
    ~AgenticModelStreamerBridge();

    // Initialize the bridge with an agentic engine instance
    bool Initialize(AgenticEngine* engine);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // --------------------------------------------------------------------
    // Model Loading API (Agentic-controlled)
    // --------------------------------------------------------------------
    
    // Queue a model load request (async, returns task ID)
    std::string QueueModelLoad(const ModelLoadRequest& request);
    
    // Load model synchronously (blocking)
    bool LoadModelSync(const std::string& modelPath, uint64_t maxMemoryMB = 8192);
    
    // Unload current model
    void UnloadModel();
    
    // Check if model is loaded
    bool IsModelLoaded() const;
    
    // Get current model info
    std::string GetCurrentModelPath() const;
    GGUFMetadata GetCurrentModelMetadata() const;

    // --------------------------------------------------------------------
    // Streaming Zone Management
    // --------------------------------------------------------------------
    
    // Load specific tensor zones on demand
    bool LoadZone(const std::string& zoneName, uint64_t maxMemoryMB = 512);
    bool UnloadZone(const std::string& zoneName);
    bool IsZoneLoaded(const std::string& zoneName) const;
    std::vector<std::string> GetLoadedZones() const;
    
    // Preload zones for upcoming inference
    void PreloadZonesForInference(const std::vector<std::string>& zoneNames);

    // --------------------------------------------------------------------
    // Status & Monitoring
    // --------------------------------------------------------------------
    
    ModelStreamerStatus GetStatus() const;
    
    // Register callback for status updates
    void SetStatusCallback(std::function<void(const ModelStreamerStatus&)> callback);

    // --------------------------------------------------------------------
    // Agentic Integration
    // --------------------------------------------------------------------
    
    // Get the streaming inference engine (for agentic use)
    std::shared_ptr<InferenceEngine> GetInferenceEngine();
    
    // Set the inference engine for agentic tasks
    void SetInferenceEngine(std::shared_ptr<InferenceEngine> engine);

    // Execute agentic task with model context
    std::string ExecuteAgenticTask(const std::string& task, const std::string& context);

    // --------------------------------------------------------------------
    // Memory Management
    // --------------------------------------------------------------------
    
    // Set memory budget for model operations
    void SetMemoryBudget(uint64_t maxMemoryMB);
    uint64_t GetMemoryBudget() const { return m_memoryBudgetMB; }
    
    // Get current memory usage
    uint64_t GetCurrentMemoryUsageMB() const;
    
    // Emergency memory cleanup
    void EmergencyMemoryCleanup();

private:
    // --------------------------------------------------------------------
    // Internal Implementation
    // --------------------------------------------------------------------
    
    // Background loading thread
    void LoadingThreadFunc();
    
    // Process a single load request
    bool ProcessLoadRequest(const ModelLoadRequest& request);
    
    // Update loading progress
    void UpdateProgress(const std::string& operation, float percent);
    
    // Notify status callbacks
    void NotifyStatusUpdate();

private:
    // Core components
    AgenticEngine* m_agenticEngine = nullptr;
    std::unique_ptr<StreamingGGUFLoader> m_streamingLoader;
    std::shared_ptr<InferenceEngine> m_inferenceEngine;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdown{false};
    ModelStreamerStatus m_status;
    mutable std::mutex m_statusMutex;
    
    // Loading queue
    std::queue<ModelLoadRequest> m_loadQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    std::thread m_loadingThread;
    
    // Memory management
    uint64_t m_memoryBudgetMB = 8192; // 8GB default
    std::atomic<uint64_t> m_currentMemoryMB{0};
    
    // Callbacks
    std::function<void(const ModelStreamerStatus&)> m_statusCallback;
    
    // Current model
    std::string m_currentModelPath;
    GGUFMetadata m_currentMetadata;
    mutable std::mutex m_modelMutex;
};

// ============================================================================
// Streaming Model Inference Engine
// ============================================================================
// InferenceEngine implementation that uses StreamingGGUFLoader for
// memory-efficient model inference with zone-based tensor loading.
// ============================================================================
class StreamingModelInferenceEngine : public InferenceEngine {
public:
    explicit StreamingModelInferenceEngine(AgenticModelStreamerBridge* bridge);
    ~StreamingModelInferenceEngine() override;

    // InferenceEngine interface implementation
    bool LoadModel(const std::string& model_path) override;
    bool IsModelLoaded() const override;
    
    std::vector<int32_t> Tokenize(const std::string& text) override;
    std::string Detokenize(const std::vector<int32_t>& tokens) override;
    
    std::vector<int32_t> Generate(const std::vector<int32_t>& input_tokens, int max_tokens = 100) override;
    std::vector<float> Eval(const std::vector<int32_t>& input_tokens) override;
    
    void GenerateStreaming(
        const std::vector<int32_t>& input_tokens,
        int max_tokens,
        std::function<void(const std::string&)> token_callback,
        std::function<void()> complete_callback,
        std::function<void(int32_t)> token_id_callback = nullptr) override;

    int GetVocabSize() const override;
    int GetEmbeddingDim() const override;
    int GetNumLayers() const override;
    int GetNumHeads() const override;

    void SetMaxMode(bool enabled) override;
    void SetDeepThinking(bool enabled) override;
    void SetDeepResearch(bool enabled) override;
    bool IsMaxMode() const override;
    bool IsDeepThinking() const override;
    bool IsDeepResearch() const override;

    size_t GetMemoryUsage() const override;
    void ClearCache() override;

    const char* GetEngineName() const override { return "StreamingModelInference"; }

    // Streaming-specific methods
    bool EnsureZonesLoaded(const std::vector<std::string>& zoneNames);
    void SetZoneCachePolicy(const std::string& policy); // "lru", "prefetch", "on_demand"

private:
    AgenticModelStreamerBridge* m_bridge = nullptr;
    std::atomic<bool> m_modelLoaded{false};
    std::atomic<bool> m_maxMode{false};
    std::atomic<bool> m_deepThinking{false};
    std::atomic<bool> m_deepResearch{false};
    
    // Zone cache management
    std::vector<std::string> m_zoneCache;
    std::mutex m_cacheMutex;
    std::string m_cachePolicy = "lru";
};

// ============================================================================
// Global Access
// ============================================================================
// Get the global bridge instance (singleton pattern)
AgenticModelStreamerBridge* GetGlobalAgenticModelStreamer();
void SetGlobalAgenticModelStreamer(AgenticModelStreamerBridge* bridge);

} // namespace Agentic
} // namespace RawrXD
