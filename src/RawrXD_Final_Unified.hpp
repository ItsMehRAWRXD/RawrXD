#pragma once
#ifndef RAWRXD_FINAL_UNIFIED_HPP
#define RAWRXD_FINAL_UNIFIED_HPP

// ============================================================================
// RAWRXD FINAL UNIFIED SYSTEM
// Zero-Dependency Model Loading & Streaming + Complete Infrastructure
// ============================================================================
// This is the culmination of all RawrXD development - a self-contained,
// zero-dependency system for AI model execution with full streaming support.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cmath>
#include <algorithm>
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <array>
#include <optional>
#include <variant>
#include <future>
#include <filesystem>

// ============================================================================
// PLATFORM DETECTION
// ============================================================================

#ifdef _WIN32
    #define RAWRXD_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #define RAWRXD_POSIX
    #include <unistd.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <sys/stat.h>
#endif

// ============================================================================
// VERSION INFO
// ============================================================================

#define RAWRXD_VERSION_MAJOR 7
#define RAWRXD_VERSION_MINOR 0
#define RAWRXD_VERSION_PATCH 0
#define RAWRXD_VERSION_STRING "7.0.0-FINAL"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace RawrXD {
    // Core types
    struct TensorInfo;
    struct GGUFHeader;
    struct GGUFMetadata;
    struct ModelConfig;
    struct InferenceRequest;
    struct InferenceResponse;
    struct ExecutionSnapshot;
    
    // Core systems
    class ZeroDependencyGGUFLoader;
    class StreamingModelLoader;
    class InferenceEngine;
    class ExecutionOrchestrator;
    class PersistenceLayer;
    class TelemetrySystem;
    
    // Capability system
    class ExecutionCapability;
    class TokenAuthority;
    class PolicyRouter;
    
    // Query API
    class ExecutionQueryAPI;
    class StatisticalAggregator;
}

// ============================================================================
// CONSTANTS
// ============================================================================

namespace RawrXD {
    // GGUF format constants
    constexpr uint32_t GGUF_MAGIC = 0x46554747; // "GGUF"
    constexpr uint32_t GGUF_VERSION = 3;
    
    // Architecture types
    enum class ArchitectureType : uint32_t {
        UNKNOWN = 0,
        LLAMA2 = 1,
        LLAMA3 = 2,
        MISTRAL = 3,
        QWEN2 = 4,
        PHI3 = 5,
        GEMMA = 6,
        COMMAND_R = 7,
        FALCON = 8,
        MPT = 9,
        GPT2 = 10,
        GPTNEOX = 11,
        BLOOM = 12,
        STABLELM = 13,
        STARCODER = 14
    };
    
    // GGML types
    enum class GGMLType : uint32_t {
        F32 = 0,
        F16 = 1,
        Q4_0 = 2,
        Q4_1 = 3,
        Q5_0 = 6,
        Q5_1 = 7,
        Q8_0 = 8,
        Q8_1 = 9,
        Q2_K = 10,
        Q3_K = 11,
        Q4_K = 12,
        Q5_K = 13,
        Q6_K = 14,
        Q8_K = 15,
        IQ2_XXS = 16,
        IQ2_XS = 17,
        IQ3_XXS = 18,
        IQ1_S = 19,
        IQ4_NL = 20,
        IQ3_S = 21,
        IQ2_S = 22,
        IQ4_XS = 23,
        IQ1_M = 24,
        COUNT = 25
    };
    
    // Execution modes
    enum class ExecutionMode : uint32_t {
        STRICT_LOCAL = 0,
        HYBRID_CONTROLLED = 1,
        FULLY_DISTRIBUTED = 2
    };
    
    // Node states
    enum class NodeState : uint32_t {
        PENDING = 0,
        RUNNING = 1,
        COMPLETED = 2,
        FAILED = 3,
        COLLAPSED = 4
    };
    
    // Capability types
    enum class CapabilityType : uint32_t {
        INVALID = 0,
        LOCAL_GGUF = 1,
        LOCAL_OLLAMA = 2,
        REMOTE_CLOUD = 3,
        HYBRID = 4
    };
}

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

namespace RawrXD {
    // Tensor information
    struct TensorInfo {
        std::string name;
        std::vector<uint64_t> shape;
        GGMLType type;
        uint64_t offset;
        uint64_t size;
        uint64_t size_bytes;
        bool loaded = false;
        std::vector<uint8_t> hostData;
        const void* data = nullptr;
        
        size_t GetElementCount() const {
            size_t count = 1;
            for (auto dim : shape) count *= dim;
            return count;
        }
        
        size_t GetByteSize() const {
            return size_bytes;
        }
    };
    
    // GGUF header
    struct GGUFHeader {
        uint32_t magic;
        uint32_t version;
        uint64_t tensor_count;
        uint64_t metadata_kv_count;
        uint64_t metadata_offset;
    };
    
    // GGUF metadata
    struct GGUFMetadata {
        std::string name;
        std::string architecture;
        ArchitectureType architecture_type = ArchitectureType::UNKNOWN;
        uint64_t parameterCount = 0;
        uint32_t vocabSize = 0;
        uint32_t contextLength = 0;
        uint32_t layer_count = 0;
        uint32_t embedding_dim = 0;
        uint32_t head_count = 0;
        uint32_t head_count_kv = 0;
        uint32_t feed_forward_length = 0;
        std::map<std::string, std::string> properties;
        std::vector<std::string> tokens;
        std::vector<float> token_scores;
        
        bool IsQwen() const {
            return architecture_type == ArchitectureType::QWEN2 ||
                   architecture.find("qwen") != std::string::npos;
        }
        
        bool IsLlama() const {
            return architecture_type == ArchitectureType::LLAMA2 ||
                   architecture_type == ArchitectureType::LLAMA3 ||
                   architecture.find("llama") != std::string::npos;
        }
    };
    
    // Model configuration
    struct ModelConfig {
        std::string model_path;
        std::string model_name;
        ArchitectureType arch_type = ArchitectureType::UNKNOWN;
        uint32_t max_tokens = 2048;
        float temperature = 0.7f;
        float top_p = 0.9f;
        uint32_t top_k = 40;
        float repeat_penalty = 1.1f;
        uint32_t batch_size = 512;
        uint32_t context_length = 4096;
        bool use_mmap = true;
        bool use_gpu = false;
        uint32_t gpu_layers = 0;
        ExecutionMode execution_mode = ExecutionMode::HYBRID_CONTROLLED;
    };
    
    // Inference request
    struct InferenceRequest {
        std::string model_id;
        std::string prompt;
        std::string system_prompt;
        uint32_t max_tokens = 2048;
        float temperature = 0.7f;
        float top_p = 0.9f;
        uint32_t top_k = 40;
        bool stream = false;
        std::function<void(const std::string&)> stream_callback;
        ExecutionMode mode = ExecutionMode::HYBRID_CONTROLLED;
        bool allow_remote = false;
    };
    
    // Inference response
    struct InferenceResponse {
        bool success = false;
        std::string text;
        std::string error;
        uint32_t tokens_generated = 0;
        uint32_t prompt_tokens = 0;
        uint64_t latency_ms = 0;
        ArchitectureType arch_type = ArchitectureType::UNKNOWN;
        std::string execution_path;
    };
    
    // Execution snapshot for persistence
    struct ExecutionSnapshot {
        std::string request_id;
        std::string graph_hash;
        std::string outcome_hash;
        std::string compressed_graph;
        std::string policy_snapshot;
        uint64_t timestamp;
        double quality_score;
        bool trusted;
        uint64_t latency_ms;
        bool success;
        std::string error_message;
    };
}

// ============================================================================
// ZERO-DEPENDENCY GGUF LOADER
// ============================================================================

namespace RawrXD {
    class ZeroDependencyGGUFLoader {
    public:
        ZeroDependencyGGUFLoader();
        ~ZeroDependencyGGUFLoader();
        
        // Core API
        bool Open(const std::string& filepath);
        void Close();
        bool ParseHeader();
        bool ParseMetadata();
        bool ParseTensorInfo();
        bool LoadTensorData(const std::string& tensor_name, std::vector<uint8_t>& data);
        bool LoadAllTensors(std::function<void(const std::string&, size_t, size_t)> progress = nullptr);
        
        // Memory-mapped loading
        bool OpenMMap(const std::string& filepath);
        const void* GetTensorPointer(const std::string& name) const;
        
        // Getters
        const GGUFHeader& GetHeader() const { return header_; }
        const GGUFMetadata& GetMetadata() const { return metadata_; }
        const std::vector<TensorInfo>& GetTensors() const { return tensors_; }
        const TensorInfo* GetTensor(const std::string& name) const;
        bool IsOpen() const { return is_open_; }
        uint64_t GetFileSize() const { return file_size_; }
        
        // Architecture detection
        ArchitectureType DetectArchitecture() const;
        std::string GetArchitectureName() const;
        
        // Validation
        bool ValidateChecksum();
        bool IsSupportedArchitecture() const;
        
    private:
        // File handling
        std::ifstream file_;
        std::string filepath_;
        bool is_open_ = false;
        uint64_t file_size_ = 0;
        uint64_t data_offset_ = 0;
        
        // Memory mapping
#ifdef RAWRXD_WINDOWS
        HANDLE hFile_ = INVALID_HANDLE_VALUE;
        HANDLE hMapping_ = nullptr;
#else
        int fd_ = -1;
#endif
        void* mapped_data_ = nullptr;
        size_t mapped_size_ = 0;
        
        // Parsed data
        GGUFHeader header_;
        GGUFMetadata metadata_;
        std::vector<TensorInfo> tensors_;
        std::unordered_map<std::string, size_t> tensor_map_;
        
        // Internal methods
        bool ReadData(void* buffer, size_t size);
        bool ReadValue(uint32_t& value);
        bool ReadValue(uint64_t& value);
        bool ReadString(std::string& str);
        bool ReadTensorType(GGMLType& type);
        bool Seek(uint64_t offset);
        uint64_t GetPosition() const;
        
        // Architecture mapping
        ArchitectureType MapArchitectureString(const std::string& arch) const;
        void ExtractMetadata(const std::string& key, const std::string& value);
    };
}

// ============================================================================
// STREAMING MODEL LOADER
// ============================================================================

namespace RawrXD {
    class StreamingModelLoader {
    public:
        struct LoadConfig {
            size_t max_memory_mb = 8192;  // 8GB default
            size_t chunk_size_mb = 512;   // 512MB chunks
            bool prioritize_speed = false;
            bool verify_integrity = true;
        };
        
        struct LoadProgress {
            size_t bytes_loaded;
            size_t bytes_total;
            size_t tensors_loaded;
            size_t tensors_total;
            float percentage;
            std::string current_tensor;
            std::chrono::milliseconds elapsed_ms;
        };
        
        StreamingModelLoader();
        ~StreamingModelLoader();
        
        // Streaming API
        bool BeginStreamLoad(const std::string& filepath, const LoadConfig& config);
        bool StreamNextChunk(std::function<void(const LoadProgress&)> callback = nullptr);
        bool IsStreamingComplete() const;
        void CancelStreamLoad();
        
        // Zone-based memory management
        bool AssignTensorToZone(const std::string& tensor_name, uint32_t zone_id);
        bool EvictZone(uint32_t zone_id);
        bool PinTensor(const std::string& tensor_name);
        bool UnpinTensor(const std::string& tensor_name);
        
        // Access loaded model
        std::shared_ptr<ZeroDependencyGGUFLoader> GetLoader() const { return loader_; }
        const LoadConfig& GetConfig() const { return config_; }
        
        // Statistics
        size_t GetMemoryUsage() const;
        size_t GetPinnedMemory() const;
        std::vector<std::string> GetLoadedTensors() const;
        
    private:
        std::shared_ptr<ZeroDependencyGGUFLoader> loader_;
        LoadConfig config_;
        
        // Streaming state
        std::atomic<bool> streaming_active_{false};
        std::atomic<bool> cancel_requested_{false};
        size_t current_tensor_idx_ = 0;
        std::chrono::steady_clock::time_point start_time_;
        
        // Memory zones
        struct MemoryZone {
            uint32_t id;
            size_t max_size;
            size_t current_size;
            std::vector<std::string> tensors;
            bool locked = false;
        };
        std::map<uint32_t, MemoryZone> zones_;
        std::unordered_set<std::string> pinned_tensors_;
        
        mutable std::mutex mutex_;
        
        // Internal methods
        bool LoadTensorChunk(size_t start_idx, size_t count);
        size_t CalculateOptimalChunkSize() const;
        void UpdateZoneUsage(uint32_t zone_id, size_t delta);
    };
}

// ============================================================================
// CAPABILITY TOKEN SYSTEM
// ============================================================================

namespace RawrXD {
    class ExecutionCapability {
    public:
        ExecutionCapability() = default;
        ExecutionCapability(CapabilityType type, uint64_t nonce);
        
        // Non-copyable
        ExecutionCapability(const ExecutionCapability&) = delete;
        ExecutionCapability& operator=(const ExecutionCapability&) = delete;
        
        // Movable
        ExecutionCapability(ExecutionCapability&& other) noexcept;
        ExecutionCapability& operator=(ExecutionCapability&& other) noexcept;
        
        // Validation
        bool IsValid() const { return valid_ && !expired_; }
        void Expire() { expired_ = true; }
        CapabilityType GetType() const { return type_; }
        uint64_t GetNonce() const { return nonce_; }
        
        std::string ToString() const;
        
    private:
        CapabilityType type_ = CapabilityType::INVALID;
        uint64_t nonce_ = 0;
        bool valid_ = false;
        bool expired_ = false;
    };
    
    class TokenAuthority {
    public:
        static TokenAuthority& Instance();
        
        ExecutionCapability MintCapability(CapabilityType type, const std::string& requester);
        bool RevokeCapability(uint64_t nonce);
        bool IsRevoked(uint64_t nonce) const;
        
        // Audit
        size_t GetMintCount() const;
        void ClearRevoked();
        
    private:
        TokenAuthority() = default;
        mutable std::mutex mutex_;
        std::set<uint64_t> revoked_nonces_;
        std::atomic<size_t> mint_count_{0};
    };
}

// ============================================================================
// POLICY ROUTER
// ============================================================================

namespace RawrXD {
    class PolicyRouter {
    public:
        struct RoutingDecision {
            CapabilityType capability_type;
            std::string reason;
            float confidence;
            uint64_t timestamp;
        };
        
        explicit PolicyRouter(ExecutionMode default_mode = ExecutionMode::HYBRID_CONTROLLED);
        
        RoutingDecision DecideExecutionPath(const ModelConfig& config, 
                                           bool local_available,
                                           bool remote_available);
        
        void SetDefaultMode(ExecutionMode mode) { default_mode_ = mode; }
        ExecutionMode GetDefaultMode() const { return default_mode_; }
        
        // Statistics
        size_t GetDecisionCount() const { return decision_count_; }
        std::vector<RoutingDecision> GetRecentDecisions(size_t count) const;
        
    private:
        ExecutionMode default_mode_;
        std::atomic<size_t> decision_count_{0};
        mutable std::mutex mutex_;
        std::vector<RoutingDecision> recent_decisions_;
        
        void RecordDecision(const RoutingDecision& decision);
    };
}

// ============================================================================
// INFERENCE ENGINE
// ============================================================================

namespace RawrXD {
    class InferenceEngine {
    public:
        struct EngineStats {
            uint64_t total_requests = 0;
            uint64_t successful_requests = 0;
            uint64_t failed_requests = 0;
            uint64_t total_tokens_generated = 0;
            double avg_latency_ms = 0.0;
            double avg_tokens_per_second = 0.0;
        };
        
        InferenceEngine();
        ~InferenceEngine();
        
        // Lifecycle
        bool Initialize(const ModelConfig& config);
        void Shutdown();
        bool IsInitialized() const { return initialized_; }
        
        // Inference
        InferenceResponse Generate(const InferenceRequest& request);
        bool GenerateStreaming(const InferenceRequest& request);
        
        // Model management
        bool LoadModel(const std::string& path);
        void UnloadModel();
        bool IsModelLoaded() const { return model_loaded_; }
        const ModelConfig& GetConfig() const { return config_; }
        
        // Statistics
        EngineStats GetStats() const { return stats_; }
        void ResetStats();
        
        // Tokenization
        std::vector<int32_t> Tokenize(const std::string& text);
        std::string Detokenize(const std::vector<int32_t>& tokens);
        
    private:
        ModelConfig config_;
        std::atomic<bool> initialized_{false};
        std::atomic<bool> model_loaded_{false};
        EngineStats stats_;
        mutable std::mutex mutex_;
        
        // Model data
        std::shared_ptr<ZeroDependencyGGUFLoader> loader_;
        std::shared_ptr<StreamingModelLoader> streamer_;
        
        // Internal methods
        InferenceResponse ExecuteLocal(const InferenceRequest& request);
        InferenceResponse ExecuteRemote(const InferenceRequest& request);
        void UpdateStats(const InferenceResponse& response);
    };
}

// ============================================================================
// PERSISTENCE LAYER
// ============================================================================

namespace RawrXD {
    class PersistenceLayer {
    public:
        struct PersistenceConfig {
            std::string storage_path = "./rawrxd_persistence";
            size_t max_snapshots = 10000;
            size_t retention_days = 30;
            bool compress_data = true;
            bool encrypt_sensitive = false;
        };
        
        struct HistoricalAnalytics {
            uint64_t total_executions;
            uint64_t unique_patterns;
            double avg_latency_trend;
            double success_rate_trend;
            double backend_drift;
            std::vector<std::string> regression_alerts;
        };
        
        PersistenceLayer();
        ~PersistenceLayer();
        
        bool Initialize(const PersistenceConfig& config);
        void Shutdown();
        
        // Core API
        bool PersistExecution(const ExecutionSnapshot& snapshot);
        std::vector<ExecutionSnapshot> LoadExecutionHistory(size_t limit = 100, 
                                                             const std::string& filter = "");
        std::vector<ExecutionSnapshot> FindSimilarExecutions(const std::string& request_id, 
                                                               double threshold = 0.9);
        
        // Analytics
        HistoricalAnalytics ComputeAnalytics(size_t window_days = 7);
        std::vector<std::string> DetectRegressions(size_t lookback_days = 1);
        std::string ExportPolicyEvolution(size_t days = 30);
        
        // Maintenance
        bool PruneOldData(size_t days);
        bool Vacuum();
        size_t GetStorageSize() const;
        
    private:
        PersistenceConfig config_;
        std::atomic<bool> initialized_{false};
        mutable std::mutex mutex_;
        
        // Storage
        std::vector<ExecutionSnapshot> snapshots_;
        std::unordered_map<std::string, size_t> snapshot_index_;
        
        // Internal methods
        bool SaveToDisk();
        bool LoadFromDisk();
        std::string GenerateSnapshotId();
        double CalculateSimilarity(const ExecutionSnapshot& a, const ExecutionSnapshot& b);
    };
}

// ============================================================================
// TELEMETRY SYSTEM
// ============================================================================

namespace RawrXD {
    class TelemetrySystem {
    public:
        struct TelemetryEvent {
            std::string event_type;
            std::string event_data;
            uint64_t timestamp;
            std::string session_id;
        };
        
        struct SystemMetrics {
            double cpu_usage;
            double memory_usage_mb;
            double gpu_usage;
            uint64_t tokens_per_second;
            uint64_t active_requests;
            uint64_t queued_requests;
        };
        
        static TelemetrySystem& Instance();
        
        bool Initialize(const std::string& endpoint = "");
        void Shutdown();
        
        // Event logging
        void LogEvent(const std::string& type, const std::string& data);
        void LogInference(const InferenceRequest& request, const InferenceResponse& response);
        void LogError(const std::string& component, const std::string& error);
        
        // Metrics
        void UpdateMetrics(const SystemMetrics& metrics);
        SystemMetrics GetCurrentMetrics() const;
        
        // Export
        std::string ExportJSON() const;
        bool FlushToDisk(const std::string& path);
        
    private:
        TelemetrySystem() = default;
        std::atomic<bool> initialized_{false};
        mutable std::mutex mutex_;
        
        std::vector<TelemetryEvent> events_;
        SystemMetrics current_metrics_;
        std::string session_id_;
        
        std::string GenerateSessionId();
    };
}

// ============================================================================
// EXECUTION ORCHESTRATOR
// ============================================================================

namespace RawrXD {
    class ExecutionOrchestrator {
    public:
        struct OrchestratorConfig {
            size_t max_concurrent_requests = 4;
            size_t max_queue_depth = 100;
            uint64_t request_timeout_ms = 300000;  // 5 minutes
            bool enable_persistence = true;
            bool enable_telemetry = true;
            bool enable_auto_optimization = true;
        };
        
        static ExecutionOrchestrator& Instance();
        
        bool Initialize(const OrchestratorConfig& config);
        void Shutdown();
        
        // Main API
        InferenceResponse Execute(const InferenceRequest& request);
        bool ExecuteAsync(const InferenceRequest& request, 
                         std::function<void(const InferenceResponse&)> callback);
        
        // Model management
        bool RegisterModel(const std::string& model_id, const ModelConfig& config);
        bool UnregisterModel(const std::string& model_id);
        std::vector<std::string> GetRegisteredModels() const;
        
        // System control
        void PauseExecution();
        void ResumeExecution();
        bool IsPaused() const { return paused_; }
        
        // Statistics
        size_t GetActiveRequestCount() const;
        size_t GetQueuedRequestCount() const;
        uint64_t GetTotalExecutions() const { return total_executions_; }
        
    private:
        ExecutionOrchestrator() = default;
        
        OrchestratorConfig config_;
        std::atomic<bool> initialized_{false};
        std::atomic<bool> paused_{false};
        std::atomic<uint64_t> total_executions_{0};
        
        // Subsystems
        std::unique_ptr<InferenceEngine> engine_;
        std::unique_ptr<PolicyRouter> router_;
        std::unique_ptr<PersistenceLayer> persistence_;
        
        // Request queue
        struct QueuedRequest {
            InferenceRequest request;
            std::function<void(const InferenceResponse&)> callback;
            uint64_t enqueue_time;
        };
        std::queue<QueuedRequest> request_queue_;
        mutable std::mutex queue_mutex_;
        std::condition_variable queue_cv_;
        
        // Worker threads
        std::vector<std::thread> workers_;
        std::atomic<bool> shutdown_{false};
        
        // Registered models
        std::unordered_map<std::string, ModelConfig> registered_models_;
        mutable std::mutex models_mutex_;
        
        // Internal methods
        void WorkerLoop();
        InferenceResponse ProcessRequest(const InferenceRequest& request);
        bool TryEnqueue(const InferenceRequest& request, 
                       std::function<void(const InferenceResponse&)> callback);
    };
}

// ============================================================================
// QUERY API
// ============================================================================

namespace RawrXD {
    class ExecutionQueryAPI {
    public:
        struct PathAnalysisResult {
            std::string path_signature;
            uint64_t execution_count;
            double avg_latency_ms;
            double p95_latency_ms;
            double failure_rate;
        };
        
        struct AnomalyResult {
            std::string node_id;
            std::string anomaly_type;
            double severity;
            std::string description;
        };
        
        static ExecutionQueryAPI& Instance();
        
        // Query methods
        std::vector<PathAnalysisResult> GetHotPaths(int top_n = 10);
        std::vector<PathAnalysisResult> GetColdPaths(int bottom_n = 10);
        std::vector<AnomalyResult> DetectAnomalies(double threshold = 0.95);
        std::vector<std::string> GetBottlenecks(double threshold_ms = 1000.0);
        
        // Export
        std::string ExportStatistics() const;
        std::string ExportExecutionGraph(const std::string& request_id);
        
    private:
        ExecutionQueryAPI() = default;
    };
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

namespace RawrXD {
    // Initialize the entire RawrXD system
    bool InitializeRawrXD(const ExecutionOrchestrator::OrchestratorConfig& config = {});
    
    // Shutdown the system
    void ShutdownRawrXD();
    
    // Quick inference API
    InferenceResponse QuickInfer(const std::string& model_path, 
                                  const std::string& prompt,
                                  const ModelConfig& overrides = {});
    
    // Get version info
    std::string GetVersionString();
    uint32_t GetVersionMajor();
    uint32_t GetVersionMinor();
    uint32_t GetVersionPatch();
}

#endif // RAWRXD_FINAL_UNIFIED_HPP
