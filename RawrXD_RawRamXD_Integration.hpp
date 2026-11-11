// =============================================================================
// RawrXD_RawRamXD_Integration.hpp - Integration Layer
// =============================================================================

#ifndef RAWRXD_RAWRAMXD_INTEGRATION_HPP
#define RAWRXD_RAWRAMXD_INTEGRATION_HPP

#include "RawRamXD.hpp"
#include "RawRamXD_Policy.hpp"
#include "RawRamXD_Telemetry.hpp"
#include <string>
#include <vector>
#include <functional>

namespace rawrxd {

// =============================================================================
// Tensor Types for RawrXD
// =============================================================================

enum class TensorType {
    MODEL_WEIGHTS = 0,      // Persistent model parameters
    KV_CACHE_KEY = 1,       // Key cache per layer
    KV_CACHE_VALUE = 2,     // Value cache per layer
    ATTENTION_OUTPUT = 3,   // Attention computation output
    FEEDFORWARD_INTERMEDIATE = 4,  // FFN intermediate activations
    NORM_OUTPUT = 5,        // Layer normalization output
    LOGITS = 6,           // Final output logits
    EMBEDDING = 7,        // Token embeddings
    WORKSPACE = 8         // Temporary workspace
};

// =============================================================================
// RawrXD Tensor Handle - Wraps RawRamXD
// =============================================================================

class RawrXDTensor {
public:
    RawrXDTensor() = default;
    RawrXDTensor(rawramxd::Handle handle, TensorType type, 
                 const std::string& name, size_t size);
    ~RawrXDTensor();
    
    // No copy, move only
    RawrXDTensor(const RawrXDTensor&) = delete;
    RawrXDTensor& operator=(const RawrXDTensor&) = delete;
    RawrXDTensor(RawrXDTensor&& other) noexcept;
    RawrXDTensor& operator=(RawrXDTensor&& other) noexcept;
    
    // Residency management
    bool EnsureResident();
    bool IsResident() const;
    void Touch();
    void Prefetch();
    
    // Access
    void* VRAMPtr();
    void* RAMPtr();
    rawramxd::Handle RawRamXDHandle() const { return handle_; }
    
    // Metadata
    TensorType Type() const { return type_; }
    const std::string& Name() const { return name_; }
    size_t Size() const { return size_; }
    rawramxd::Tier CurrentTier() const;
    
    // Validation
    bool IsValid() const { return handle_ != 0; }
    void Invalidate();

private:
    rawramxd::Handle handle_ = 0;
    TensorType type_;
    std::string name_;
    size_t size_ = 0;
};

// =============================================================================
// Model Manager - Manages All Tensors for a Model
// =============================================================================

class ModelManager {
public:
    struct ModelConfig {
        std::string name;
        int numLayers;
        size_t hiddenSize;
        size_t intermediateSize;
        size_t vocabSize;
        int maxSequenceLength;
        int numAttentionHeads;
        int numKeyValueHeads;
    };
    
    bool LoadModel(const std::string& ggufPath, const ModelConfig& config);
    void UnloadModel();
    
    // Layer access
    RawrXDTensor* GetLayerWeights(int layer);
    RawrXDTensor* GetLayerNormWeights(int layer);
    RawrXDTensor* GetAttentionWeights(int layer);
    RawrXDTensor* GetFFNWeights(int layer);
    
    // KV cache access
    RawrXDTensor* GetKeyCache(int layer, int token);
    RawrXDTensor* GetValueCache(int layer, int token);
    
    // Prepare for inference
    bool PrepareLayer(int layer);
    bool PrepareAllLayers();
    
    // Residency hints
    void PinLayer(int layer);      // Keep in VRAM
    void UnpinLayer(int layer);    // Allow eviction
    void PrefetchNextLayer(int currentLayer);
    
    // Stats
    size_t TotalModelSize() const;
    size_t VRAMUsage() const;
    size_t RAMUsage() const;
    
private:
    ModelConfig config_;
    std::vector<RawrXDTensor> layerWeights_;
    std::vector<RawrXDTensor> layerNormWeights_;
    std::vector<RawrXDTensor> attentionWeights_;
    std::vector<RawrXDTensor> ffnWeights_;
    std::vector<RawrXDTensor> keyCache_;
    std::vector<RawrXDTensor> valueCache_;
    
    RawrXDTensor embeddingWeights_;
    RawrXDTensor lmHeadWeights_;
    
    std::vector<bool> pinnedLayers_;
};

// =============================================================================
// Inference Context - Per-request state
// =============================================================================

class InferenceContext {
public:
    struct Request {
        std::vector<int> inputTokens;
        int maxNewTokens;
        float temperature;
        int topK;
        float topP;
    };
    
    struct Response {
        std::vector<int> outputTokens;
        double timeToFirstTokenMs;
        double avgTokenTimeMs;
        double totalTimeMs;
        rawramxd::ResidencyMetrics residencyMetrics;
    };
    
    InferenceContext(ModelManager* model);
    ~InferenceContext();
    
    // Execution
    Response Generate(const Request& request);
    
    // Streaming
    using TokenCallback = std::function<void(int token, double latencyMs)>;
    void GenerateStreaming(const Request& request, TokenCallback callback);
    
    // Cancellation
    void Cancel();
    bool IsCancelled() const;

private:
    ModelManager* model_;
    std::atomic<bool> cancelled_{false};
    
    // Workspace tensors
    RawrXDTensor attentionOutput_;
    RawrXDTensor ffnIntermediate_;
    RawrXDTensor normOutput_;
    RawrXDTensor logits_;
    
    bool ExecuteLayer(int layer, const void* input, void* output);
    int SampleToken(const void* logits);
};

// =============================================================================
// Runtime Configuration
// =============================================================================

struct RawrXDRuntimeConfig {
    // Memory configuration
    size_t vramSize = 48ULL * 1024 * 1024 * 1024;      // 48GB
    size_t ramSize = 128ULL * 1024 * 1024 * 1024;      // 128GB
    size_t nvmeSize = 2ULL * 1024 * 1024 * 1024 * 1024; // 2TB
    
    // Policy selection
    std::string residencyPolicy = "LLMInference";
    
    // Performance targets
    double targetTPS = 50.0;           // tokens/sec
    double maxFirstTokenLatency = 500; // ms
    double maxStallTime = 10;          // ms per token
    
    // Telemetry
    bool enableTelemetry = true;
    std::string telemetryOutputPath = "rawrxd_telemetry/";
    int telemetryIntervalSeconds = 60;
    
    // Optimization
    bool enablePrefetching = true;
    bool enableAsyncMigration = true;
    int prefetchLookahead = 3;         // layers
};

// =============================================================================
// Main Runtime Class
// =============================================================================

class RawrXDRuntime {
public:
    static RawrXDRuntime& Instance();
    
    // Lifecycle
    bool Initialize(const RawrXDRuntimeConfig& config);
    void Shutdown();
    
    // Model management
    bool LoadModel(const std::string& path, const ModelManager::ModelConfig& config);
    void UnloadModel();
    ModelManager* CurrentModel();
    
    // Inference
    InferenceContext::Response Generate(const InferenceContext::Request& request);
    void GenerateStreaming(const InferenceContext::Request& request,
                          InferenceContext::TokenCallback callback);
    
    // Telemetry
    void ExportTelemetry(const std::string& path);
    void PrintStats();
    rawramxd::ResidencyMetrics GetMetrics();
    
    // Benchmarking
    bool RunBenchmark(int tokens = 128);
    bool RunSoakTest(int hours);
    
    // Configuration
    void SetPolicy(const std::string& policy);
    void SetTargetTPS(double tps);

private:
    RawrXDRuntime() = default;
    ~RawrXDRuntime() = default;
    RawrXDRuntime(const RawrXDRuntime&) = delete;
    RawrXDRuntime& operator=(const RawrXDRuntime&) = delete;
    
    std::unique_ptr<ModelManager> model_;
    RawrXDRuntimeConfig config_;
    std::unique_ptr<rawramxd::TelemetryCollector> telemetry_;
    
    bool initialized_ = false;
};

// =============================================================================
// C API for External Integration
// =============================================================================

extern "C" {

// Runtime lifecycle
bool rawrxd_init(const RawrXDRuntimeConfig* config);
void rawrxd_shutdown();

// Model loading
bool rawrxd_load_model(const char* path, int num_layers, int hidden_size);
void rawrxd_unload_model();

// Inference
bool rawrxd_generate(const int* input_tokens, int input_count,
                    int max_new_tokens,
                    int* output_tokens, int* output_count,
                    double* time_to_first_token,
                    double* avg_token_time);

// Telemetry
void rawrxd_export_telemetry(const char* path);
void rawrxd_print_stats();

// Benchmarking
bool rawrxd_benchmark(int tokens);
bool rawrxd_soak_test(int hours);

} // extern "C"

} // namespace rawrxd

#endif // RAWRXD_RAWRAMXD_INTEGRATION_HPP