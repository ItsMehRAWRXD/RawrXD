// ============================================================================
// SovereignInferencePipeline.hpp - Complete Production Inference Pipeline
// 
// This is the top-level integration header that wires together:
//   - GGUF Loader (zero-dependency model loading)
//   - Kernel Dispatcher (runtime CPU feature routing)
//   - Deep2Engine (Q4_K_M GEMV via MASM)
//   - InferenceTask (AgenticSupervisor bridge)
//   - KV Cache (O(n) attention)
//
// Usage:
//   SovereignInferencePipeline pipeline;
//   pipeline.LoadModel("model.gguf");
//   pipeline.Generate("Hello, world!", 100);
// ============================================================================

#pragma once

#include "Deep2Engine.h"
#include "KernelDispatcher.hpp"
#include "GGUFLoader.hpp"
#include "InferenceTask.hpp"
#include "KVCache.h"
#include <string>
#include <vector>
#include <memory>

namespace Deep2 {

// ============================================================================
// Token Generation Configuration
// ============================================================================
struct GenerationConfig {
    size_t maxTokens = 256;
    float temperature = 0.8f;
    float topP = 0.95f;
    size_t topK = 40;
    float repetitionPenalty = 1.0f;
    bool useKVCache = true;
    bool useParallel = true;
    TaskPriority priority = TaskPriority::NORMAL;
};

// ============================================================================
// Generation Result
// ============================================================================
struct GenerationResult {
    bool success = false;
    std::vector<int> tokens;
    double tokensPerSecond = 0.0;
    double avgLatencyMs = 0.0;
    size_t promptTokens = 0;
    size_t generatedTokens = 0;
    char error[256] = {0};
};

// ============================================================================
// SovereignInferencePipeline - Complete Production Pipeline
// ============================================================================
class SovereignInferencePipeline {
public:
    SovereignInferencePipeline();
    ~SovereignInferencePipeline();
    
    // Initialize pipeline
    bool Initialize(const EngineConfig& config);
    
    // Load model from GGUF file
    // Returns number of tensors loaded, or -1 on error
    int LoadModel(const char* ggufPath, bool verbose = false);
    
    // Check if model is loaded
    bool IsModelLoaded() const { return modelLoaded; }
    
    // Generate tokens from prompt
    GenerationResult Generate(const char* prompt, const GenerationConfig& config);
    
    // Generate from token IDs
    GenerationResult Generate(const std::vector<int>& promptTokens, 
                               const GenerationConfig& config);
    
    // Reset conversation state
    void Reset();
    
    // Get model metadata
    const ModelMetadata& GetModelMetadata() const { return modelMetadata; }
    
    // Get engine
    Deep2Engine* GetEngine() { return &engine; }
    
    // Get bridge
    SovereignInferenceBridge* GetBridge() { return &bridge; }
    
    // Performance stats
    struct PipelineStats {
        uint64_t tokensGenerated = 0;
        uint64_t tokensPrompt = 0;
        double totalTimeMs = 0.0;
        double peakTps = 0.0;
        double avgTps = 0.0;
        size_t memoryUsedMB = 0;
    };
    PipelineStats GetStats() const;
    void ResetStats();

private:
    Deep2Engine engine;
    SovereignInferenceBridge bridge;
    
    bool initialized = false;
    bool modelLoaded = false;
    
    ModelMetadata modelMetadata;
    GGUFLoadResult ggufResult;
    
    // Tokenizer (placeholder - would integrate with actual tokenizer)
    std::vector<int> Tokenize(const char* text);
    std::string Detokenize(const std::vector<int>& tokens);
    
    // Forward pass through model
    bool Forward(const float* input, float* output, size_t hiddenDim);
    
    // Sample next token
    int Sample(const float* logits, const GenerationConfig& config);
    
    // Stats
    PipelineStats stats;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick inference: Load model and generate in one call
GenerationResult QuickInfer(const char* modelPath, const char* prompt, 
                             size_t maxTokens = 256);

// Benchmark model performance
struct BenchmarkResult {
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
    double bandwidthGBps = 0.0;
    size_t memoryMB = 0;
    bool success = false;
    char error[256] = {0};
};
BenchmarkResult BenchmarkModel(const char* modelPath, size_t numTokens = 100);

} // namespace Deep2

// ============================================================================
// C API for External Integration
// ============================================================================

extern "C" {

// Opaque handle
typedef void* SovereignPipelineHandle;

// Create/destroy
SovereignPipelineHandle SovereignPipeline_Create();
void SovereignPipeline_Destroy(SovereignPipelineHandle handle);

// Initialize
int SovereignPipeline_Initialize(SovereignPipelineHandle handle, 
                                  const Deep2::EngineConfig* config);

// Load model
int SovereignPipeline_LoadModel(SovereignPipelineHandle handle, const char* path);

// Generate
int SovereignPipeline_Generate(SovereignPipelineHandle handle,
                                const char* prompt,
                                int maxTokens,
                                int* outputTokens,
                                int outputBufferSize);

// Get last error
const char* SovereignPipeline_GetError(SovereignPipelineHandle handle);

} // extern "C"
