# Sovereign IDE — API Reference: MoE (Mixture of Experts) SDK
## Complete API Documentation for MoE Model Shaping Functions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** Complete

---

## 1. Overview

The MoE SDK provides APIs for the Mixture of Experts model shaping system. It enables hardware-aware model optimization, expert pruning, quantization, and disk streaming for running frontier-scale models on consumer hardware.

### 1.1 API Categories

| Category | Description | Header |
|----------|-------------|--------|
| Governor | MoE Governor management | `sdk/moe/governor.h` |
| Expert Management | Expert pruning and selection | `sdk/moe/expert.h` |
| Quantization | Model quantization | `sdk/moe/quantize.h` |
| Streaming | Disk-based model streaming | `sdk/moe/stream.h` |
| Hardware | Hardware capability detection | `sdk/moe/hardware.h` |

---

## 2. Governor API

### 2.1 Governor Initialization

```cpp
// sdk/moe/governor.h

/**
 * Governor configuration
 */
typedef struct {
    uint32_t maxExperts;
    uint32_t activeExperts;
    uint32_t expertPruningThreshold;
    bool enableDynamicRouting;
    bool enableDiskStreaming;
    uint64_t memoryBudget;
    char cachePath[512];
} GovernorConfig;

/**
 * Governor statistics
 */
typedef struct {
    uint32_t totalExperts;
    uint32_t activeExperts;
    uint32_t prunedExperts;
    uint32_t loadedExperts;
    uint64_t memoryUsed;
    uint64_t memoryBudget;
    float avgRoutingScore;
    uint64_t cacheHits;
    uint64_t cacheMisses;
} GovernorStats;

/**
 * Initialize MoE Governor
 * @param sdk SDK handle
 * @param config Governor configuration
 * @param outGovernor Output governor handle
 * @return SDKResult
 */
SDKResult SDK_MoE_Init(
    SDKHandle sdk,
    const GovernorConfig* config,
    MoEGovernorHandle* outGovernor
);

/**
 * Shutdown MoE Governor
 * @param sdk SDK handle
 * @param governor Governor handle
 * @return SDKResult
 */
SDKResult SDK_MoE_Shutdown(
    SDKHandle sdk,
    MoEGovernorHandle governor
);

/**
 * Get governor statistics
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param outStats Output statistics
 * @return SDKResult
 */
SDKResult SDK_MoE_GetStats(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    GovernorStats* outStats
);

/**
 * Update configuration
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param config New configuration
 * @return SDKResult
 */
SDKResult SDK_MoE_UpdateConfig(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const GovernorConfig* config
);
```

### 2.2 Model Registration

```cpp
/**
 * Model information
 */
typedef struct {
    char modelId[64];
    char name[128];
    uint64_t totalParameters;
    uint32_t expertCount;
    uint32_t activeExpertCount;
    uint64_t modelSize;
    bool isQuantized;
    uint32_t quantizationBits;
} MoEModelInfo;

/**
 * Register model with governor
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelPath Path to model
 * @param outModelId Output model ID
 * @return SDKResult
 */
SDKResult SDK_MoE_RegisterModel(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelPath,
    char* outModelId
);

/**
 * Unregister model
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @return SDKResult
 */
SDKResult SDK_MoE_UnregisterModel(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId
);

/**
 * Get model information
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param outInfo Output model info
 * @return SDKResult
 */
SDKResult SDK_MoE_GetModelInfo(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    MoEModelInfo* outInfo
);

/**
 * Get registered models
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param outModels Output model array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_MoE_GetModels(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    MoEModelInfo** outModels,
    uint32_t* outCount
);
```

---

## 3. Expert Management API

### 3.1 Expert Operations

```cpp
// sdk/moe/expert.h

/**
 * Expert information
 */
typedef struct {
    char expertId[64];
    uint32_t layerIndex;
    uint32_t expertIndex;
    uint64_t parameterCount;
    uint64_t memorySize;
    float importanceScore;
    float usageFrequency;
    bool isActive;
    bool isLoaded;
} ExpertInfo;

/**
 * Get expert information
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @param outInfo Output expert info
 * @return SDKResult
 */
SDKResult SDK_Expert_GetInfo(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId,
    ExpertInfo* outInfo
);

/**
 * Get all experts
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param outExperts Output expert array
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Expert_GetAll(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    ExpertInfo** outExperts,
    uint32_t* outCount
);

/**
 * Activate expert
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @return SDKResult
 */
SDKResult SDK_Expert_Activate(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId
);

/**
 * Deactivate expert
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @return SDKResult
 */
SDKResult SDK_Expert_Deactivate(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId
);

/**
 * Prune expert
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @return SDKResult
 */
SDKResult SDK_Expert_Prune(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId
);

/**
 * Restore pruned expert
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @return SDKResult
 */
SDKResult SDK_Expert_Restore(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId
);
```

### 3.2 Expert Selection

```cpp
/**
 * Expert selection strategy
 */
typedef enum {
    SELECT_TOP_K = 0,
    SELECT_THRESHOLD = 1,
    SELECT_ADAPTIVE = 2,
    SELECT_CUSTOM = 3
} ExpertSelectionStrategy;

/**
 * Expert selection configuration
 */
typedef struct {
    ExpertSelectionStrategy strategy;
    uint32_t topK;
    float threshold;
    bool useImportanceScore;
    bool useUsageFrequency;
} ExpertSelectionConfig;

/**
 * Select experts for inference
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param inputEmbedding Input embedding
 * @param config Selection configuration
 * @param outExpertIds Output expert IDs
 * @param outCount Output count
 * @return SDKResult
 */
SDKResult SDK_Expert_Select(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const float* inputEmbedding,
    const ExpertSelectionConfig* config,
    char** outExpertIds,
    uint32_t* outCount
);

/**
 * Set active expert set
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertIds Expert IDs to activate
 * @param count Expert count
 * @return SDKResult
 */
SDKResult SDK_Expert_SetActiveSet(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char** expertIds,
    uint32_t count
);
```

---

## 4. Quantization API

### 4.1 Quantization Operations

```cpp
// sdk/moe/quantize.h

/**
 * Quantization types
 */
typedef enum {
    QUANT_Q4_0 = 0,
    QUANT_Q4_1 = 1,
    QUANT_Q5_0 = 2,
    QUANT_Q5_1 = 3,
    QUANT_Q8_0 = 4,
    QUANT_Q8_1 = 5,
    QUANT_F16 = 6,
    QUANT_BF16 = 7
} QuantizationType;

/**
 * Quantization configuration
 */
typedef struct {
    QuantizationType type;
    bool quantizeExperts;
    bool quantizeAttention;
    bool quantizeEmbeddings;
    float importanceThreshold;
} QuantizationConfig;

/**
 * Quantize model
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param config Quantization configuration
 * @param outQuantizedModelId Output quantized model ID
 * @return SDKResult
 */
SDKResult SDK_Quantize_Model(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const QuantizationConfig* config,
    char* outQuantizedModelId
);

/**
 * Quantize specific expert
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertId Expert ID
 * @param type Quantization type
 * @return SDKResult
 */
SDKResult SDK_Quantize_Expert(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char* expertId,
    QuantizationType type
);

/**
 * Dequantize model
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param outOriginalModelId Output original model ID
 * @return SDKResult
 */
SDKResult SDK_Quantize_Dequantize(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    char* outOriginalModelId
);

/**
 * Get quantization info
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param outType Output quantization type
 * @param outBits Output bits per weight
 * @return SDKResult
 */
SDKResult SDK_Quantize_GetInfo(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    QuantizationType* outType,
    uint32_t* outBits
);
```

---

## 5. Streaming API

### 5.1 Disk Streaming

```cpp
// sdk/moe/stream.h

/**
 * Streaming configuration
 */
typedef struct {
    uint64_t cacheSize;
    uint32_t prefetchCount;
    uint32_t evictionStrategy;
    char diskPath[512];
} StreamingConfig;

/**
 * Streaming statistics
 */
typedef struct {
    uint64_t totalBytesStreamed;
    uint64_t cacheHits;
    uint64_t cacheMisses;
    float hitRate;
    uint32_t activeStreams;
    uint64_t avgLatencyMs;
} StreamingStats;

/**
 * Configure streaming
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param config Streaming configuration
 * @return SDKResult
 */
SDKResult SDK_Stream_Configure(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const StreamingConfig* config
);

/**
 * Prefetch experts
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertIds Expert IDs to prefetch
 * @param count Expert count
 * @return SDKResult
 */
SDKResult SDK_Stream_Prefetch(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char** expertIds,
    uint32_t count
);

/**
 * Evict experts from memory
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param modelId Model ID
 * @param expertIds Expert IDs to evict
 * @param count Expert count
 * @return SDKResult
 */
SDKResult SDK_Stream_Evict(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    const char* modelId,
    const char** expertIds,
    uint32_t count
);

/**
 * Get streaming statistics
 * @param sdk SDK handle
 * @param governor Governor handle
 * @param outStats Output statistics
 * @return SDKResult
 */
SDKResult SDK_Stream_GetStats(
    SDKHandle sdk,
    MoEGovernorHandle governor,
    StreamingStats* outStats
);

/**
 * Force cache flush
 * @param sdk SDK handle
 * @param governor Governor handle
 * @return SDKResult
 */
SDKResult SDK_Stream_FlushCache(
    SDKHandle sdk,
    MoEGovernorHandle governor
);
```

---

## 6. Hardware API

### 6.1 Hardware Detection

```cpp
// sdk/moe/hardware.h

/**
 * Hardware capabilities
 */
typedef struct {
    uint64_t totalMemory;
    uint64_t availableMemory;
    uint32_t cpuCores;
    bool hasGPU;
    uint64_t gpuMemory;
    bool hasCUDA;
    bool hasVulkan;
    bool hasAVX512;
    bool hasAVX2;
    uint32_t computeCapability;
} HardwareCapabilities;

/**
 * Hardware requirements
 */
typedef struct {
    uint64_t minMemory;
    uint64_t recommendedMemory;
    bool requiresGPU;
    uint64_t minGPUMemory;
    bool requiresAVX2;
} HardwareRequirements;

/**
 * Detect hardware capabilities
 * @param sdk SDK handle
 * @param outCapabilities Output capabilities
 * @return SDKResult
 */
SDKResult SDK_Hardware_Detect(
    SDKHandle sdk,
    HardwareCapabilities* outCapabilities
);

/**
 * Check model compatibility
 * @param sdk SDK handle
 * @param modelId Model ID
 * @param requirements Hardware requirements
 * @param outCompatible Output compatible flag
 * @param outRecommendation Output recommendation
 * @return SDKResult
 */
SDKResult SDK_Hardware_CheckCompatibility(
    SDKHandle sdk,
    const char* modelId,
    const HardwareRequirements* requirements,
    bool* outCompatible,
    char* outRecommendation
);

/**
 * Estimate memory requirements
 * @param sdk SDK handle
 * @param modelId Model ID
 * @param activeExperts Number of active experts
 * @param contextLength Context length
 * @param outMemory Output memory estimate
 * @return SDKResult
 */
SDKResult SDK_Hardware_EstimateMemory(
    SDKHandle sdk,
    const char* modelId,
    uint32_t activeExperts,
    uint32_t contextLength,
    uint64_t* outMemory
);

/**
 * Get optimal configuration
 * @param sdk SDK handle
 * @param modelId Model ID
 * @param outConfig Output optimal configuration
 * @return SDKResult
 */
SDKResult SDK_Hardware_GetOptimalConfig(
    SDKHandle sdk,
    const char* modelId,
    GovernorConfig* outConfig
);
```

---

## 7. Usage Examples

### 7.1 Setting Up MoE Governor

```cpp
#include <sdk/core/init.h>
#include <sdk/moe/governor.h>
#include <sdk/moe/expert.h>
#include <sdk/moe/quantize.h>
#include <sdk/moe/hardware.h>

void setupMoE(SDKHandle sdk) {
    // Detect hardware
    HardwareCapabilities hw;
    SDK_Hardware_Detect(sdk, &hw);
    
    printf("Hardware: %llu GB RAM, GPU: %s\n",
           hw.totalMemory / (1024*1024*1024),
           hw.hasGPU ? "yes" : "no");
    
    // Configure governor
    GovernorConfig config = {
        .maxExperts = 128,
        .activeExperts = 8,
        .expertPruningThreshold = 0.1f,
        .enableDynamicRouting = true,
        .enableDiskStreaming = true,
        .memoryBudget = hw.totalMemory * 0.8,  // 80% of RAM
        .cachePath = "cache/moe"
    };
    
    // Initialize governor
    MoEGovernorHandle governor;
    SDK_MoE_Init(sdk, &config, &governor);
    
    // Register model
    char modelId[64];
    SDK_MoE_RegisterModel(sdk, governor, 
                          "models/mixtral-8x7b.gguf", modelId);
    
    // Get model info
    MoEModelInfo info;
    SDK_MoE_GetModelInfo(sdk, governor, modelId, &info);
    printf("Model: %s, %llu parameters, %d experts\n",
           info.name, info.totalParameters, info.expertCount);
    
    // Quantize model
    QuantizationConfig quantConfig = {
        .type = QUANT_Q4_K_M,
        .quantizeExperts = true,
        .quantizeAttention = false,
        .quantizeEmbeddings = false,
        .importanceThreshold = 0.05f
    };
    
    char quantizedId[64];
    SDK_Quantize_Model(sdk, governor, modelId, &quantConfig, quantizedId);
    
    // Get experts
    ExpertInfo* experts;
    uint32_t expertCount;
    SDK_Expert_GetAll(sdk, governor, quantizedId, &experts, &expertCount);
    
    // Activate top experts
    for (uint32_t i = 0; i < expertCount && i < 8; i++) {
        SDK_Expert_Activate(sdk, governor, quantizedId, experts[i].expertId);
    }
    
    // Get stats
    GovernorStats stats;
    SDK_MoE_GetStats(sdk, governor, &stats);
    printf("Active experts: %d/%d, Memory: %llu/%llu GB\n",
           stats.activeExperts, stats.totalExperts,
           stats.memoryUsed / (1024*1024*1024),
           stats.memoryBudget / (1024*1024*1024));
    
    // Cleanup
    SDK_MoE_Shutdown(sdk, governor);
}
```

### 7.2 Dynamic Expert Selection

```cpp
void dynamicExpertSelection(SDKHandle sdk, MoEGovernorHandle governor, 
                            const char* modelId, const float* embedding) {
    // Configure selection
    ExpertSelectionConfig config = {
        .strategy = SELECT_TOP_K,
        .topK = 2,
        .threshold = 0.0f,
        .useImportanceScore = true,
        .useUsageFrequency = true
    };
    
    // Select experts
    char** expertIds;
    uint32_t count;
    SDK_Expert_Select(sdk, governor, modelId, embedding, &config, &expertIds, &count);
    
    printf("Selected %d experts for inference:\n", count);
    for (uint32_t i = 0; i < count; i++) {
        printf("  - %s\n", expertIds[i]);
    }
    
    // Set active
    SDK_Expert_SetActiveSet(sdk, governor, modelId, 
                            (const char**)expertIds, count);
    
    // Prefetch for next token
    SDK_Stream_Prefetch(sdk, governor, modelId, 
                        (const char**)expertIds, count);
}
```

---

## Summary

The MoE SDK API provides:

- ✅ Governor initialization and management
- ✅ Expert pruning and selection
- ✅ Dynamic routing
- ✅ Model quantization (Q4, Q5, Q8, F16, BF16)
- ✅ Disk-based streaming
- ✅ Hardware capability detection
- ✅ Memory estimation and optimization

**Status:** Complete

---

*End of API Reference: MoE SDK*
