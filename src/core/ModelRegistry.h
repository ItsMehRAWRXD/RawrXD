//==============================================================================
// ModelRegistry.h - Phase 14: Multi-Model Registry + Hot-Swap
//
// Central registry for managing multiple GGUF models.
// Supports model metadata, capabilities, and hot-swapping.
//==============================================================================

#ifndef MODEL_REGISTRY_H
#define MODEL_REGISTRY_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Constants
//==============================================================================

#define MODEL_REGISTRY_VERSION "14.0.0"
#define MAX_MODELS 64
#define MAX_MODEL_NAME 128
#define MAX_PATH_LEN 512
#define MAX_CAPABILITIES 16

//==============================================================================
// Model Capabilities (bitmask)
//==============================================================================

typedef enum {
    CAP_CODE_GENERATION = 0x0001,
    CAP_CODE_FIXING = 0x0002,
    CAP_OPTIMIZATION = 0x0004,
    CAP_TRANSLATION = 0x0008,
    CAP_REASONING = 0x0010,
    CAP_CHAT = 0x0020,
    CAP_EMBEDDINGS = 0x0040,
    CAP_RAG = 0x0080,
    CAP_MULTILINGUAL = 0x0100,
    CAP_MATH = 0x0200
} ModelCapability;

//==============================================================================
// Model Info Structure
//==============================================================================

typedef struct ModelInfo {
    // Identity
    char name[MAX_MODEL_NAME];
    char id[64];  // Unique identifier
    char path[MAX_PATH_LEN];
    
    // Type
    int is_local;  // 1 = GGUF, 0 = external (Ollama, etc.)
    char backend_type[32];  // "native", "ollama", "openai"
    
    // Specifications
    size_t parameter_count;  // e.g., 7000000000 for 7B
    int context_window;        // e.g., 4096, 8192, 128000
    int embedding_dim;       // e.g., 4096
    int num_layers;
    int num_heads;
    
    // Capabilities
    unsigned int capabilities;  // Bitmask of ModelCapability
    char recommended_tasks[256];  // Human-readable
    
    // Performance metrics (populated after benchmarking)
    float tokens_per_second;   // Measured on this hardware
    float latency_ms;          // Time to first token
    size_t memory_required_mb; // RAM/VRAM needed
    
    // Status
    int is_loaded;             // Currently in memory
    int is_default;            // Default model for new sessions
    uint64_t last_used_ms;     // Timestamp
    int use_count;             // How many times used
    
    // Metadata
    char description[512];
    char version[32];
    char quantization[16];   // "Q4_K_M", "Q8_0", etc.
    char license[64];
    char source_url[256];      // Download URL
} ModelInfo;

//==============================================================================
// Registry API
//==============================================================================

// Initialize registry from JSON file
int ModelRegistry_Init(const char* registry_path);

// Shutdown and cleanup
int ModelRegistry_Shutdown(void);

// Load registry from JSON
int ModelRegistry_LoadFromJSON(const char* json_path);

// Save registry to JSON
int ModelRegistry_SaveToJSON(const char* json_path);

//==============================================================================
// Model Management
//==============================================================================

// Add a model to registry
int ModelRegistry_AddModel(const ModelInfo* model);

// Remove a model
int ModelRegistry_RemoveModel(const char* model_id);

// Get model info by ID
int ModelRegistry_GetModel(const char* model_id, ModelInfo* out_model);

// Get model by name (fuzzy match)
int ModelRegistry_GetModelByName(const char* name, ModelInfo* out_model);

// Get default model
int ModelRegistry_GetDefaultModel(ModelInfo* out_model);

// Set default model
int ModelRegistry_SetDefaultModel(const char* model_id);

// List all models
int ModelRegistry_ListModels(ModelInfo* out_models, int max_models, int* count);

//==============================================================================
// Model Selection
//==============================================================================

// Find best model for task
int ModelRegistry_SelectModelForTask(
    const char* task_type,      // "code", "chat", "reasoning", etc.
    const char* language,       // "rust", "python", etc. (optional)
    int prefer_speed,           // 1 = prioritize tokens/sec
    int prefer_quality,         // 1 = prioritize capability
    ModelInfo* out_model
);

// Find model by capability
int ModelRegistry_FindByCapability(
    unsigned int required_caps,
    ModelInfo* out_models,
    int max_models,
    int* count
);

// Check if model supports capability
int ModelRegistry_HasCapability(const char* model_id, unsigned int capability);

//==============================================================================
// Hot-Swap Operations
//==============================================================================

// Load model into memory (prepare for use)
int ModelRegistry_LoadModel(const char* model_id);

// Unload model from memory
int ModelRegistry_UnloadModel(const char* model_id);

// Switch active model (hot-swap)
int ModelRegistry_SwitchModel(const char* model_id);

// Get currently active model
int ModelRegistry_GetActiveModel(ModelInfo* out_model);

// Preload multiple models (for fast switching)
int ModelRegistry_PreloadModels(const char** model_ids, int count);

//==============================================================================
// Benchmarking
//==============================================================================

// Run benchmark on model
int ModelRegistry_BenchmarkModel(const char* model_id);

// Update performance metrics
int ModelRegistry_UpdateMetrics(
    const char* model_id,
    float tokens_per_sec,
    float latency_ms
);

// Get benchmark results
int ModelRegistry_GetBenchmark(const char* model_id, char* report, size_t report_size);

//==============================================================================
// CLI Integration
//==============================================================================

int ModelRegistrySubsystem_Handler(int argc, char** argv, char* output, size_t output_size);
int ModelRegistrySubsystem_Init(void);
int ModelRegistrySubsystem_Shutdown(void);

#ifdef __cplusplus
}
#endif

#endif // MODEL_REGISTRY_H
