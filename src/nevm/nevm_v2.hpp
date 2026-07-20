//============================================================================
// nevm_v2.hpp
// RawrXD N-EVM v0.2 - Neural Execution Virtual Machine
// Complete architecture with Neural MMU, Precision Controller, GGUF passthrough
//============================================================================

#pragma once

// Core components
#include "nevm_core.hpp"
#include "nevm_isa.hpp"
#include "nevm_mmu.hpp"
#include "nevm_precision_controller.hpp"
#include "nevm_gguf_loader.hpp"

// Original components
#include "nevm_nano_format.hpp"
#include "nevm_components.hpp"

namespace RawrXD {
namespace NEVM {

//============================================================================
// N-EVM v0.2 - Complete System
//============================================================================

class NEVM_v2 {
public:
    struct Config {
        // Memory budgets
        size_t ram_budget = 64ULL * 1024 * 1024 * 1024;      // 64GB
        size_t vram_budget = 16ULL * 1024 * 1024 * 1024;   // 16GB
        size_t cache_budget = 256ULL * 1024 * 1024;        // 256MB L3
        
        // Block configuration
        size_t block_size = 4ULL * 1024 * 1024;            // 4MB blocks
        
        // Precision control
        PrecisionController::Config precision_config;
        
        // Loader config
        GGUF_PassthroughLoader::Config loader_config;
    };
    
    explicit NEVM_v2(const Config& config);
    ~NEVM_v2();
    
    // Disable copy/move
    NEVM_v2(const NEVM_v2&) = delete;
    NEVM_v2& operator=(const NEVM_v2&) = delete;
    
    // System initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Model loading - ANY FORMAT
    bool LoadModel(const std::wstring& path);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Virtual tensor access
    void* GetTensor(const std::string& tensor_name);
    void* GetTensorVA(uint64_t virtual_address);
    
    // Execution
    bool ExecuteLayer(uint8_t layer_id, 
                       const float* input,
                       float* output,
                       uint32_t seq_len);
    
    // Precision control
    void SetPrecisionMode(ISA::PrecisionMode mode);
    void SetAdaptivePrecision(bool enabled);
    
    // Medusa/speculative integration
    void OnSpeculativePrediction(float acceptance_probability);
    void OnTokenVerified(bool accepted);
    
    // Statistics
    struct Stats {
        uint64_t instructions_executed;
        uint64_t tensor_accesses;
        uint64_t precision_switches;
        uint64_t blocks_decoded;
        uint64_t cache_hits;
        uint64_t cache_misses;
        
        // Memory
        size_t ram_used;
        size_t vram_used;
        size_t working_set_size;
        
        // Performance
        float avg_decode_latency_ms;
        float avg_compute_latency_ms;
        float current_memory_pressure;
    };
    Stats GetStats() const;
    
    // Component access (for advanced use)
    NeuralMMU* GetMMU() { return mmu_.get(); }
    PrecisionController* GetPrecisionController() { return precision_controller_.get(); }
    GGUF_PassthroughLoader* GetLoader() { return loader_.get(); }
    AdaptivePrecisionManager* GetAdaptiveManager() { return adaptive_manager_.get(); }
    
private:
    Config config_;
    bool initialized_;
    
    // Core components
    std::unique_ptr<NeuralMMU> mmu_;
    std::unique_ptr<PrecisionController> precision_controller_;
    std::unique_ptr<GGUF_PassthroughLoader> loader_;
    std::unique_ptr<AdaptivePrecisionManager> adaptive_manager_;
    
    // Execution state
    ISA::ExecutionContext execution_context_;
    bool adaptive_precision_enabled_;
    
    // Model state
    std::wstring current_model_path_;
    bool model_loaded_;
    
    // Private methods
    bool InitializeComponents();
    void* ResolveTensor(const std::string& name);
};

//============================================================================
// C API for N-EVM v0.2
//============================================================================

extern "C" {
    // System lifecycle
    NEVM_EXPORT NEVM_v2* NEVM2_Create(const NEVM_v2::Config* config);
    NEVM_EXPORT void NEVM2_Destroy(NEVM_v2* vm);
    NEVM_EXPORT int NEVM2_Initialize(NEVM_v2* vm);
    NEVM_EXPORT void NEVM2_Shutdown(NEVM_v2* vm);
    
    // Model loading (ANY FORMAT)
    NEVM_EXPORT int NEVM2_LoadModel(NEVM_v2* vm, const wchar_t* path);
    NEVM_EXPORT void NEVM2_UnloadModel(NEVM_v2* vm);
    NEVM_EXPORT int NEVM2_IsModelLoaded(NEVM_v2* vm);
    
    // Tensor access
    NEVM_EXPORT void* NEVM2_GetTensor(NEVM_v2* vm, const char* name);
    NEVM_EXPORT void* NEVM2_GetTensorVA(NEVM_v2* vm, uint64_t va);
    
    // Execution
    NEVM_EXPORT int NEVM2_ExecuteLayer(NEVM_v2* vm, uint8_t layer_id,
                                        const float* input, float* output,
                                        uint32_t seq_len);
    
    // Precision control
    NEVM_EXPORT void NEVM2_SetPrecisionMode(NEVM_v2* vm, int mode);
    NEVM_EXPORT void NEVM2_SetAdaptivePrecision(NEVM_v2* vm, int enabled);
    
    // Medusa/speculative
    NEVM_EXPORT void NEVM2_OnSpeculative(NEVM_v2* vm, float prob);
    NEVM_EXPORT void NEVM2_OnVerified(NEVM_v2* vm, int accepted);
    
    // Statistics
    NEVM_EXPORT void NEVM2_GetStats(NEVM_v2* vm, NEVM_v2::Stats* stats);
}

//============================================================================
// Usage Example (as comments)
//============================================================================

/*
// Initialize N-EVM v0.2
NEVM_v2::Config config;
config.ram_budget = 64ULL * 1024 * 1024 * 1024;  // 64GB
config.vram_budget = 16ULL * 1024 * 1024 * 1024; // 16GB

auto vm = std::make_unique<NEVM_v2>(config);
vm->Initialize();

// Load ANY model format
vm->LoadModel(L"deepseek-671b.gguf");   // GGUF
vm->LoadModel(L"llama-70b.gguf");       // GGUF
vm->LoadModel(L"mixtral.safetensors");  // Safetensors

// Enable adaptive precision
vm->SetAdaptivePrecision(true);

// Execute with automatic precision selection
float input[4096];
float output[4096];
vm->ExecuteLayer(0, input, output, 1);

// Medusa integration
vm->OnSpeculativePrediction(0.95f);  // High confidence
// ... execute ...
vm->OnTokenVerified(true);            // Accepted

// Statistics
auto stats = vm->GetStats();
printf("Working set: %.1f GB\n", stats.working_set_size / 1e9);
*/

} // namespace NEVM
} // namespace RawrXD
