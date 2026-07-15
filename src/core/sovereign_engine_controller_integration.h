// =============================================================================
// sovereign_engine_controller.h
// Phase 22: Engine Controller - Integration with Phase 11 Loader
// Bridges RawrXD_120B_Loader.asm (Phase 11) with Thread Pool (Phase 22)
// =============================================================================

#ifndef SOVEREIGN_ENGINE_CONTROLLER_H
#define SOVEREIGN_ENGINE_CONTROLLER_H

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>
#include <mutex>

// Phase 22: Thread Pool
#include "sovereign_thread_pool.h"
#include "sovereign_kv_cache.h"

// Forward declarations for Phase 11 ASM exports
extern "C" {
    typedef void* RawrXD_ModelHandle;
    typedef void* RawrXD_KVCacheHandle;
    
    // Phase 11 Loader exports
    RawrXD_ModelHandle RawrXD_LoadModel(const char* path);
    void RawrXD_UnloadModel(RawrXD_ModelHandle handle);
    void* RawrXD_GetLayer(RawrXD_ModelHandle handle, uint32_t layer_idx);
    int RawrXD_Quantize(void* src, void* dst, uint32_t n_elements, uint32_t quant_type);
    int RawrXD_KVCache_Init(RawrXD_ModelHandle handle);
    int RawrXD_KVCache_Update(RawrXD_ModelHandle handle, uint32_t position, 
                               const float* k_vec, const float* v_vec);
    void RawrXD_KVCache_Evict(RawrXD_ModelHandle handle);
}

// Phase 22 Configuration
namespace Sovereign {

// Quantization strategy from Phase 11
enum class QuantZone {
    CRITICAL = 0,   // Q8_0: Embedding + output head
    MIDDLE = 1,     // Q4_K: Middle transformer blocks
    TAIL = 2        // Q2_K: Late attention layers
};

// Layer metadata (bridges ASM loader with C++ engine)
struct LayerMetadata {
    void* data_ptr;           // From RawrXD_GetLayer
    uint32_t layer_idx;
    QuantZone quant_zone;
    uint32_t quant_type;      // GGML_TYPE_Q8_0, Q4_K, Q2_K
    uint32_t n_elements;
    uint32_t n_dims;
    uint32_t dims[8];
    char name[64];
    size_t size_bytes;
};

// Session configuration
struct SessionConfig {
    uint32_t max_seq_length = 8192;
    uint32_t batch_size = 1;
    float temperature = 0.8f;
    float top_p = 0.9f;
    uint32_t top_k = 40;
    bool use_kv_cache = true;
    bool use_amx = true;
};

// Engine statistics
struct EngineStats {
    uint64_t tokens_generated = 0;
    uint64_t total_inferences = 0;
    double avg_latency_ms = 0.0;
    double peak_memory_mb = 0.0;
    uint32_t active_sessions = 0;
    uint32_t n_layers_loaded = 0;
    uint64_t cache_hits = 0;
    uint64_t cache_misses = 0;
};



// =============================================================================
// SovereignEngineController - Main Controller Class
// =============================================================================

class SovereignEngineController {
public:
    // Constructor/Destructor
    SovereignEngineController();
    virtual ~SovereignEngineController();
    
    // Get layer count
    uint32_t GetLayerCount() const { return n_layers_; }
    
    // Phase 11 Integration: Model Loading
    bool LoadModel(const char* model_path);
    void UnloadModel();
    bool IsModelLoaded() const { return model_loaded_; }
    
    // Phase 22: Session Management
    uint32_t CreateSession(const SessionConfig& config);
    void DestroySession(uint32_t session_id);
    void DestroyAllSessions();
    
    // Phase 22: Inference
    bool GenerateTokens(uint32_t session_id, const char* prompt, 
                         char* output, size_t output_len);
    bool GenerateToken(uint32_t session_id, uint32_t* next_token);
    
    // Phase 23: Swarm Integration (preparation)
    void SetSwarmMode(bool enabled) { swarm_mode_ = enabled; }
    bool IsSwarmMode() const { return swarm_mode_; }
    
    // Statistics
    void GetStats(EngineStats* stats) const;
    void PrintStatus() const;
    
    // Phase 11: Direct layer access (for advanced users)
    const LayerMetadata* GetLayerMetadata(uint32_t layer_idx) const;
    void* GetLayerData(uint32_t layer_idx);
    
    // Phase 11: KV Cache management
    bool InitializeKVCache();
    void UpdateKVCache(uint32_t position, const float* k, const float* v);
    void EvictKVCache();
    
private:
    // Phase 11: ASM Loader handle
    RawrXD_ModelHandle model_handle_ = nullptr;
    bool model_loaded_ = false;
    
    // Phase 11: Layer metadata cache
    std::vector<LayerMetadata> layer_metadata_;
    uint32_t n_layers_ = 0;
    
    // Phase 22: Thread pool (C API)
    SovereignThreadPoolHandle thread_pool_ = nullptr;
    uint32_t num_threads_ = 4;
    
    // Phase 22: Session management
    struct Session {
        uint32_t id;
        SessionConfig config;
        std::vector<uint32_t> token_history;
        uint32_t current_pos = 0;
        bool active = false;
    };
    std::vector<std::unique_ptr<Session>> sessions_;
    uint32_t next_session_id_ = 1;
    mutable std::mutex sessions_mutex_;
    
    // Phase 22: KV Cache handle (from ASM)
    RawrXD_KVCacheHandle kv_cache_handle_ = nullptr;
    
    // Phase 22: Quantization type
    uint32_t quant_type_ = 8;  // Default Q8_0
    
    // Phase 23: Swarm mode
    bool swarm_mode_ = false;
    
    // Statistics
    mutable EngineStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Private methods
    bool ParseLayerMetadata();
    QuantZone DetermineQuantZone(uint32_t layer_idx) const;
    void* GetQuantizedKernel(uint32_t quant_type);
    Session* GetSession(uint32_t session_id);
};

} // namespace Sovereign

// =============================================================================
// C-API for External Integration (outside namespace)
// =============================================================================

extern "C" {
    // Opaque handle
    typedef void* SovereignEngineHandle;
    
    // Lifecycle
    SovereignEngineHandle Sovereign_Engine_Create();
    void Sovereign_Engine_Destroy(SovereignEngineHandle handle);
    
    // Model loading
    int Sovereign_LoadModel(SovereignEngineHandle handle, const char* path);
    void Sovereign_UnloadModel(SovereignEngineHandle handle);
    
    // Session management
    uint32_t Sovereign_CreateSession(SovereignEngineHandle handle, 
                                      const Sovereign::SessionConfig* config);
    void Sovereign_DestroySession(SovereignEngineHandle handle, uint32_t session_id);
    
    // Inference
    int Sovereign_Generate(SovereignEngineHandle handle, uint32_t session_id,
                           const char* prompt, char* output, size_t output_len);
    
    // Statistics
    void Sovereign_GetStats(SovereignEngineHandle handle, Sovereign::EngineStats* stats);
}

#endif // SOVEREIGN_ENGINE_CONTROLLER_H
