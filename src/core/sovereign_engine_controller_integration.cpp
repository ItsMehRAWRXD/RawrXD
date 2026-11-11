// =============================================================================
// sovereign_engine_controller_integration.cpp
// Phase 22: Engine Controller Implementation
// Bridges Phase 11 (ASM Loader) with Phase 22/23 (Thread Pool + Swarm)
// =============================================================================

#include "sovereign_engine_controller_integration.h"
#include "sovereign_thread_pool.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <mutex>

namespace Sovereign {

// =============================================================================
// Constructor / Destructor
// =============================================================================

SovereignEngineController::SovereignEngineController() {
    // Initialize thread pool using C API
    thread_pool_ = Sovereign_ThreadPool_Init(num_threads_, 0);
    
    printf("[Sovereign] Engine Controller initialized\n");
    printf("  Thread pool: %u threads\n", num_threads_);
}

SovereignEngineController::~SovereignEngineController() {
    DestroyAllSessions();
    UnloadModel();
    
    // Destroy thread pool using C API
    if (thread_pool_) {
        Sovereign_ThreadPool_Shutdown(thread_pool_);
        thread_pool_ = nullptr;
    }
    
    printf("[Sovereign] Engine Controller destroyed\n");
}

// =============================================================================
// Phase 11 Integration: Model Loading
// =============================================================================

bool SovereignEngineController::LoadModel(const char* model_path) {
    if (model_loaded_) {
        printf("[Sovereign] Warning: Model already loaded, unloading first\n");
        UnloadModel();
    }
    
    printf("[Sovereign] Loading model: %s\n", model_path);
    
    // Call Phase 11 ASM loader
    model_handle_ = RawrXD_LoadModel(model_path);
    if (!model_handle_) {
        fprintf(stderr, "[Sovereign] ERROR: Failed to load model\n");
        return false;
    }
    
    model_loaded_ = true;
    
    // Parse layer metadata from loaded model
    if (!ParseLayerMetadata()) {
        fprintf(stderr, "[Sovereign] ERROR: Failed to parse layer metadata\n");
        RawrXD_UnloadModel(model_handle_);
        model_handle_ = nullptr;
        model_loaded_ = false;
        return false;
    }
    
    // Initialize KV cache (Phase 11)
    if (!InitializeKVCache()) {
        fprintf(stderr, "[Sovereign] WARNING: Failed to initialize KV cache\n");
        // Continue anyway - model can work without KV cache
    }
    
    printf("[Sovereign] Model loaded successfully\n");
    printf("  Layers: %u\n", n_layers_);
    printf("  Thread pool: Active\n");
    
    return true;
}

void SovereignEngineController::UnloadModel() {
    if (!model_loaded_ || !model_handle_) {
        return;
    }
    
    printf("[Sovereign] Unloading model...\n");
    
    // Destroy all sessions first
    DestroyAllSessions();
    
    // Unload model via Phase 11 ASM
    RawrXD_UnloadModel(model_handle_);
    
    model_handle_ = nullptr;
    model_loaded_ = false;
    layer_metadata_.clear();
    n_layers_ = 0;
    
    printf("[Sovereign] Model unloaded\n");
}

// =============================================================================
// Layer Metadata Parsing (bridges ASM to C++)
// =============================================================================

bool SovereignEngineController::ParseLayerMetadata() {
    if (!model_handle_) return false;
    
    // Query model for layer count
    // In production, this would read from GGUF header
    // For now, assume standard transformer architecture
    n_layers_ = 32;  // Typical Llama model
    
    layer_metadata_.reserve(n_layers_);
    
    for (uint32_t i = 0; i < n_layers_; i++) {
        LayerMetadata meta;
        meta.layer_idx = i;
        
        // Get layer data pointer from Phase 11 ASM
        meta.data_ptr = RawrXD_GetLayer(model_handle_, i);
        if (!meta.data_ptr) {
            fprintf(stderr, "[Sovereign] Warning: Layer %u not found\n", i);
            continue;
        }
        
        // Determine quantization zone based on layer position
        meta.quant_zone = DetermineQuantZone(i);
        
        // Map zone to quant type
        switch (meta.quant_zone) {
            case QuantZone::CRITICAL:
                meta.quant_type = 8;   // GGML_TYPE_Q8_0
                snprintf(meta.name, sizeof(meta.name), "layer_%u_critical", i);
                break;
            case QuantZone::MIDDLE:
                meta.quant_type = 12;  // GGML_TYPE_Q4_K
                snprintf(meta.name, sizeof(meta.name), "layer_%u_middle", i);
                break;
            case QuantZone::TAIL:
                meta.quant_type = 10;  // GGML_TYPE_Q2_K
                snprintf(meta.name, sizeof(meta.name), "layer_%u_tail", i);
                break;
        }
        
        // Estimate size (would be read from GGUF in production)
        meta.n_elements = 4096 * 4096;  // Typical weight matrix
        meta.n_dims = 2;
        meta.dims[0] = 4096;
        meta.dims[1] = 4096;
        meta.size_bytes = meta.n_elements * sizeof(float);  // Before quantization
        
        layer_metadata_.push_back(meta);
    }
    
    // Update stats
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.n_layers_loaded = n_layers_;
    
    return !layer_metadata_.empty();
}

QuantZone SovereignEngineController::DetermineQuantZone(uint32_t layer_idx) const {
    // Hierarchical quantization strategy from Phase 11:
    // - Critical (Q8_0): First 2 layers (embed) + last 2 layers (output)
    // - Middle (Q4_K): Layers 2 to N-2
    // - Tail (Q2_K): Last 4 layers (if > 32 layers)
    
    if (layer_idx < 2 || layer_idx >= n_layers_ - 2) {
        return QuantZone::CRITICAL;  // Q8_0
    } else if (n_layers_ > 32 && layer_idx >= n_layers_ - 4) {
        return QuantZone::TAIL;      // Q2_K
    } else {
        return QuantZone::MIDDLE;    // Q4_K
    }
}

// =============================================================================
// Phase 11: Layer Access
// =============================================================================

const LayerMetadata* SovereignEngineController::GetLayerMetadata(uint32_t layer_idx) const {
    if (layer_idx >= layer_metadata_.size()) {
        return nullptr;
    }
    return &layer_metadata_[layer_idx];
}

void* SovereignEngineController::GetLayerData(uint32_t layer_idx) {
    if (!model_loaded_ || !model_handle_) {
        return nullptr;
    }
    return RawrXD_GetLayer(model_handle_, layer_idx);
}

// =============================================================================
// Phase 11: KV Cache Management
// =============================================================================

bool SovereignEngineController::InitializeKVCache() {
    if (!model_loaded_ || !model_handle_) {
        return false;
    }
    
    int result = RawrXD_KVCache_Init(model_handle_);
    if (result != 1) {
        fprintf(stderr, "[Sovereign] KV cache init failed: %d\n", result);
        return false;
    }
    
    printf("[Sovereign] KV cache initialized\n");
    return true;
}

void SovereignEngineController::UpdateKVCache(uint32_t position, 
                                               const float* k, 
                                               const float* v) {
    if (!model_loaded_ || !model_handle_) {
        return;
    }
    
    RawrXD_KVCache_Update(model_handle_, position, k, v);
}

void SovereignEngineController::EvictKVCache() {
    if (!model_loaded_ || !model_handle_) {
        return;
    }
    
    RawrXD_KVCache_Evict(model_handle_);
}

// =============================================================================
// Phase 22: Session Management
// =============================================================================

uint32_t SovereignEngineController::CreateSession(const SessionConfig& config) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto session = std::make_unique<Session>();
    session->id = next_session_id_++;
    session->config = config;
    session->active = true;
    session->token_history.reserve(config.max_seq_length);
    
    uint32_t id = session->id;
    sessions_.push_back(std::move(session));
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.active_sessions = static_cast<uint32_t>(sessions_.size());
    
    printf("[Sovereign] Session %u created\n", id);
    return id;
}

void SovereignEngineController::DestroySession(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = std::remove_if(sessions_.begin(), sessions_.end(),
        [session_id](const std::unique_ptr<Session>& s) {
            return s->id == session_id;
        });
    
    if (it != sessions_.end()) {
        sessions_.erase(it, sessions_.end());
        printf("[Sovereign] Session %u destroyed\n", session_id);
    }
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.active_sessions = static_cast<uint32_t>(sessions_.size());
}

void SovereignEngineController::DestroyAllSessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.clear();
    
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.active_sessions = 0;
    
    printf("[Sovereign] All sessions destroyed\n");
}

SovereignEngineController::Session* SovereignEngineController::GetSession(uint32_t session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    for (auto& s : sessions_) {
        if (s->id == session_id && s->active) {
            return s.get();
        }
    }
    return nullptr;
}

// =============================================================================
// Phase 22: Inference (Stub - would call actual kernels)
// =============================================================================

bool SovereignEngineController::GenerateTokens(uint32_t session_id, 
                                                const char* prompt,
                                                char* output, 
                                                size_t output_len) {
    Session* session = GetSession(session_id);
    if (!session) {
        fprintf(stderr, "[Sovereign] ERROR: Session %u not found\n", session_id);
        return false;
    }
    
    if (!model_loaded_) {
        fprintf(stderr, "[Sovereign] ERROR: No model loaded\n");
        return false;
    }
    
    // TODO: Tokenize prompt
    // TODO: Run forward pass through layers using thread pool
    // TODO: Sample next tokens
    // TODO: Detokenize to output
    
    // Stub: Just copy prompt to output
    strncpy(output, prompt, output_len - 1);
    output[output_len - 1] = '\0';
    
    // Update stats
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_inferences++;
    
    return true;
}

bool SovereignEngineController::GenerateToken(uint32_t session_id, uint32_t* next_token) {
    Session* session = GetSession(session_id);
    if (!session || !next_token) {
        return false;
    }
    
    // TODO: Single token generation
    *next_token = 1;  // Stub
    
    session->token_history.push_back(*next_token);
    session->current_pos++;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.tokens_generated++;
    
    return true;
}

// =============================================================================
// Statistics
// =============================================================================

void SovereignEngineController::GetStats(EngineStats* stats) const {
    if (!stats) return;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    *stats = stats_;
}

void SovereignEngineController::PrintStatus() const {
    printf("\n=== Sovereign Engine Status ===\n");
    printf("Model loaded: %s\n", model_loaded_ ? "Yes" : "No");
    printf("Layers: %u\n", n_layers_);
    printf("Active sessions: %u\n", stats_.active_sessions);
    printf("Tokens generated: %llu\n", stats_.tokens_generated);
    printf("Total inferences: %llu\n", stats_.total_inferences);
    printf("Swarm mode: %s\n", swarm_mode_ ? "Enabled" : "Disabled");
    printf("===============================\n\n");
}

} // namespace Sovereign

// =============================================================================
// C-API Implementation
// =============================================================================

extern "C" {

SovereignEngineHandle Sovereign_Engine_Create() {
    return new Sovereign::SovereignEngineController();
}

void Sovereign_Engine_Destroy(SovereignEngineHandle handle) {
    if (handle) {
        delete static_cast<Sovereign::SovereignEngineController*>(handle);
    }
}

int Sovereign_LoadModel(SovereignEngineHandle handle, const char* path) {
    if (!handle || !path) return -1;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    return engine->LoadModel(path) ? 0 : -1;
}

void Sovereign_UnloadModel(SovereignEngineHandle handle) {
    if (!handle) return;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    engine->UnloadModel();
}

uint32_t Sovereign_CreateSession(SovereignEngineHandle handle, 
                                  const Sovereign::SessionConfig* config) {
    if (!handle || !config) return 0;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    return engine->CreateSession(*config);
}

void Sovereign_DestroySession(SovereignEngineHandle handle, uint32_t session_id) {
    if (!handle) return;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    engine->DestroySession(session_id);
}

int Sovereign_Generate(SovereignEngineHandle handle, uint32_t session_id,
                       const char* prompt, char* output, size_t output_len) {
    if (!handle || !prompt || !output || output_len == 0) return -1;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    return engine->GenerateTokens(session_id, prompt, output, output_len) ? 0 : -1;
}

void Sovereign_GetStats(SovereignEngineHandle handle, Sovereign::EngineStats* stats) {
    if (!handle || !stats) return;
    auto* engine = static_cast<Sovereign::SovereignEngineController*>(handle);
    engine->GetStats(stats);
}

}
