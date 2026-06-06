// ============================================================================
// transformer_stack_orchestrator.hpp — Transformer Stack Orchestrator for Phase 3
// Multi-token generation with KV cache reuse for full stack inference
// ============================================================================
#pragma once

#ifndef RAWRXD_TRANSFORMER_STACK_ORCHESTRATOR_HPP
#define RAWRXD_TRANSFORMER_STACK_ORCHESTRATOR_HPP

#include "kv_cache_manager.h"
#include <memory>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

// Forward declarations for testing
namespace RawrXD {
namespace Agent {
class SovereignInferenceClient;
}
}

namespace RawrXD {
namespace AI {

// ============================================================================
// Generation State — Per-token generation state with KV cache tracking
// ============================================================================
struct GenerationState {
    std::vector<uint32_t> token_ids;           // Generated token IDs
    std::vector<float> kv_cache_data;         // KV cache for this context
    size_t seq_len;                           // Current sequence length
    ContextHash context_hash;                 // Hash of context
    bool cache_hit;                           // Was this a cache hit?
    bool ready_for_next;                      // Ready for next token generation
    uint32_t last_layer_idx;                  // Last processed layer index
    std::chrono::steady_clock::time_point start_time;
    
    GenerationState() : seq_len(0), context_hash(0), cache_hit(false), 
                       ready_for_next(false), last_layer_idx(0) {}
};

// ============================================================================
// Layer Output — Output from a single transformer layer
// ============================================================================
struct LayerOutput {
    uint32_t layer_idx;
    std::vector<float> activations;
    bool use_cache;
    ContextHash cache_key;
};

// ============================================================================
// TransformerStackOrchestrator — Orchestrates multi-token generation
// Uses KV cache for prefix optimization across token steps
// ============================================================================
class TransformerStackOrchestrator {
public:
    explicit TransformerStackOrchestrator(
        std::shared_ptr<Agent::SovereignInferenceClient> inference_client,
        std::shared_ptr<KVCacheManager> kv_cache_manager = nullptr);
    
    ~TransformerStackOrchestrator();
    
    // Initialize orchestrator
    bool Initialize();
    
    // Full generation with KV cache reuse
    std::vector<uint32_t> GenerateTokens(
        const std::string& prompt,
        uint32_t max_tokens,
        float temperature = 0.7f,
        bool use_cache = true);
    
    // Step-by-step generation (for streaming)
    GenerationState BeginGeneration(const std::string& prompt);
    uint32_t GenerateNextToken(GenerationState& state);
    bool EndGeneration(GenerationState& state);
    
    // Context hashing for cache lookup
    ContextHash HashGenerationContext(
        const std::string& prompt,
        const GenerationState* prev_state = nullptr) const;
    
    // Cache management
    bool LoadCachedPrefix(GenerationState& state);
    bool StoreCurrentCache(GenerationState& state);
    
    // Statistics
    struct Stats {
        uint64_t total_tokens_generated;
        uint64_t total_cache_hits;
        uint64_t total_cache_misses;
        uint64_t total_generation_time_ms;
        float avg_tokens_per_second;
        float cache_hit_rate;
    };
    
    Stats GetStats() const;
    void ResetStats();
    
    // Configuration
    void SetCacheEnabled(bool enabled) { cache_enabled_ = enabled; }
    bool GetCacheEnabled() const { return cache_enabled_; }
    
    void SetMaxCacheEntries(size_t max_entries);
    void SetMaxCacheMemory(size_t max_memory_mb);
    
    void SetTemperature(float temp) { temperature_ = temp; }
    float GetTemperature() const { return temperature_; }
    
    bool IsInitialized() const { return initialized_; }

private:
    // Internal generation methods
    uint32_t GenerateFirstToken(const std::string& prompt, GenerationState& state);
    uint32_t GenerateSubsequentToken(GenerationState& state);
    
    // Layer processing
    std::vector<float> ProcessLayer(
        uint32_t layer_idx,
        const std::vector<float>& inputs,
        const GenerationState& state,
        bool use_cache);
    
    // KV cache integration
    bool ExtractKVCache(GenerationState& state);
    bool InjectKVCache(GenerationState& state);
    
    // State validation
    bool ValidateState(const GenerationState& state) const;
    
    // Statistics updates
    void UpdateStats(bool cache_hit, uint64_t generation_time_us);
    
    // Members
    std::shared_ptr<Agent::SovereignInferenceClient> inference_client_;
    std::shared_ptr<KVCacheManager> kv_cache_manager_;
    
    std::atomic<bool> cache_enabled_;
    std::atomic<float> temperature_;
    bool initialized_;
    
    mutable std::mutex state_mutex_;
    mutable std::mutex stats_mutex_;
    
    // Statistics
    std::atomic<uint64_t> total_tokens_generated_;
    std::atomic<uint64_t> total_cache_hits_;
    std::atomic<uint64_t> total_cache_misses_;
    std::atomic<uint64_t> total_generation_time_us_;
};

} // namespace AI
} // namespace RawrXD

#endif // RAWRXD_TRANSFORMER_STACK_ORCHESTRATOR_HPP