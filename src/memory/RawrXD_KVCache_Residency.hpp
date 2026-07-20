//=============================================================================
// Fix 5A Phase 2: KV Cache Residency Integration with NEVM
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// This module connects the Fix #5A KV cache layout to the NEVM residency
// management system, enabling:
//   - Quantized KV tiers (FP16/INT8/INT4)
//   - Sliding window residency (hot/warm/cold)
//   - Head-aware compression
//
// ARCHITECTURAL CONTEXT:
// ====================
// Fix #5A established that memory bandwidth is the bottleneck for KV cache
// performance. The layout is optimal, but 128MB working set exceeds L3 cache.
//
// The solution is not better layout - it's residency management.
// NEVM provides block-granular precision control that we apply to KV cache
// tokens based on their attention importance and recency.
//
// INTEGRATION POINTS:
// ===================
// - Uses NEVM ResidencyStateMachine for token lifecycle
// - Uses PrecisionController for format selection
// - Maintains Fix #5A [head][token][K/V][dim] layout within each tier
//
// See: docs/architecture/Fix_5A_KV_Cache_Findings.md
// See: src/nevm/nevm_residency.hpp
// See: src/nevm/nevm_precision_controller.hpp
//=============================================================================

#pragma once

#include "RawrXD_KVCache_Layout.hpp"
#include "../nevm/nevm_residency.hpp"
#include "../nevm/nevm_precision_controller.hpp"
#include <vector>
#include <memory>
#include <atomic>

namespace RawrXD {
namespace Memory {

//=============================================================================
// KV Cache Residency Configuration
//=============================================================================

struct KVResidencyConfig {
    // Base KV cache config
    KVCacheConfig kv_config;
    
    // Tier boundaries (in tokens from current position)
    // Tokens [current - hot_window, current] stay in FP16
    uint32_t hot_window_size = 512;      // Most recent tokens
    uint32_t warm_window_size = 2048;    // Recent tokens
    uint32_t cold_threshold = 8192;       // Older tokens
    
    // Precision per tier
    NEVM::ISA::PrecisionMode hot_precision = NEVM::ISA::PrecisionMode::FP16;
    NEVM::ISA::PrecisionMode warm_precision = NEVM::ISA::PrecisionMode::Q8_0;
    NEVM::ISA::PrecisionMode cold_precision = NEVM::ISA::PrecisionMode::Q4_0;
    NEVM::ISA::PrecisionMode frozen_precision = NEVM::ISA::PrecisionMode::Q2_0;
    
    // Head-specific compression (some heads matter more)
    bool enable_head_aware_compression = true;
    float head_importance_threshold = 0.7f;  // Heads above this get +1 precision tier
    
    // Async migration
    bool enable_async_migration = true;
    uint32_t migration_batch_size = 64;  // Tokens per batch
    
    // Validation
    bool Validate() const {
        return hot_window_size < warm_window_size && 
               warm_window_size < cold_threshold &&
               cold_threshold <= kv_config.max_seq_len;
    }
};

//=============================================================================
// KV Token Residency State
// Per-token residency tracking for NEVM integration
//=============================================================================

struct KVTokenResidency {
    uint32_t token_idx;           // Position in sequence
    uint32_t head_idx;            // Attention head
    
    // NEVM residency state
    NEVM::ResidencyState k_state;
    NEVM::ResidencyState v_state;
    
    // Current precision format
    NEVM::ISA::PrecisionMode k_format;
    NEVM::ISA::PrecisionMode v_format;
    
    // Physical storage
    void* k_data;                 // May be compressed
    void* v_data;
    size_t k_size;                // Actual bytes used
    size_t v_size;
    
    // Access statistics for migration decisions
    std::atomic<uint64_t> access_count{0};
    std::atomic<uint64_t> last_access_tick{0};
    float attention_score;        // Average attention weight (for importance)
    
    // Migration tracking
    bool migration_pending;
    uint32_t target_tier;
    
    KVTokenResidency() : token_idx(0), head_idx(0),
                         k_state(NEVM::ResidencyState::INVALID),
                         v_state(NEVM::ResidencyState::INVALID),
                         k_format(NEVM::ISA::PrecisionMode::FP16),
                         v_format(NEVM::ISA::PrecisionMode::FP16),
                         k_data(nullptr), v_data(nullptr),
                         k_size(0), v_size(0),
                         attention_score(0.0f),
                         migration_pending(false),
                         target_tier(0) {}
};

//=============================================================================
// KV Residency Tier
// Manages tokens at a specific precision level
//=============================================================================

class KVResidencyTier {
public:
    enum class TierLevel {
        HOT = 0,    // FP16 - most recent tokens
        WARM = 1,   // Q8 - recent tokens
        COLD = 2,   // Q4 - older tokens
        FROZEN = 3  // Q2 - very old tokens (or paged out)
    };
    
    explicit KVResidencyTier(TierLevel level, const KVResidencyConfig& config);
    ~KVResidencyTier();
    
    // Disable copy, enable move
    KVResidencyTier(const KVResidencyTier&) = delete;
    KVResidencyTier& operator=(const KVResidencyTier&) = delete;
    KVResidencyTier(KVResidencyTier&&) noexcept;
    KVResidencyTier& operator=(KVResidencyTier&&) noexcept;
    
    // Token management
    bool AllocateToken(uint32_t token_idx, uint32_t head_idx);
    void FreeToken(uint32_t token_idx, uint32_t head_idx);
    
    // Data access
    const void* GetK(uint32_t token_idx, uint32_t head_idx) const;
    const void* GetV(uint32_t token_idx, uint32_t head_idx) const;
    bool WriteK(uint32_t token_idx, uint32_t head_idx, const float* data);
    bool WriteV(uint32_t token_idx, uint32_t head_idx, const float* data);
    
    // Residency queries
    TierLevel GetLevel() const { return m_level; }
    NEVM::ISA::PrecisionMode GetPrecision() const { return m_precision; }
    size_t GetMemoryUsed() const { return m_memory_used; }
    uint32_t GetTokenCount() const { return m_token_count; }
    
    // Compression/decompression
    bool CompressFrom(const KVResidencyTier& source, 
                      uint32_t token_idx, uint32_t head_idx);
    bool DecompressTo(KVResidencyTier& target,
                      uint32_t token_idx, uint32_t head_idx);
    
private:
    TierLevel m_level;
    KVResidencyConfig m_config;
    NEVM::ISA::PrecisionMode m_precision;
    
    // Storage (compressed or raw)
    std::unique_ptr<uint8_t[]> m_storage;
    size_t m_storage_size;
    size_t m_memory_used;
    uint32_t m_token_count;
    
    // Token lookup table
    std::vector<std::unique_ptr<KVTokenResidency>> m_tokens;
    
    // Calculate storage requirements
    size_t CalculateTokenSize() const;
    size_t GetStorageOffset(uint32_t token_idx, uint32_t head_idx, bool is_k) const;
};

//=============================================================================
// KV Cache Residency Manager
// Main interface integrating Fix #5A with NEVM
//=============================================================================

class KVCacheResidencyManager {
public:
    explicit KVCacheResidencyManager(const KVResidencyConfig& config);
    ~KVCacheResidencyManager();
    
    // Disable copy, enable move
    KVCacheResidencyManager(const KVCacheResidencyManager&) = delete;
    KVCacheResidencyManager& operator=(const KVCacheResidencyManager&) = delete;
    KVCacheResidencyManager(KVCacheResidencyManager&&) noexcept;
    KVCacheResidencyManager& operator=(KVCacheResidencyManager&&) noexcept;
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Token lifecycle (called during autoregressive decode)
    bool AppendToken(uint32_t seq_len, const float* k_data, const float* v_data);
    bool GetTokenForAttention(uint32_t token_idx, uint32_t head_idx,
                              const void** k_out, const void** v_out,
                              NEVM::ISA::PrecisionMode* format_out);
    
    // Sliding window management
    void UpdateWindow(uint32_t current_seq_len);
    void MigrateTokens(uint32_t current_seq_len);
    
    // Head-aware compression
    void UpdateHeadImportance(uint32_t head_idx, float importance_score);
    float GetHeadImportance(uint32_t head_idx) const;
    
    // Statistics
    struct Stats {
        size_t total_memory_used;
        size_t peak_memory_used;
        uint32_t tokens_in_hot;
        uint32_t tokens_in_warm;
        uint32_t tokens_in_cold;
        uint32_t tokens_in_frozen;
        uint64_t migration_count;
        uint64_t decompression_count;
        float compression_ratio;
        float average_precision;
    };
    Stats GetStats() const;
    void GetDetailedReport(std::string& report) const;
    
    // NEVM integration
    void ConnectToPrecisionController(NEVM::PrecisionController* controller);
    void OnTelemetrySample(const NEVM::PrecisionController::TelemetrySample& sample);
    
    // Emergency memory pressure handling
    void OnMemoryPressure(float pressure_level);
    bool EmergencyEvict(uint32_t target_tokens);
    
private:
    KVResidencyConfig m_config;
    std::unique_ptr<KVResidencyTier> m_tiers[4];  // HOT, WARM, COLD, FROZEN
    
    // Head importance scores (for head-aware compression)
    std::vector<float> m_head_importance;
    std::vector<uint32_t> m_head_precision_boost;
    
    // Current sequence position
    uint32_t m_current_seq_len;
    uint64_t m_tick_counter;
    
    // Statistics
    mutable Stats m_stats;
    
    // NEVM integration
    NEVM::PrecisionController* m_precision_controller;
    
    // Internal helpers
    KVResidencyTier::TierLevel SelectTierForToken(uint32_t token_idx, 
                                                   uint32_t head_idx) const;
    bool MigrateToken(uint32_t token_idx, uint32_t head_idx,
                      KVResidencyTier::TierLevel from_tier,
                      KVResidencyTier::TierLevel to_tier);
    void UpdateStats();
};

//=============================================================================
// Integration Helpers
// Convenience functions for common operations
//=============================================================================

// Create default residency config for a model
KVResidencyConfig MakeResidencyConfig(uint32_t num_heads, uint32_t head_dim,
                                      uint32_t max_seq_len, size_t memory_budget_mb);

// Calculate expected memory usage
size_t CalculateResidencyMemoryUsage(const KVResidencyConfig& config, 
                                      uint32_t seq_len);

// Validate residency configuration
bool ValidateResidencyConfig(const KVResidencyConfig& config, 
                             std::string* error_msg = nullptr);

} // namespace Memory
} // namespace RawrXD
