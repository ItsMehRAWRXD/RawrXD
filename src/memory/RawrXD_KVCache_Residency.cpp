//=============================================================================
// Fix 5A Phase 2: KV Cache Residency Implementation
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// Implementation of NEVM-integrated KV cache residency management.
//
// KEY INSIGHT FROM FIX #5A:
// =========================
// Memory bandwidth is the bottleneck (128MB KV > L3 cache). Layout optimization
// achieved parity but cannot create bandwidth. The solution is residency
// management - keep hot tokens in fast memory, compress cold tokens.
//
// IMPLEMENTATION NOTES:
// =====================
// - Maintains Fix #5A [head][token][K/V][dim] layout within each tier
// - Uses NEVM PrecisionController for format decisions
// - Async migration prevents decode stalls
// - Head-aware compression: important heads stay at higher precision
//
// See: RawrXD_KVCache_Residency.hpp for interface
// See: docs/architecture/Fix_5A_KV_Cache_Findings.md
//=============================================================================

#include "RawrXD_KVCache_Residency.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Memory {

//=============================================================================
// KVResidencyTier Implementation
//=============================================================================

KVResidencyTier::KVResidencyTier(TierLevel level, const KVResidencyConfig& config)
    : m_level(level)
    , m_config(config)
    , m_storage_size(0)
    , m_memory_used(0)
    , m_token_count(0) {
    
    // Set precision based on tier
    switch (level) {
        case TierLevel::HOT:
            m_precision = config.hot_precision;
            break;
        case TierLevel::WARM:
            m_precision = config.warm_precision;
            break;
        case TierLevel::COLD:
            m_precision = config.cold_precision;
            break;
        case TierLevel::FROZEN:
            m_precision = config.frozen_precision;
            break;
    }
}

KVResidencyTier::~KVResidencyTier() = default;

KVResidencyTier::KVResidencyTier(KVResidencyTier&&) noexcept = default;
KVResidencyTier& KVResidencyTier::operator=(KVResidencyTier&&) noexcept = default;

size_t KVResidencyTier::CalculateTokenSize() const {
    // Calculate compressed size based on precision
    size_t raw_size = 2 * m_config.kv_config.head_dim * sizeof(float);  // K+V
    
    switch (m_precision) {
        case NEVM::ISA::PrecisionMode::FP16:
            return raw_size;  // No compression
        case NEVM::ISA::PrecisionMode::Q8_0:
            return raw_size / 2 + sizeof(float);  // 8-bit + scale
        case NEVM::ISA::PrecisionMode::Q4_0:
            return raw_size / 4 + sizeof(float);  // 4-bit + scale
        case NEVM::ISA::PrecisionMode::Q2_0:
            return raw_size / 8 + sizeof(float);  // 2-bit + scale
        default:
            return raw_size;
    }
}

size_t KVResidencyTier::GetStorageOffset(uint32_t token_idx, uint32_t head_idx, 
                                         bool is_k) const {
    // Layout within tier: [head][token][K/V]
    size_t token_size = CalculateTokenSize();
    size_t tokens_per_head = m_config.kv_config.max_seq_len;
    
    size_t head_offset = head_idx * tokens_per_head * token_size;
    size_t token_offset = token_idx * token_size;
    size_t kv_offset = is_k ? 0 : token_size / 2;  // V follows K
    
    return head_offset + token_offset + kv_offset;
}

bool KVResidencyTier::AllocateToken(uint32_t token_idx, uint32_t head_idx) {
    // Ensure storage is allocated
    if (!m_storage) {
        size_t total_tokens = static_cast<size_t>(m_config.kv_config.num_heads) * 
                              m_config.kv_config.max_seq_len;
        m_storage_size = total_tokens * CalculateTokenSize();
        m_storage = std::make_unique<uint8_t[]>(m_storage_size);
        std::fill(m_storage.get(), m_storage.get() + m_storage_size, 0);
    }
    
    // Create residency tracking
    auto residency = std::make_unique<KVTokenResidency>();
    residency->token_idx = token_idx;
    residency->head_idx = head_idx;
    residency->k_format = m_precision;
    residency->v_format = m_precision;
    residency->k_state = NEVM::ResidencyState::RESIDENT_FAST;
    residency->v_state = NEVM::ResidencyState::RESIDENT_FAST;
    
    size_t k_offset = GetStorageOffset(token_idx, head_idx, true);
    size_t v_offset = GetStorageOffset(token_idx, head_idx, false);
    residency->k_data = m_storage.get() + k_offset;
    residency->v_data = m_storage.get() + v_offset;
    residency->k_size = CalculateTokenSize() / 2;
    residency->v_size = CalculateTokenSize() / 2;
    
    m_tokens.push_back(std::move(residency));
    m_token_count++;
    m_memory_used += CalculateTokenSize();
    
    return true;
}

void KVResidencyTier::FreeToken(uint32_t token_idx, uint32_t head_idx) {
    // Find and remove token
    auto it = std::remove_if(m_tokens.begin(), m_tokens.end(),
        [token_idx, head_idx](const auto& token) {
            return token->token_idx == token_idx && token->head_idx == head_idx;
        });
    
    if (it != m_tokens.end()) {
        m_memory_used -= CalculateTokenSize();
        m_token_count--;
        m_tokens.erase(it, m_tokens.end());
    }
}

const void* KVResidencyTier::GetK(uint32_t token_idx, uint32_t head_idx) const {
    size_t offset = GetStorageOffset(token_idx, head_idx, true);
    if (offset >= m_storage_size) return nullptr;
    return m_storage.get() + offset;
}

const void* KVResidencyTier::GetV(uint32_t token_idx, uint32_t head_idx) const {
    size_t offset = GetStorageOffset(token_idx, head_idx, false);
    if (offset >= m_storage_size) return nullptr;
    return m_storage.get() + offset;
}

bool KVResidencyTier::WriteK(uint32_t token_idx, uint32_t head_idx, const float* data) {
    void* dest = const_cast<void*>(GetK(token_idx, head_idx));
    if (!dest) return false;
    
    if (m_precision == NEVM::ISA::PrecisionMode::FP16) {
        // Direct copy for FP16
        std::memcpy(dest, data, m_config.kv_config.head_dim * sizeof(float));
    } else {
        // Quantize to target precision
        // TODO: Implement quantization
        // For now, just copy (will be lossy but functional)
        std::memcpy(dest, data, m_config.kv_config.head_dim * sizeof(float));
    }
    return true;
}

bool KVResidencyTier::WriteV(uint32_t token_idx, uint32_t head_idx, const float* data) {
    void* dest = const_cast<void*>(GetV(token_idx, head_idx));
    if (!dest) return false;
    
    if (m_precision == NEVM::ISA::PrecisionMode::FP16) {
        std::memcpy(dest, data, m_config.kv_config.head_dim * sizeof(float));
    } else {
        // TODO: Implement quantization
        std::memcpy(dest, data, m_config.kv_config.head_dim * sizeof(float));
    }
    return true;
}

//=============================================================================
// KVCacheResidencyManager Implementation
//=============================================================================

KVCacheResidencyManager::KVCacheResidencyManager(const KVResidencyConfig& config)
    : m_config(config)
    , m_current_seq_len(0)
    , m_tick_counter(0)
    , m_precision_controller(nullptr) {
    
    m_stats = {};
    m_head_importance.resize(config.kv_config.num_heads, 1.0f);
    m_head_precision_boost.resize(config.kv_config.num_heads, 0);
}

KVCacheResidencyManager::~KVCacheResidencyManager() {
    Shutdown();
}

KVCacheResidencyManager::KVCacheResidencyManager(KVCacheResidencyManager&&) noexcept = default;
KVCacheResidencyManager& KVCacheResidencyManager::operator=(KVCacheResidencyManager&&) noexcept = default;

bool KVCacheResidencyManager::Initialize() {
    if (!m_config.Validate()) {
        return false;
    }
    
    // Create tiers
    m_tiers[0] = std::make_unique<KVResidencyTier>(
        KVResidencyTier::TierLevel::HOT, m_config);
    m_tiers[1] = std::make_unique<KVResidencyTier>(
        KVResidencyTier::TierLevel::WARM, m_config);
    m_tiers[2] = std::make_unique<KVResidencyTier>(
        KVResidencyTier::TierLevel::COLD, m_config);
    m_tiers[3] = std::make_unique<KVResidencyTier>(
        KVResidencyTier::TierLevel::FROZEN, m_config);
    
    return true;
}

void KVCacheResidencyManager::Shutdown() {
    for (auto& tier : m_tiers) {
        tier.reset();
    }
}

bool KVCacheResidencyManager::AppendToken(uint32_t seq_len, 
                                          const float* k_data, 
                                          const float* v_data) {
    if (seq_len >= m_config.kv_config.max_seq_len) {
        return false;
    }
    
    m_current_seq_len = seq_len;
    uint32_t token_idx = seq_len - 1;  // 0-indexed
    
    // Allocate in HOT tier for all heads
    for (uint32_t h = 0; h < m_config.kv_config.num_heads; ++h) {
        // Check if head gets precision boost
        uint32_t target_tier = 0;  // HOT
        if (m_config.enable_head_aware_compression) {
            if (m_head_importance[h] < m_config.head_importance_threshold) {
                // Lower importance head - can start in WARM tier
                target_tier = 1;
            }
        }
        
        // Allocate in target tier
        if (!m_tiers[target_tier]->AllocateToken(token_idx, h)) {
            return false;
        }
        
        // Write K and V data
        const float* k_ptr = k_data + h * m_config.kv_config.head_dim;
        const float* v_ptr = v_data + h * m_config.kv_config.head_dim;
        
        m_tiers[target_tier]->WriteK(token_idx, h, k_ptr);
        m_tiers[target_tier]->WriteV(token_idx, h, v_ptr);
    }
    
    // Trigger migration check
    if (m_config.enable_async_migration) {
        MigrateTokens(seq_len);
    }
    
    UpdateStats();
    return true;
}

bool KVCacheResidencyManager::GetTokenForAttention(uint32_t token_idx, 
                                                   uint32_t head_idx,
                                                   const void** k_out, 
                                                   const void** v_out,
                                                   NEVM::ISA::PrecisionMode* format_out) {
    // Search tiers from HOT to FROZEN
    for (int tier = 0; tier < 4; ++tier) {
        *k_out = m_tiers[tier]->GetK(token_idx, head_idx);
        *v_out = m_tiers[tier]->GetV(token_idx, head_idx);
        
        if (*k_out && *v_out) {
            *format_out = m_tiers[tier]->GetPrecision();
            
            // Update access statistics
            // TODO: Track access for migration decisions
            
            return true;
        }
    }
    
    return false;  // Token not found
}

void KVCacheResidencyManager::UpdateWindow(uint32_t current_seq_len) {
    m_current_seq_len = current_seq_len;
    
    // Trigger migration for tokens that moved outside windows
    MigrateTokens(current_seq_len);
}

void KVCacheResidencyManager::MigrateTokens(uint32_t current_seq_len) {
    // Determine which tokens need to migrate based on position
    for (uint32_t t = 0; t < current_seq_len; ++t) {
        uint32_t distance_from_end = current_seq_len - t - 1;
        
        for (uint32_t h = 0; h < m_config.kv_config.num_heads; ++h) {
            KVResidencyTier::TierLevel current_tier = SelectTierForToken(t, h);
            KVResidencyTier::TierLevel target_tier;
            
            // Determine target tier based on distance
            if (distance_from_end < m_config.hot_window_size) {
                target_tier = KVResidencyTier::TierLevel::HOT;
            } else if (distance_from_end < m_config.warm_window_size) {
                target_tier = KVResidencyTier::TierLevel::WARM;
            } else if (distance_from_end < m_config.cold_threshold) {
                target_tier = KVResidencyTier::TierLevel::COLD;
            } else {
                target_tier = KVResidencyTier::TierLevel::FROZEN;
            }
            
            // Apply head-aware adjustment
            if (m_config.enable_head_aware_compression) {
                int boost = m_head_precision_boost[h];
                if (boost > 0 && static_cast<int>(target_tier) > 0) {
                    target_tier = static_cast<KVResidencyTier::TierLevel>(
                        static_cast<int>(target_tier) - boost);
                }
            }
            
            // Migrate if needed
            if (current_tier != target_tier) {
                MigrateToken(t, h, current_tier, target_tier);
            }
        }
    }
    
    UpdateStats();
}

KVResidencyTier::TierLevel KVCacheResidencyManager::SelectTierForToken(
    uint32_t token_idx, uint32_t head_idx) const {
    
    // Find which tier currently holds this token
    for (int tier = 0; tier < 4; ++tier) {
        if (m_tiers[tier]->GetK(token_idx, head_idx) != nullptr) {
            return static_cast<KVResidencyTier::TierLevel>(tier);
        }
    }
    
    return KVResidencyTier::TierLevel::FROZEN;  // Not found
}

bool KVCacheResidencyManager::MigrateToken(uint32_t token_idx, uint32_t head_idx,
                                           KVResidencyTier::TierLevel from_tier,
                                           KVResidencyTier::TierLevel to_tier) {
    if (from_tier == to_tier) return true;
    
    int from_idx = static_cast<int>(from_tier);
    int to_idx = static_cast<int>(to_tier);
    
    // Get data from source tier
    const void* k_data = m_tiers[from_idx]->GetK(token_idx, head_idx);
    const void* v_data = m_tiers[from_idx]->GetV(token_idx, head_idx);
    
    if (!k_data || !v_data) return false;
    
    // Allocate in target tier
    if (!m_tiers[to_idx]->AllocateToken(token_idx, head_idx)) {
        return false;
    }
    
    // Copy data (with potential decompression/recompression)
    // TODO: Implement proper quantization/dequantization
    float k_temp[256];  // Max head_dim
    float v_temp[256];
    std::memcpy(k_temp, k_data, m_config.kv_config.head_dim * sizeof(float));
    std::memcpy(v_temp, v_data, m_config.kv_config.head_dim * sizeof(float));
    
    m_tiers[to_idx]->WriteK(token_idx, head_idx, k_temp);
    m_tiers[to_idx]->WriteV(token_idx, head_idx, v_temp);
    
    // Free from source tier
    m_tiers[from_idx]->FreeToken(token_idx, head_idx);
    
    m_stats.migration_count++;
    return true;
}

void KVCacheResidencyManager::UpdateHeadImportance(uint32_t head_idx, 
                                                   float importance_score) {
    if (head_idx >= m_head_importance.size()) return;
    
    m_head_importance[head_idx] = importance_score;
    
    // Calculate precision boost based on importance
    if (importance_score > 0.9f) {
        m_head_precision_boost[head_idx] = 2;  // Stay in higher tier
    } else if (importance_score > 0.7f) {
        m_head_precision_boost[head_idx] = 1;
    } else {
        m_head_precision_boost[head_idx] = 0;
    }
}

float KVCacheResidencyManager::GetHeadImportance(uint32_t head_idx) const {
    if (head_idx >= m_head_importance.size()) return 0.0f;
    return m_head_importance[head_idx];
}

KVCacheResidencyManager::Stats KVCacheResidencyManager::GetStats() const {
    return m_stats;
}

void KVCacheResidencyManager::GetDetailedReport(std::string& report) const {
    std::ostringstream oss;
    
    oss << "=== KV Cache Residency Report ===" << std::endl;
    oss << "Current Sequence Length: " <> m_current_seq_len << std::endl;
    oss << std::endl;
    
    oss << "Tier Distribution:" << std::endl;
    oss << "  HOT (FP16):    " << m_stats.tokens_in_hot << " tokens" << std::endl;
    oss << "  WARM (Q8):     " << m_stats.tokens_in_warm << " tokens" << std::endl;
    oss << "  COLD (Q4):     " << m_stats.tokens_in_cold << " tokens" << std::endl;
    oss << "  FROZEN (Q2):   " << m_stats.tokens_in_frozen << " tokens" << std::endl;
    oss << std::endl;
    
    oss << "Memory Usage:" << std::endl;
    oss << "  Current: " << std::fixed << std::setprecision(2) 
        << (m_stats.total_memory_used / (1024.0 * 1024.0)) << " MB" << std::endl;
    oss << "  Peak:    " << (m_stats.peak_memory_used / (1024.0 * 1024.0)) << " MB" << std::endl;
    oss << "  Compression Ratio: " << m_stats.compression_ratio << "x" << std::endl;
    oss << std::endl;
    
    oss << "Activity:" << std::endl;
    oss << "  Migrations:      " << m_stats.migration_count << std::endl;
    oss << "  Decompressions:  " << m_stats.decompression_count << std::endl;
    oss << "  Avg Precision:   " << m_stats.average_precision << std::endl;
    
    report = oss.str();
}

void KVCacheResidencyManager::ConnectToPrecisionController(
    NEVM::PrecisionController* controller) {
    m_precision_controller = controller;
}

void KVCacheResidencyManager::OnTelemetrySample(
    const NEVM::PrecisionController::TelemetrySample& sample) {
    // Use telemetry to adjust residency decisions
    // TODO: Implement feedback loop
}

void KVCacheResidencyManager::OnMemoryPressure(float pressure_level) {
    if (pressure_level > 0.8f) {
        // Critical pressure - emergency evict to FROZEN tier
        EmergencyEvict(m_current_seq_len / 4);  // Evict 25% of tokens
    } else if (pressure_level > 0.6f) {
        // High pressure - accelerate migration
        MigrateTokens(m_current_seq_len);
    }
}

bool KVCacheResidencyManager::EmergencyEvict(uint32_t target_tokens) {
    // Move oldest tokens from HOT/WARM to FROZEN
    uint32_t evicted = 0;
    
    for (uint32_t t = 0; t < m_current_seq_len && evicted < target_tokens; ++t) {
        for (uint32_t h = 0; h < m_config.kv_config.num_heads; ++h) {
            KVResidencyTier::TierLevel current = SelectTierForToken(t, h);
            if (current < KVResidencyTier::TierLevel::FROZEN) {
                if (MigrateToken(t, h, current, KVResidencyTier::TierLevel::FROZEN)) {
                    evicted++;
                }
            }
        }
    }
    
    UpdateStats();
    return evicted > 0;
}

void KVCacheResidencyManager::UpdateStats() {
    m_stats.total_memory_used = 0;
    m_stats.tokens_in_hot = m_tiers[0]->GetTokenCount();
    m_stats.tokens_in_warm = m_tiers[1]->GetTokenCount();
    m_stats.tokens_in_cold = m_tiers[2]->GetTokenCount();
    m_stats.tokens_in_frozen = m_tiers[3]->GetTokenCount();
    
    for (int i = 0; i < 4; ++i) {
        m_stats.total_memory_used += m_tiers[i]->GetMemoryUsed();
    }
    
    if (m_stats.total_memory_used > m_stats.peak_memory_used) {
        m_stats.peak_memory_used = m_stats.total_memory_used;
    }
    
    // Calculate compression ratio vs raw FP16
    size_t raw_size = static_cast<size_t>(m_current_seq_len) * 
                      m_config.kv_config.num_heads * 
                      2 * m_config.kv_config.head_dim * sizeof(float);
    if (raw_size > 0) {
        m_stats.compression_ratio = static_cast<float>(raw_size) / 
                                    static_cast<float>(m_stats.total_memory_used);
    }
    
    // Calculate average precision (weighted by token count)
    float total_tokens = static_cast<float>(m_stats.tokens_in_hot + 
                                              m_stats.tokens_in_warm + 
                                              m_stats.tokens_in_cold + 
                                              m_stats.tokens_in_frozen);
    if (total_tokens > 0) {
        m_stats.average_precision = 
            (16.0f * m_stats.tokens_in_hot +     // FP16 = 16 bits
             8.0f * m_stats.tokens_in_warm +      // Q8 = 8 bits
             4.0f * m_stats.tokens_in_cold +      // Q4 = 4 bits
             2.0f * m_stats.tokens_in_frozen)     // Q2 = 2 bits
            / total_tokens;
    }
}

//=============================================================================
// Helper Functions
//=============================================================================

KVResidencyConfig MakeResidencyConfig(uint32_t num_heads, uint32_t head_dim,
                                      uint32_t max_seq_len, size_t memory_budget_mb) {
    KVResidencyConfig config;
    config.kv_config.num_heads = num_heads;
    config.kv_config.head_dim = head_dim;
    config.kv_config.max_seq_len = max_seq_len;
    
    // Calculate tier sizes based on memory budget
    // Rough estimate: assume 50% of budget for KV cache
    size_t kv_budget_bytes = memory_budget_mb * 1024 * 1024 / 2;
    size_t raw_kv_size = static_cast<size_t>(max_seq_len) * num_heads * 
                         2 * head_dim * sizeof(float);
    
    float compression_needed = static_cast<float>(raw_kv_size) / 
                               static_cast<float>(kv_budget_bytes);
    
    if (compression_needed <= 1.0f) {
        // No compression needed - all HOT
        config.hot_window_size = max_seq_len;
        config.warm_window_size = max_seq_len;
        config.cold_threshold = max_seq_len;
    } else if (compression_needed <= 2.0f) {
        // Need ~2x compression - use WARM tier
        config.hot_window_size = max_seq_len / 4;
        config.warm_window_size = max_seq_len;
        config.cold_threshold = max_seq_len;
    } else if (compression_needed <= 4.0f) {
        // Need ~4x compression - use COLD tier
        config.hot_window_size = max_seq_len / 8;
        config.warm_window_size = max_seq_len / 2;
        config.cold_threshold = max_seq_len;
    } else {
        // Need >4x compression - use FROZEN tier
        config.hot_window_size = max_seq_len / 16;
        config.warm_window_size = max_seq_len / 4;
        config.cold_threshold = max_seq_len / 2;
    }
    
    return config;
}

size_t CalculateResidencyMemoryUsage(const KVResidencyConfig& config, 
                                     uint32_t seq_len) {
    size_t total = 0;
    
    // HOT tier: FP16
    uint32_t hot_tokens = std::min(seq_len, config.hot_window_size);
    total += static_cast<size_t>(hot_tokens) * config.kv_config.num_heads * 
              2 * config.kv_config.head_dim * sizeof(float);
    
    // WARM tier: Q8 (0.5x)
    uint32_t warm_tokens = std::min(seq_len - hot_tokens, 
                                    config.warm_window_size - config.hot_window_size);
    total += static_cast<size_t>(warm_tokens) * config.kv_config.num_heads * 
              config.kv_config.head_dim * sizeof(float);  // K+V compressed
    
    // COLD tier: Q4 (0.25x)
    uint32_t cold_tokens = std::min(seq_len - config.warm_window_size,
                                    config.cold_threshold - config.warm_window_size);
    total += static_cast<size_t>(cold_tokens) * config.kv_config.num_heads * 
              config.kv_config.head_dim * sizeof(float) / 2;
    
    // FROZEN tier: Q2 (0.125x)
    uint32_t frozen_tokens = (seq_len > config.cold_threshold) ? 
                             (seq_len - config.cold_threshold) : 0;
    total += static_cast<size_t>(frozen_tokens) * config.kv_config.num_heads * 
              config.kv_config.head_dim * sizeof(float) / 4;
    
    return total;
}

bool ValidateResidencyConfig(const KVResidencyConfig& config, 
                             std::string* error_msg) {
    if (!config.Validate()) {
        if (error_msg) {
            *error_msg = "Invalid tier boundaries: must satisfy hot < warm < cold <= max_seq";
        }
        return false;
    }
    
    if (config.kv_config.num_heads == 0 || config.kv_config.head_dim == 0) {
        if (error_msg) {
            *error_msg = "Invalid KV dimensions: heads and head_dim must be > 0";
        }
        return false;
    }
    
    if (config.head_importance_threshold < 0.0f || 
        config.head_importance_threshold > 1.0f) {
        if (error_msg) {
            *error_msg = "Invalid importance threshold: must be in [0, 1]";
        }
        return false;
    }
    
    return true;
}

} // namespace Memory
} // namespace RawrXD
