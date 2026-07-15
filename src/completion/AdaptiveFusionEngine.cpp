#include "AdaptiveFusionEngine.h"

#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cmath>

namespace RawrXD {

// =============================================================================
// Singleton Implementation
// =============================================================================

AdaptiveFusionEngine& AdaptiveFusionEngine::instance() {
    static AdaptiveFusionEngine instance;
    return instance;
}

AdaptiveFusionEngine::AdaptiveFusionEngine() {
    // Initialize with default values (no persistence for now)
    m_alpha.store(0.75f, std::memory_order_relaxed);
    m_learning_rate = 0.01f;
    m_update_count = 0;
    m_alpha_sum = 0.0f;
    m_alpha_squared_sum = 0.0f;
}

// =============================================================================
// Core Learning Algorithm
// =============================================================================

void AdaptiveFusionEngine::update_weights(float reward) {
    // Clamp reward to valid range
    reward = std::clamp(reward, 0.0f, 1.0f);
    
    // SGD Update Rule: α_new = α_old + η · (Reward - α_old)
    float current_alpha = m_alpha.load(std::memory_order_relaxed);
    float delta = m_learning_rate * (reward - current_alpha);
    float new_alpha = current_alpha + delta;
    
    // Clamp alpha to valid range [0.0, 1.0]
    new_alpha = std::clamp(new_alpha, 0.0f, 1.0f);
    
    // Atomic update
    m_alpha.store(new_alpha, std::memory_order_relaxed);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_update_count++;
        m_alpha_sum += new_alpha;
        m_alpha_squared_sum += new_alpha * new_alpha;
    }
}

void AdaptiveFusionEngine::reset() {
    m_alpha.store(0.75f, std::memory_order_relaxed);
    m_learning_rate = 0.01f;
    
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_update_count = 0;
        m_alpha_sum = 0.0f;
        m_alpha_squared_sum = 0.0f;
    }
}

// =============================================================================
// Persistence (stubbed - no JSON dependency)
// =============================================================================

std::string AdaptiveFusionEngine::get_default_cache_path() {
    // Stub - persistence disabled
    return "";
}

bool AdaptiveFusionEngine::load_state() {
    // Persistence disabled - using in-memory defaults
    return false;
}

bool AdaptiveFusionEngine::save_state() const {
    // Persistence disabled
    return true;
}

// =============================================================================
// Statistics
// =============================================================================

AdaptiveFusionEngine::Stats AdaptiveFusionEngine::get_stats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    
    Stats stats;
    stats.update_count = m_update_count;
    stats.current_alpha = m_alpha.load(std::memory_order_relaxed);
    
    if (m_update_count > 0) {
        float mean = m_alpha_sum / static_cast<float>(m_update_count);
        float mean_squared = m_alpha_squared_sum / static_cast<float>(m_update_count);
        float variance = mean_squared - (mean * mean);
        stats.alpha_variance = std::max(0.0f, variance);  // Ensure non-negative
        stats.is_converged = stats.alpha_variance < CONVERGENCE_THRESHOLD;
    }
    
    return stats;
}

// =============================================================================
// Scoped Alpha Override
// =============================================================================

ScopedAlphaOverride::ScopedAlphaOverride(float temp_alpha) {
    auto& engine = AdaptiveFusionEngine::instance();
    m_original_alpha = engine.get_alpha();
    
    // Only override if significantly different
    if (std::abs(temp_alpha - m_original_alpha) > 0.01f) {
        engine.m_alpha.store(std::clamp(temp_alpha, 0.0f, 1.0f), std::memory_order_relaxed);
        m_active = true;
    }
}

ScopedAlphaOverride::~ScopedAlphaOverride() {
    if (m_active) {
        AdaptiveFusionEngine::instance().m_alpha.store(
            m_original_alpha, std::memory_order_relaxed
        );
    }
}

} // namespace RawrXD
