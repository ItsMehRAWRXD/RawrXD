#pragma once

#include <atomic>
#include <string>
#include <mutex>
#include <algorithm>

namespace RawrXD {

/**
 * @brief Adaptive Fusion Engine - Self-tuning completion weights
 * 
 * Phase 18B: Uses Stochastic Gradient Descent (SGD) to learn optimal
 * fusion weights between Trie and Semantic search based on user feedback.
 * 
 * Learning Rule:
 *   α_new = α_old + η · (Reward - α_old)
 * 
 * Where:
 *   α = Fusion weight (0.0 = Pure Semantic, 1.0 = Pure Trie)
 *   η = Learning rate (default: 0.01)
 *   Reward = 1.0 for Accept, 0.0 for Dismiss/Ignore
 * 
 * The engine converges toward the user's preference over time,
 * automatically adjusting for different coding styles and contexts.
 */
class AdaptiveFusionEngine {
public:
    /**
     * @brief Singleton accessor
     */
    static AdaptiveFusionEngine& instance();

    /**
     * @brief Get current dynamic fusion weight
     * 
     * @return float Alpha value (0.0 = Pure Semantic, 1.0 = Pure Trie)
     */
    float get_alpha() const { return m_alpha.load(std::memory_order_relaxed); }

    /**
     * @brief Get current learning rate
     */
    float get_learning_rate() const { return m_learning_rate; }

    /**
     * @brief Update fusion weight based on user feedback
     * 
     * Implements SGD update rule:
     *   α_new = α_old + η · (Reward - α_old)
     * 
     * @param reward 1.0 for Accept, 0.0 for Dismiss/Ignore
     */
    void update_weights(float reward);

    /**
     * @brief Set learning rate (for advanced tuning)
     */
    void set_learning_rate(float rate) { m_learning_rate = std::clamp(rate, 0.001f, 0.1f); }

    /**
     * @brief Reset to default state
     */
    void reset();

    /**
     * @brief Persistence - Load state from disk
     * 
     * Loads from: d:\rawrxd\.cache\fusion_weights.json
     * 
     * @return true if state loaded successfully
     */
    bool load_state();

    /**
     * @brief Persistence - Save state to disk
     * 
     * Saves to: d:\rawrxd\.cache\fusion_weights.json
     * 
     * @return true if state saved successfully
     */
    bool save_state() const;

    /**
     * @brief Get default cache path
     */
    static std::string get_default_cache_path();

    /**
     * @brief Set custom cache path
     */
    void set_cache_path(const std::string& path) { m_cache_path = path; }

    /**
     * @brief Get convergence statistics
     */
    struct Stats {
        uint64_t update_count = 0;
        float current_alpha = 0.75f;
        float alpha_variance = 0.0f;  // Measure of stability
        bool is_converged = false;   // Variance below threshold
    };
    Stats get_stats() const;

    // Allow ScopedAlphaOverride to access private members
    friend class ScopedAlphaOverride;

private:
    AdaptiveFusionEngine();
    ~AdaptiveFusionEngine() = default;
    
    // Disable copy/move
    AdaptiveFusionEngine(const AdaptiveFusionEngine&) = delete;
    AdaptiveFusionEngine& operator=(const AdaptiveFusionEngine&) = delete;

    // Core state
    std::atomic<float> m_alpha{0.75f};  // Start with balanced weight
    float m_learning_rate = 0.01f;
    
    // Convergence tracking
    mutable std::mutex m_stats_mutex;
    uint64_t m_update_count = 0;
    float m_alpha_sum = 0.0f;
    float m_alpha_squared_sum = 0.0f;
    static constexpr float CONVERGENCE_THRESHOLD = 0.001f;
    
    // Persistence
    std::string m_cache_path;
    mutable std::mutex m_io_mutex;
};

/**
 * @brief Scoped alpha modifier for A/B testing
 * 
 * Temporarily overrides alpha for a specific completion request,
 * restoring the learned value on destruction.
 */
class ScopedAlphaOverride {
public:
    explicit ScopedAlphaOverride(float temp_alpha);
    ~ScopedAlphaOverride();
    
    // Disable copy/move
    ScopedAlphaOverride(const ScopedAlphaOverride&) = delete;
    ScopedAlphaOverride& operator=(const ScopedAlphaOverride&) = delete;

private:
    float m_original_alpha;
    bool m_active = false;
};

} // namespace RawrXD
