#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace RawrXD::Telemetry {
    class FeedbackCollector;
    enum class InteractionSignal;
}

namespace RawrXD::Fusion {

/**
 * @brief Configuration for adaptive fusion learning
 */
struct AdaptiveFusionConfig {
    double learning_rate = 0.01;           // η: Step size for gradient descent
    double momentum = 0.9;                 // β: Momentum for smooth updates
    double min_alpha = 0.1;                // Floor for semantic weight
    double max_alpha = 0.95;               // Ceiling for trie weight
    double initial_alpha = 0.75;           // Starting point (Phase 17 default)
    int confidence_threshold = 10;         // Min samples before adapting
    double decay_factor = 0.999;           // Learning rate decay per update
    std::string weights_path;              // Override default save location
};

/**
 * @brief User persona profile for context-aware fusion
 */
struct UserPersona {
    std::string persona_id;                // Unique identifier
    double avg_trie_preference;            // Historical trie preference
    double avg_semantic_preference;        // Historical semantic preference
    int64_t total_interactions;            // Total feedback signals
    int64_t tab_accepts;                   // Positive signals
    int64_t dismissals;                    // Negative signals
    std::chrono::system_clock::time_point last_updated;
    
    double get_confidence() const;         // 0.0-1.0 based on sample size
};

/**
 * @brief Fusion weight state with momentum
 */
struct FusionState {
    double alpha;                          // Current trie weight
    double velocity;                       // Momentum term
    double learning_rate;                  // Current (possibly decayed) η
    int update_count;                      // Number of updates applied
    double cumulative_reward;              // Running reward sum
    
    FusionState() : alpha(0.75), velocity(0.0), 
                    learning_rate(0.01), update_count(0), 
                    cumulative_reward(0.0) {}
};

/**
 * @brief Adaptive Fusion Engine - Phase 18B
 * 
 * Dynamically adjusts Trie vs Semantic fusion weights based on
 * user feedback signals. Implements online gradient descent with
 * momentum for smooth adaptation.
 * 
 * Mathematical Model:
 *   α_{t+1} = clip(α_t + v_{t+1}, min, max)
 *   v_{t+1} = β·v_t + η·(R - α_t)
 * 
 * Where:
 *   α = trie weight (0.0-1.0)
 *   β = momentum (0.9)
 *   η = learning rate (0.01, decaying)
 *   R = reward signal (1.0 for accept, 0.0 for dismiss)
 */
class AdaptiveFusionEngine {
public:
    /**
     * @brief Get singleton instance
     */
    static AdaptiveFusionEngine& instance();
    
    /**
     * @brief Initialize with configuration
     * @param config Learning parameters
     * @return true if state loaded successfully
     */
    bool initialize(const AdaptiveFusionConfig& config = {});
    
    /**
     * @brief Get current fusion weight
     * @param context_hash Optional context for future per-file weights
     * @return Alpha value (0.0 = pure semantic, 1.0 = pure trie)
     * 
     * Thread-safe: Can be called from completion thread
     */
    double get_weight(const std::string& context_hash = "") const;
    
    /**
     * @brief Get weight with confidence indicator
     * @param confidence_out Set to true if we have enough data
     * @return Current alpha
     */
    double get_weight_confident(bool& confidence_out) const;
    
    /**
     * @brief Update weights based on user feedback
     * @param signal The interaction signal from FeedbackCollector
     * @param context_hash Identifies the autocomplete context
     * @param trie_score Original trie score
     * @param semantic_score Original semantic score
     * 
     * Called by FeedbackCollector when user interacts with suggestion
     */
    void update_from_signal(
        RawrXD::Telemetry::InteractionSignal signal,
        const std::string& context_hash,
        float trie_score = 0.0f,
        float semantic_score = 0.0f
    );
    
    /**
     * @brief Calculate reward from signal
     * @param signal User interaction type
     * @return Reward value (1.0 = accept, 0.0 = dismiss, 0.5 = ignore)
     */
    static double signal_to_reward(RawrXD::Telemetry::InteractionSignal signal);
    
    /**
     * @brief Get current user persona
     */
    UserPersona get_persona() const;
    
    /**
     * @brief Get detailed fusion state
     */
    FusionState get_state() const;
    
    /**
     * @brief Reset to initial state
     */
    void reset();
    
    /**
     * @brief Force save current state to disk
     * @return true if saved successfully
     */
    bool save_state();
    
    /**
     * @brief Register callback for weight changes
     * @param callback Function called when alpha updates
     */
    void on_weight_changed(std::function<void(double)> callback);
    
    /**
     * @brief Shutdown and persist state
     */
    void shutdown();
    
    // Disable copy/move
    AdaptiveFusionEngine(const AdaptiveFusionEngine&) = delete;
    AdaptiveFusionEngine& operator=(const AdaptiveFusionEngine&) = delete;
    AdaptiveFusionEngine(AdaptiveFusionEngine&&) = delete;
    AdaptiveFusionEngine& operator=(AdaptiveFusionEngine&&) = delete;

private:
    AdaptiveFusionEngine();
    ~AdaptiveFusionEngine();
    
    void load_state();                     // Load from JSON
    std::string get_default_weights_path() const;
    void apply_update(double reward);      // Core gradient descent step
    void notify_callbacks();               // Trigger change listeners
    
    // State
    mutable std::mutex m_state_mutex;
    FusionState m_state;
    AdaptiveFusionConfig m_config;
    UserPersona m_persona;
    
    // Callbacks
    std::vector<std::function<void(double)>> m_callbacks;
    std::mutex m_callback_mutex;
    
    // Initialization
    std::atomic<bool> m_initialized{false};
    
    // Constants
    static constexpr double DEFAULT_ALPHA = 0.75;
    static constexpr double REWARD_ACCEPT = 1.0;
    static constexpr double REWARD_DISMISS = 0.0;
    static constexpr double REWARD_IGNORE = 0.5;
    static constexpr double REWARD_EDIT_AFTER = 0.3;  // Partial credit
};

} // namespace RawrXD::Fusion
