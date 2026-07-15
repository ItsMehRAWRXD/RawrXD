#pragma once

#include <functional>
#include <memory>
#include <string>
#include <mutex>
#include <unordered_map>
#include <array>

namespace RawrXD {

// Forward declarations
class AdaptiveFusionEngine;

/**
 * @brief Feedback event types for completion suggestions
 */
enum class FeedbackEventType {
    UNKNOWN = 0,
    TAB_ACCEPT,      // User pressed Tab to accept suggestion
    CLICK_ACCEPT,    // User clicked to accept suggestion
    DISMISS,         // User dismissed suggestion (Esc, typed over, etc.)
    IGNORE,          // Suggestion shown but user continued typing
    PARTIAL_ACCEPT,  // User accepted part of suggestion
    EXPLICIT_REJECT  // User explicitly rejected (e.g., "X" button)
};

/**
 * @brief Feedback event data
 */
struct FeedbackEvent {
    FeedbackEventType type = FeedbackEventType::UNKNOWN;
    std::string suggestion_text;
    std::string query;           // Original query that produced suggestion
    std::string source;          // "trie", "semantic", "hybrid"
    float suggestion_score = 0.0f;
    uint64_t timestamp_ms = 0;
    int latency_ms = 0;          // How long suggestion took to generate
    
    // Context
    std::string file_extension;
    int line_number = 0;
};

/**
 * @brief Feedback Listener - Observer for completion feedback
 * 
 * Phase 18B: Lightweight observer that subscribes to FeedbackCollector
 * and triggers AdaptiveFusionEngine updates based on user actions.
 * 
 * Maps feedback events to rewards:
 *   - Accept (Tab/Click): Reward = 1.0 (prefer this source more)
 *   - Dismiss/Reject: Reward = 0.0 (prefer other sources)
 *   - Ignore: Reward = 0.5 (neutral, minimal update)
 * 
 * The listener maintains a sliding window of recent events to
 * prevent overfitting to short-term fluctuations.
 */
class FeedbackListener {
public:
    using EventCallback = std::function<void(const FeedbackEvent&)>;

    /**
     * @brief Singleton accessor
     */
    static FeedbackListener& instance();

    /**
     * @brief Initialize the listener
     * 
     * Connects to FeedbackCollector and starts listening for events.
     * 
     * @return true if initialization successful
     */
    bool initialize();

    /**
     * @brief Check if listener is active
     */
    bool is_initialized() const { return m_initialized; }

    /**
     * @brief Process a feedback event
     * 
     * Called by FeedbackCollector when user interacts with a suggestion.
     * 
     * @param event The feedback event
     */
    void on_feedback(const FeedbackEvent& event);

    /**
     * @brief Register additional callback for events
     * 
     * @param callback Function to call on each feedback event
     * @return Callback ID for unregistering
     */
    int register_callback(EventCallback callback);
    
    /**
     * @brief Unregister a callback
     * 
     * @param callback_id ID returned by register_callback
     */
    void unregister_callback(int callback_id);

    /**
     * @brief Set reward mapping for event types
     * 
     * Default mapping:
     *   - TAB_ACCEPT: 1.0
     *   - CLICK_ACCEPT: 1.0
     *   - DISMISS: 0.0
     *   - IGNORE: 0.5
     *   - PARTIAL_ACCEPT: 0.7
     *   - EXPLICIT_REJECT: 0.0
     * 
     * @param event_type Event type to configure
     * @param reward Reward value (0.0 - 1.0)
     */
    void set_reward_mapping(FeedbackEventType event_type, float reward);

    /**
     * @brief Get current reward mapping
     */
    float get_reward_mapping(FeedbackEventType event_type) const;

    /**
     * @brief Enable/disable learning
     * 
     * When disabled, events are logged but weights are not updated.
     */
    void set_learning_enabled(bool enabled) { m_learning_enabled = enabled; }
    bool is_learning_enabled() const { return m_learning_enabled; }

    /**
     * @brief Get event statistics
     */
    struct Stats {
        uint64_t total_events = 0;
        uint64_t accept_count = 0;
        uint64_t dismiss_count = 0;
        uint64_t ignore_count = 0;
        float average_reward = 0.5f;
        float recent_accept_rate = 0.5f;  // Last 100 events
    };
    Stats get_stats() const;

    /**
     * @brief Reset statistics
     */
    void reset_stats();

private:
    FeedbackListener() = default;
    ~FeedbackListener() = default;
    
    // Disable copy/move
    FeedbackListener(const FeedbackListener&) = delete;
    FeedbackListener& operator=(const FeedbackListener&) = delete;

    /**
     * @brief Convert event type to reward value
     */
    float event_to_reward(FeedbackEventType type) const;

    /**
     * @brief Update recent accept rate with new event
     */
    void update_accept_rate(bool accepted);

private:
    bool m_initialized = false;
    bool m_learning_enabled = true;
    
    // Reward mapping
    float m_reward_map[6] = {
        0.5f,   // UNKNOWN
        1.0f,   // TAB_ACCEPT
        1.0f,   // CLICK_ACCEPT
        0.0f,   // DISMISS
        0.5f,   // IGNORE
        0.7f    // PARTIAL_ACCEPT
    };
    
    // Statistics
    mutable std::mutex m_stats_mutex;
    uint64_t m_total_events = 0;
    uint64_t m_accept_count = 0;
    uint64_t m_dismiss_count = 0;
    uint64_t m_ignore_count = 0;
    float m_reward_sum = 0.0f;
    
    // Sliding window for recent accept rate (last 100 events)
    static constexpr size_t WINDOW_SIZE = 100;
    std::array<bool, WINDOW_SIZE> m_event_window{};
    size_t m_window_index = 0;
    size_t m_window_count = 0;
    
    // Callbacks
    std::mutex m_callback_mutex;
    int m_next_callback_id = 1;
    std::unordered_map<int, EventCallback> m_callbacks;
};

/**
 * @brief RAII helper for scoped event subscription
 */
class ScopedFeedbackSubscription {
public:
    explicit ScopedFeedbackSubscription(FeedbackListener::EventCallback callback);
    ~ScopedFeedbackSubscription();
    
    // Disable copy/move
    ScopedFeedbackSubscription(const ScopedFeedbackSubscription&) = delete;
    ScopedFeedbackSubscription& operator=(const ScopedFeedbackSubscription&) = delete;

private:
    int m_callback_id = -1;
};

} // namespace RawrXD
