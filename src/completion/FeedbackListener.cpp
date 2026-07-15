#include "FeedbackListener.h"
#include "AdaptiveFusionEngine.h"

#include <chrono>
#include <algorithm>

namespace RawrXD {

// =============================================================================
// Singleton Implementation
// =============================================================================

FeedbackListener& FeedbackListener::instance() {
    static FeedbackListener instance;
    return instance;
}

bool FeedbackListener::initialize() {
    if (m_initialized) {
        return true;
    }
    
    // Initialize sliding window
    m_event_window.fill(false);
    m_window_index = 0;
    m_window_count = 0;
    
    m_initialized = true;
    return true;
}

// =============================================================================
// Event Processing
// =============================================================================

void FeedbackListener::on_feedback(const FeedbackEvent& event) {
    if (!m_initialized) {
        return;
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_total_events++;
        
        float reward = event_to_reward(event.type);
        m_reward_sum += reward;
        
        switch (event.type) {
            case FeedbackEventType::TAB_ACCEPT:
            case FeedbackEventType::CLICK_ACCEPT:
            case FeedbackEventType::PARTIAL_ACCEPT:
                m_accept_count++;
                update_accept_rate(true);
                break;
                
            case FeedbackEventType::DISMISS:
            case FeedbackEventType::EXPLICIT_REJECT:
                m_dismiss_count++;
                update_accept_rate(false);
                break;
                
            case FeedbackEventType::IGNORE:
                m_ignore_count++;
                update_accept_rate(false);
                break;
                
            default:
                break;
        }
    }
    
    // Update fusion weights if learning enabled
    if (m_learning_enabled) {
        float reward = event_to_reward(event.type);
        
        // Adjust reward based on source
        // If user accepted a semantic suggestion, reward should push alpha toward semantic (0.0)
        // If user accepted a trie suggestion, reward should push alpha toward trie (1.0)
        float adjusted_reward = reward;
        if (event.source == "semantic") {
            // For semantic: reward=1.0 means prefer semantic (alpha->0.0)
            adjusted_reward = 1.0f - reward;  // Invert: accept semantic = 0.0 alpha
        } else if (event.source == "trie") {
            // For trie: reward=1.0 means prefer trie (alpha->1.0)
            adjusted_reward = reward;  // Keep as-is
        } else {
            // Hybrid or unknown - use neutral
            adjusted_reward = 0.5f;
        }
        
        AdaptiveFusionEngine::instance().update_weights(adjusted_reward);
    }
    
    // Notify callbacks
    {
        std::lock_guard<std::mutex> lock(m_callback_mutex);
        for (const auto& [id, callback] : m_callbacks) {
            if (callback) {
                callback(event);
            }
        }
    }
}

// =============================================================================
// Callback Management
// =============================================================================

int FeedbackListener::register_callback(EventCallback callback) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    int id = m_next_callback_id++;
    m_callbacks[id] = std::move(callback);
    return id;
}

void FeedbackListener::unregister_callback(int callback_id) {
    std::lock_guard<std::mutex> lock(m_callback_mutex);
    m_callbacks.erase(callback_id);
}

// =============================================================================
// Reward Mapping
// =============================================================================

void FeedbackListener::set_reward_mapping(FeedbackEventType event_type, float reward) {
    int index = static_cast<int>(event_type);
    if (index >= 0 && index < 6) {
        m_reward_map[index] = std::clamp(reward, 0.0f, 1.0f);
    }
}

float FeedbackListener::get_reward_mapping(FeedbackEventType event_type) const {
    int index = static_cast<int>(event_type);
    if (index >= 0 && index < 6) {
        return m_reward_map[index];
    }
    return 0.5f;
}

float FeedbackListener::event_to_reward(FeedbackEventType type) const {
    return get_reward_mapping(type);
}

// =============================================================================
// Statistics
// =============================================================================

void FeedbackListener::update_accept_rate(bool accepted) {
    // Add to sliding window
    m_event_window[m_window_index] = accepted;
    m_window_index = (m_window_index + 1) % WINDOW_SIZE;
    if (m_window_count < WINDOW_SIZE) {
        m_window_count++;
    }
}

FeedbackListener::Stats FeedbackListener::get_stats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    
    Stats stats;
    stats.total_events = m_total_events;
    stats.accept_count = m_accept_count;
    stats.dismiss_count = m_dismiss_count;
    stats.ignore_count = m_ignore_count;
    
    if (m_total_events > 0) {
        stats.average_reward = m_reward_sum / static_cast<float>(m_total_events);
    }
    
    // Calculate recent accept rate from sliding window
    if (m_window_count > 0) {
        int accepts = 0;
        for (size_t i = 0; i < m_window_count; ++i) {
            if (m_event_window[i]) accepts++;
        }
        stats.recent_accept_rate = static_cast<float>(accepts) / static_cast<float>(m_window_count);
    }
    
    return stats;
}

void FeedbackListener::reset_stats() {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    m_total_events = 0;
    m_accept_count = 0;
    m_dismiss_count = 0;
    m_ignore_count = 0;
    m_reward_sum = 0.0f;
    m_window_count = 0;
    m_window_index = 0;
    m_event_window.fill(false);
}

// =============================================================================
// Scoped Subscription
// =============================================================================

ScopedFeedbackSubscription::ScopedFeedbackSubscription(FeedbackListener::EventCallback callback) {
    m_callback_id = FeedbackListener::instance().register_callback(std::move(callback));
}

ScopedFeedbackSubscription::~ScopedFeedbackSubscription() {
    if (m_callback_id >= 0) {
        FeedbackListener::instance().unregister_callback(m_callback_id);
    }
}

} // namespace RawrXD
