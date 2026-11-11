#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>

namespace RawrXD {

// Forward declarations
class LoRAAdapterManager;
class FeedbackCollector;

/**
 * @brief Trust indicator types for UI badges
 * 
 * Phase 18D: Visual indicators showing suggestion provenance
 */
enum class TrustIndicatorType {
    NONE = 0,           // No special indicator
    LEARNED,            // Learned from user feedback
    PERSONALIZED,       // Adapted to user style
    SEMANTIC,           // Semantic (vector) match
    SYNTACTIC,          // Syntactic (trie) match
    HYBRID,             // Combined semantic + syntactic
    CONFIDENT,          // High confidence prediction
    EXPERIMENTAL        // Low confidence / new pattern
};

/**
 * @brief Trust metadata for explainability
 * 
 * Carried with each completion to inform UI rendering.
 * Lightweight struct for async passing.
 */
struct TrustMetadata {
    // Source identification
    std::string adapter_id;              // LoRA adapter used (if any)
    std::string origin_description;      // Human-readable source
    
    // Confidence metrics
    float confidence_score;                // 0.0 - 1.0
    float trie_contribution;             // Weight from trie path
    float semantic_contribution;         // Weight from semantic path
    float lora_contribution;             // Weight from LoRA adaptation
    
    // Status flags
    bool is_personalized;                // True if user-adapted
    bool is_learning;                    // True if actively training
    bool is_cached;                      // True if from cache
    
    // Training info
    int training_samples;                // Samples used for adaptation
    float training_loss;                 // Current training loss
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;
    
    TrustMetadata() 
        : confidence_score(0.0f)
        , trie_contribution(0.0f)
        , semantic_contribution(0.0f)
        , lora_contribution(0.0f)
        , is_personalized(false)
        , is_learning(false)
        , is_cached(false)
        , training_samples(0)
        , training_loss(0.0f) {}
    
    // Determine indicator type from metadata
    TrustIndicatorType get_indicator_type() const;
    
    // Get human-readable description
    std::string get_description() const;
    
    // Get CSS class for UI styling
    std::string get_css_class() const;
};

/**
 * @brief Completion report for UI consumption
 * 
 * Async notification sent after inference completes.
 */
struct CompletionReport {
    std::string completion_text;         // The suggested completion
    std::string context_hash;            // Identifies the context
    TrustMetadata trust;                 // Explainability metadata
    float latency_ms;                    // Inference latency
    bool was_accepted;                   // User feedback (if known)
    
    CompletionReport() 
        : latency_ms(0.0f)
        , was_accepted(false) {}
};

/**
 * @brief Trust indicator observer interface
 * 
 * UI components implement this to receive async notifications.
 */
class ITrustIndicatorObserver {
public:
    virtual ~ITrustIndicatorObserver() = default;
    
    /**
     * @brief Called when a completion is generated
     * @param report Completion details with trust metadata
     * 
     * Thread: UI thread (async from inference)
     */
    virtual void on_completion_generated(const CompletionReport& report) = 0;
    
    /**
     * @brief Called when training state changes
     * @param adapter_id Adapter being trained
     * @param is_training True if training active
     * @param progress 0.0-1.0 training progress
     */
    virtual void on_training_state_changed(
        const std::string& adapter_id,
        bool is_training,
        float progress
    ) = 0;
    
    /**
     * @brief Called when adapter is swapped
     * @param old_adapter Previous adapter ID
     * @param new_adapter New active adapter ID
     */
    virtual void on_adapter_swapped(
        const std::string& old_adapter,
        const std::string& new_adapter
    ) = 0;
};

/**
 * @brief Trust Indicator System - UI Bridge
 * 
 * Phase 18D: Reactive consumer of inference events.
 * Decouples MASM inference from UI rendering via async observer pattern.
 * 
 * Architecture:
 *   Inference Engine ──► TrustIndicatorSystem ──► UI Observers
 *        (MASM)              (C++ bridge)         (Win32/GDI)
 */
class TrustIndicatorSystem {
public:
    /**
     * @brief Get singleton instance
     */
    static TrustIndicatorSystem& instance();
    
    /**
     * @brief Initialize the trust system
     * @return true if initialized successfully
     */
    bool initialize();
    
    /**
     * @brief Register UI observer
     * @param observer Weak pointer to observer
     * @return Observer ID for unregistering
     */
    int register_observer(std::weak_ptr<ITrustIndicatorObserver> observer);
    
    /**
     * @brief Unregister observer
     * @param observer_id ID returned from register_observer
     */
    void unregister_observer(int observer_id);
    
    /**
     * @brief Report completion generated (called from inference)
     * @param report Completion details
     * 
     * Thread-safe: Can be called from inference thread
     */
    void report_completion(const CompletionReport& report);
    
    /**
     * @brief Report training state change
     * @param adapter_id Adapter being trained
     * @param is_training True if active
     * @param progress Training progress 0.0-1.0
     */
    void report_training_state(
        const std::string& adapter_id,
        bool is_training,
        float progress
    );
    
    /**
     * @brief Report adapter swap
     * @param old_adapter Previous adapter
     * @param new_adapter New adapter
     */
    void report_adapter_swap(
        const std::string& old_adapter,
        const std::string& new_adapter
    );
    
    /**
     * @brief Get current trust metadata for active adapter
     */
    TrustMetadata get_active_metadata() const;
    
    /**
     * @brief Enable/disable trust indicators
     */
    void set_enabled(bool enabled) { m_enabled.store(enabled); }
    bool is_enabled() const { return m_enabled.load(); }
    
    /**
     * @brief Shutdown and cleanup
     */
    void shutdown();
    
    // Disable copy/move
    TrustIndicatorSystem(const TrustIndicatorSystem&) = delete;
    TrustIndicatorSystem& operator=(const TrustIndicatorSystem&) = delete;
    TrustIndicatorSystem(TrustIndicatorSystem&&) = delete;
    TrustIndicatorSystem& operator=(TrustIndicatorSystem&&) = delete;

private:
    TrustIndicatorSystem() = default;
    ~TrustIndicatorSystem();
    
    void notify_observers(const CompletionReport& report);
    void notify_training_state(const std::string& adapter_id, bool is_training, float progress);
    void notify_adapter_swap(const std::string& old_adapter, const std::string& new_adapter);
    
    // Process pending notifications (called on UI thread)
    void process_notifications();
    
    std::atomic<bool> m_enabled{true};
    std::atomic<bool> m_initialized{false};
    
    // Observer management
    mutable std::mutex m_observers_mutex;
    std::vector<std::pair<int, std::weak_ptr<ITrustIndicatorObserver>>> m_observers;
    int m_next_observer_id = 1;
    
    // Active metadata
    mutable std::mutex m_metadata_mutex;
    TrustMetadata m_active_metadata;
    
    // Notification queue (thread-safe)
    struct Notification {
        enum Type { COMPLETION, TRAINING_STATE, ADAPTER_SWAP } type;
        CompletionReport report;
        std::string adapter_id;
        std::string old_adapter;
        std::string new_adapter;
        bool is_training;
        float progress;
    };
    
    std::queue<Notification> m_notification_queue;
    mutable std::mutex m_queue_mutex;
};

/**
 * @brief UI Badge Renderer interface
 * 
 * Platform-specific implementations render trust badges.
 */
class ITrustBadgeRenderer {
public:
    virtual ~ITrustBadgeRenderer() = default;
    
    /**
     * @brief Render trust badge for completion
     * @param x Screen X coordinate
     * @param y Screen Y coordinate
     * @param metadata Trust metadata
     */
    virtual void render_badge(int x, int y, const TrustMetadata& metadata) = 0;
    
    /**
     * @brief Render tooltip on hover
     * @param x Screen X coordinate
     * @param y Screen Y coordinate
     * @param metadata Trust metadata
     */
    virtual void render_tooltip(int x, int y, const TrustMetadata& metadata) = 0;
    
    /**
     * @brief Get badge size for layout
     */
    virtual void get_badge_size(const TrustMetadata& metadata, int& width, int& height) = 0;
};

} // namespace RawrXD
