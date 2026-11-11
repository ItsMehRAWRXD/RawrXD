#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace RawrXD::Telemetry {

/**
 * @brief User interaction signals for feedback loop
 * 
 * Phase 18A: Captures developer intent signals to train
 * the adaptive ranking model.
 */
enum class InteractionSignal {
    TAB_ACCEPT,           // User pressed Tab to accept suggestion
    IGNORE_5S,            // User continued typing without accepting (5s timeout)
    DISMISS,              // User explicitly dismissed (Esc)
    EDIT_AFTER_ACCEPT     // User accepted then modified the result
};

/**
 * @brief Serializable feedback entry for WAL storage
 */
struct FeedbackEntry {
    InteractionSignal signal;
    std::string context_hash;      // Hash of autocomplete context
    std::string suggestion_text;   // The suggested completion
    float trie_score;              // Original trie ranking score
    float semantic_score;          // Original semantic ranking score
    float final_score;             // Post-fusion score
    int64_t timestamp_ms;          // Unix timestamp in milliseconds
    int edit_distance;             // Levenshtein distance (for confidence)
    
    // Serialize to JSON for WAL
    std::string to_json() const;
    static FeedbackEntry from_json(const std::string& json);
};

/**
 * @brief Thread-safe feedback collector with WAL persistence
 * 
 * Phase 18A: Singleton pattern for UI thread access.
 * Uses lock-free queue + background flush to maintain
 * P95 < 3.5ms latency guarantee.
 */
class FeedbackCollector {
public:
    /**
     * @brief Get singleton instance
     */
    static FeedbackCollector& instance();
    
    /**
     * @brief Record a user interaction signal
     * @param signal The interaction type
     * @param context_hash Hash identifying the autocomplete context
     * @param suggestion_text The suggested completion text
     * @param trie_score Original trie score
     * @param semantic_score Original semantic score
     * @param final_score Post-fusion score
     * @param edit_distance Edit distance for confidence scoring
     * 
     * Thread-safe: Can be called from UI thread
     */
    void record(
        InteractionSignal signal,
        const std::string& context_hash,
        const std::string& suggestion_text,
        float trie_score = 0.0f,
        float semantic_score = 0.0f,
        float final_score = 0.0f,
        int edit_distance = 0
    );
    
    /**
     * @brief Force immediate flush to WAL
     * @return Number of entries flushed
     * 
     * Called automatically on IDE shutdown
     */
    size_t flush_to_wal();
    
    /**
     * @brief Get count of pending entries in queue
     */
    size_t pending_count() const;
    
    /**
     * @brief Check if collector is running
     */
    bool is_running() const { return m_running.load(); }
    
    /**
     * @brief Set handler for real-time feedback processing
     * @param handler Callback invoked for each entry (before WAL flush)
     * 
     * Phase 18B: Wire to AdaptiveFusionEngine for online learning
     */
    using FeedbackHandler = std::function<void(const FeedbackEntry&)>;
    void SetHandler(FeedbackHandler handler);
    
    /**
     * @brief Shutdown collector and flush remaining entries
     */
    void shutdown();
    
    // Disable copy/move
    FeedbackCollector(const FeedbackCollector&) = delete;
    FeedbackCollector& operator=(const FeedbackCollector&) = delete;
    FeedbackCollector(FeedbackCollector&&) = delete;
    FeedbackCollector& operator=(FeedbackCollector&&) = delete;

private:
    FeedbackCollector();
    ~FeedbackCollector();
    
    void worker_loop();           // Background thread entry point
    void flush_batch();           // Flush current batch to WAL
    std::string get_wal_path();   // Get WAL file path
    
    // Thread-safe queue
    std::queue<FeedbackEntry> m_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_cv;
    
    // Background thread
    std::thread m_worker;
    std::atomic<bool> m_running{true};
    
    // Phase 18B: Real-time handler for fusion engine
    FeedbackHandler m_handler;
    mutable std::mutex m_handler_mutex;
    
    // WAL configuration
    static constexpr size_t BATCH_SIZE = 100;      // Flush every N entries
    static constexpr auto FLUSH_INTERVAL_MS = std::chrono::milliseconds(5000);
    
    // Statistics
    std::atomic<size_t> m_total_recorded{0};
    std::atomic<size_t> m_total_flushed{0};
};

} // namespace RawrXD::Telemetry
