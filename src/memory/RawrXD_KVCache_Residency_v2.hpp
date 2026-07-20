//=============================================================================
// Fix 5B Phase 2: Page-Based Async KV Cache Residency
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// ARCHITECTURAL REDESIGN based on validation-first approach:
//
// KEY INSIGHTS FROM REVIEW:
// =========================
// 1. Page-based migration reduces bookkeeping (32-64 tokens per page vs individual)
// 2. Async migration prevents decode stalls
// 3. Deterministic policy is easier to validate than adaptive
// 4. Comprehensive logging enables verification of:
//    - No duplicate migrations
//    - No lost pages
//    - No oscillation between tiers
//
// PAGE STRUCTURE:
// ===============
// A KVResidencyPage contains 32-64 tokens (configurable), all at same precision.
// Pages are the unit of migration, not individual tokens.
//
// ASYNC ARCHITECTURE:
// ===================
// Decode Thread          Migration Thread
//      |                        |
//      |-- Use HOT pages ------>|-- Compress old pages
//      |-- Trigger migration    |-- Atomically publish new page
//      |-- Continue decode      |-- Log transition
//      |                        |
//      +------------------------> No decode stalls
//
// DETERMINISTIC POLICY:
// =====================
// Newest 512 tokens:   FP16 (HOT)
// Next 2048 tokens:    Q8  (WARM)
// Remaining:           Q4  (COLD)
//
// Only after this works would adaptive policies be introduced.
//
// VALIDATION LOGGING:
// ===================
// Every transition logged with:
//   - Page ID
//   - Token range
//   - Source/dest tier
//   - Reason (window expired, pressure, etc.)
//   - Latency (μs)
//
// See: docs/architecture/Fix_5B_KV_Residency_Integration.md
//=============================================================================

#pragma once

#include "RawrXD_KVCache_Layout.hpp"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <algorithm>
#include <numeric>

// Define PrecisionMode if NEVM::ISA is not available
namespace NEVM {
namespace ISA {
    enum class PrecisionMode {
        FP16 = 0,
        Q8_0 = 1,
        Q4_0 = 2,
        Q4_K = 3,
        Q2_K = 4,
        UNKNOWN = 5
    };
}
}

namespace RawrXD {
namespace Memory {

//=============================================================================
// Configuration
//=============================================================================

// Compile-time page size configuration
// Allows benchmarking 16, 32, 64 token pages without code changes
template<uint32_t PageTokens = 32>
struct KVResidencyConfigV2 {
    static_assert(PageTokens >= 16 && PageTokens <= 256, 
                  "Page size must be between 16 and 256 tokens");
    
    static constexpr uint32_t TOKENS_PER_PAGE = PageTokens;  // Migration unit
    
    // Tier boundaries (in tokens from current position)
    uint32_t hot_window_tokens = 512;    // FP16
    uint32_t warm_window_tokens = 2048;  // Q8
    // Cold is everything beyond warm
    
    // Async migration
    bool enable_async_migration = true;
    uint32_t migration_batch_size = 4;   // Pages per batch
    
    // Validation logging
    bool enable_detailed_logging = true;
    uint32_t log_buffer_size = 10000;    // Transition log entries
    
    // Memory pressure thresholds
    float pressure_threshold_high = 0.7f;    // Start migrating
    float pressure_threshold_critical = 0.9f; // Emergency eviction
    
    // Validation
    bool Validate() const {
        return hot_window_tokens % TOKENS_PER_PAGE == 0 &&
               warm_window_tokens % TOKENS_PER_PAGE == 0 &&
               hot_window_tokens < warm_window_tokens;
    }
};

// Default page size alias
using KVResidencyConfigV2Default = KVResidencyConfigV2<32>;

//=============================================================================
// Residency Tier Enumeration
//=============================================================================

enum class ResidencyTier : uint8_t {
    INVALID = 0,
    HOT = 1,     // FP16 - most recent
    WARM = 2,    // Q8 - recent
    COLD = 3,    // Q4 - older
    FROZEN = 4   // Q2/paged - very old
};

const char* TierToString(ResidencyTier tier);

//=============================================================================
// Migration Reason
//=============================================================================

enum class MigrationReason : uint8_t {
    WINDOW_EXPIRED = 0,      // Token moved outside window
    MEMORY_PRESSURE = 1,   // Memory pressure triggered
    EMERGENCY_EVICTION = 2, // Critical pressure
    MANUAL = 3,              // Explicit request
    PREFETCH = 4             // Proactive migration
};

const char* ReasonToString(MigrationReason reason);

//=============================================================================
// Page State
//=============================================================================

enum class PageState : uint8_t {
    INVALID = 0,
    RESIDENT = 1,        // Ready for use
    MIGRATING = 2,     // Async migration in progress
    COMPRESSED = 3,      // In compressed tier
    EVICTED = 4          // Paged out
};

//=============================================================================
// KV Residency Page
// The unit of migration - contains multiple tokens
//=============================================================================

struct KVResidencyPage {
    // Identity
    uint64_t page_id;
    uint32_t first_token;      // Global token index
    uint32_t token_count;      // Usually TOKENS_PER_PAGE
    
    // Residency
    ResidencyTier current_tier;
    ResidencyTier target_tier;
    PageState state;
    
    // Precision
    NEVM::ISA::PrecisionMode precision;
    
    // Storage
    void* storage;             // Page data
    size_t storage_size;       // Bytes allocated
    size_t compressed_size;    // Bytes after compression (if compressed)
    
    // Statistics
    std::atomic<uint64_t> access_count{0};
    std::atomic<uint64_t> last_access_tick{0};
    uint64_t migration_count;
    
    // Async migration
    std::atomic<bool> migration_pending{false};
    std::chrono::microseconds last_migration_latency{0};
    
    // Constructor
    KVResidencyPage() : page_id(0), first_token(0), token_count(0),
                        current_tier(ResidencyTier::INVALID),
                        target_tier(ResidencyTier::INVALID),
                        state(PageState::INVALID),
                        precision(NEVM::ISA::PrecisionMode::FP16),
                        storage(nullptr), storage_size(0), compressed_size(0),
                        migration_count(0) {}
};

//=============================================================================
// Migration Request
// Queued for async processing
//=============================================================================

struct MigrationRequest {
    uint64_t page_id;
    ResidencyTier source_tier;
    ResidencyTier target_tier;
    MigrationReason reason;
    uint64_t timestamp;
    uint32_t priority;  // Higher = more urgent
};

//=============================================================================
// Transition Log Entry
// For validation and debugging
//=============================================================================

struct TransitionLogEntry {
    uint64_t timestamp;
    uint64_t page_id;
    uint32_t first_token;
    uint32_t token_count;
    ResidencyTier from_tier;
    ResidencyTier to_tier;
    MigrationReason reason;
    uint64_t latency_us;
    bool success;
    const char* error_msg;  // nullptr if success
};

//=============================================================================
// Residency Statistics
//=============================================================================

struct ResidencyStats {
    // Page counts
    uint32_t pages_in_hot;
    uint32_t pages_in_warm;
    uint32_t pages_in_cold;
    uint32_t pages_in_frozen;
    uint32_t pages_migrating;
    uint32_t total_pages;              // Conservation check: HOT+WARM+COLD+FROZEN+migrating
    
    // Memory
    size_t total_memory_used;
    size_t peak_memory_used;
    float compression_ratio;
    
    // Migration activity
    uint64_t migrations_completed;
    uint64_t migrations_failed;
    uint64_t migrations_queued;
    uint64_t migrations_cancelled;       // Cancelled before completion
    uint64_t migrations_retried;         // Retry count
    uint64_t emergency_evictions;
    
    // Queue metrics
    uint32_t current_queue_depth;
    uint32_t max_queue_depth;            // Peak queue depth observed
    
    // Performance - Migration latency (microseconds)
    double avg_migration_latency_us;
    double p50_migration_latency_us;
    double p95_migration_latency_us;
    double p99_migration_latency_us;
    uint64_t max_migration_latency_us;
    
    // Performance - Decode
    uint64_t decode_stalls;              // Should be 0 with async
    uint64_t cache_misses;               // Page not in expected tier
    
    // Residency hit rates
    uint64_t hot_hits;
    uint64_t warm_hits;
    uint64_t cold_hits;
    uint64_t frozen_hits;
    uint64_t migration_waits;            // Decode blocked on migration
    
    // Page churn (moves per page per minute)
    double page_churn_rate;              // Detect instability
    uint64_t total_page_moves;
    
    // Validation
    uint64_t duplicate_migrations;       // Should be 0
    uint64_t lost_pages;                 // Should be 0
    uint64_t tier_oscillations;          // Should be 0
    uint64_t ownership_violations;       // Should be 0 (page in multiple tiers)
    uint64_t conservation_violations;    // Should be 0 (page count mismatch)
    
    void Reset() {
        pages_in_hot = pages_in_warm = pages_in_cold = pages_in_frozen = pages_migrating = total_pages = 0;
        total_memory_used = peak_memory_used = 0;
        compression_ratio = 0.0f;
        migrations_completed = migrations_failed = migrations_queued = migrations_cancelled = 0;
        migrations_retried = emergency_evictions = 0;
        current_queue_depth = max_queue_depth = 0;
        avg_migration_latency_us = p50_migration_latency_us = p95_migration_latency_us = p99_migration_latency_us = 0.0;
        max_migration_latency_us = 0;
        decode_stalls = cache_misses = 0;
        hot_hits = warm_hits = cold_hits = frozen_hits = migration_waits = 0;
        page_churn_rate = 0.0;
        total_page_moves = 0;
        duplicate_migrations = lost_pages = tier_oscillations = 0;
        ownership_violations = conservation_violations = 0;
    }
};

//=============================================================================
// Page Table
// Manages all pages
//=============================================================================

class KVPageTable {
public:
    explicit KVPageTable(const KVResidencyConfigV2<>& config);
    ~KVPageTable();
    
    // Disable copy
    KVPageTable(const KVPageTable&) = delete;
    KVPageTable& operator=(const KVPageTable&) = delete;
    
    // Page lifecycle
    bool AllocatePage(uint64_t page_id, uint32_t first_token, uint32_t token_count);
    void FreePage(uint64_t page_id);
    
    // Page access
    KVResidencyPage* GetPage(uint64_t page_id);
    KVResidencyPage* FindPageContainingToken(uint32_t token_idx);
    
    // Tier queries
    std::vector<KVResidencyPage*> GetPagesInTier(ResidencyTier tier);
    uint32_t CountPagesInTier(ResidencyTier tier) const;
    
    // Validation
    bool ValidatePageConsistency() const;
    bool ValidatePageConservation(uint32_t& hot, uint32_t& warm, uint32_t& cold, 
                                    uint32_t& frozen, uint32_t& migrating) const;
    bool ValidateSingleOwnership(uint64_t page_id) const;
    uint32_t GetTotalPageCount() const;
    
private:
    KVResidencyConfigV2<> m_config;
    std::vector<std::unique_ptr<KVResidencyPage>> m_pages;
    mutable std::mutex m_mutex;
};

//=============================================================================
// Async Migration Worker
// Background thread for page migration
//=============================================================================

class KVMigrationWorker {
public:
    using MigrationCallback = std::function<void(uint64_t page_id, bool success, 
                                                  uint64_t latency_us)>;
    
    explicit KVMigrationWorker(KVPageTable* page_table);
    ~KVMigrationWorker();
    
    // Control
    void Start();
    void Stop();
    bool IsRunning() const { return m_running; }
    
    // Queue migration
    void QueueMigration(const MigrationRequest& request);
    uint32_t GetQueueDepth() const;
    
    // Set callback for completion notification
    void SetCompletionCallback(MigrationCallback callback);
    
private:
    void WorkerLoop();
    bool ExecuteMigration(const MigrationRequest& request);
    
    KVPageTable* m_page_table;
    std::thread m_worker_thread;
    std::atomic<bool> m_running{false};
    
    std::queue<MigrationRequest> m_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    
    MigrationCallback m_completion_callback;
};

//=============================================================================
// Transition Logger
// Validates residency behavior
//=============================================================================

class KVTransitionLogger {
public:
    explicit KVTransitionLogger(size_t buffer_size = 10000);
    ~KVTransitionLogger();
    
    // Log a transition
    void LogTransition(const TransitionLogEntry& entry);
    
    // Query
    std::vector<TransitionLogEntry> GetRecentTransitions(uint32_t count) const;
    std::vector<TransitionLogEntry> GetTransitionsForPage(uint64_t page_id) const;
    
    // Validation checks
    bool CheckForDuplicates(uint64_t page_id, uint64_t window_ms = 1000) const;
    bool CheckForOscillation(uint64_t page_id, uint32_t min_transitions = 3) const;
    uint32_t CountLostPages(const std::vector<uint64_t>& expected_page_ids) const;
    
    // Statistics
    void GetMigrationStats(uint64_t& total, uint64_t& failed, 
                          double& avg_latency) const;
    
private:
    std::vector<TransitionLogEntry> m_log;
    mutable std::mutex m_mutex;
    size_t m_buffer_size;
    size_t m_write_index;
    bool m_buffer_full;
};

//=============================================================================
// Main Residency Manager (v2)
// Page-based async residency management
//=============================================================================

class KVCacheResidencyManagerV2 {
public:
    explicit KVCacheResidencyManagerV2(const KVResidencyConfigV2<>& config);
    ~KVCacheResidencyManagerV2();
    
    // Disable copy/move
    KVCacheResidencyManagerV2(const KVCacheResidencyManagerV2&) = delete;
    KVCacheResidencyManagerV2& operator=(const KVCacheResidencyManagerV2&) = delete;
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Token lifecycle (called during decode)
    bool AppendTokens(uint32_t seq_len, const float* k_data, const float* v_data);
    bool GetTokenForAttention(uint32_t token_idx, uint32_t head_idx,
                              const void** k_out, const void** v_out,
                              NEVM::ISA::PrecisionMode* format_out);
    
    // Window management (triggers async migration)
    void UpdateWindow(uint32_t current_seq_len);
    void OnMemoryPressure(float pressure_level);
    
    // Statistics and validation
    ResidencyStats GetStats() const;
    void GetDetailedReport(std::string& report) const;
    void DumpTransitionLog(std::string& output) const;
    
    // Validation
    bool RunValidationChecks(std::string& report) const;
    
private:
    // Internal helpers
    ResidencyTier DetermineTargetTier(uint32_t token_idx) const;
    void EvaluateMigrations(uint32_t current_seq_len);
    void QueuePageMigration(uint64_t page_id, ResidencyTier target, MigrationReason reason);
    void OnMigrationComplete(uint64_t page_id, bool success, uint64_t latency_us);
    void UpdateStats();
    
    // Components
    KVResidencyConfigV2<> m_config;
    std::unique_ptr<KVPageTable> m_page_table;
    std::unique_ptr<KVMigrationWorker> m_migration_worker;
    std::unique_ptr<KVTransitionLogger> m_logger;
    
    // State
    uint32_t m_current_seq_len;
    uint64_t m_tick_counter;
    ResidencyStats m_stats;
    
    // Migration latency tracking for percentiles
    mutable std::vector<uint64_t> m_migration_latencies;
    
    // Head importance (for future head-aware compression)
    std::vector<float> m_head_importance;
};

//=============================================================================
// Helper Functions
//=============================================================================

// Calculate number of pages needed for sequence
uint32_t CalculatePageCount(uint32_t seq_len, uint32_t tokens_per_page);

// Calculate which page contains a token
uint32_t GetPageIndexForToken(uint32_t token_idx, uint32_t tokens_per_page);

// Validate configuration
bool ValidateResidencyConfigV2(const KVResidencyConfigV2<>& config, 
                                  std::string* error_msg = nullptr);

} // namespace Memory
} // namespace RawrXD
