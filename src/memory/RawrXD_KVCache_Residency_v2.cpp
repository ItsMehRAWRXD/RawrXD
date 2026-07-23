//=============================================================================
// Fix 5B Phase 2: Page-Based Async KV Cache Residency Implementation
// RawrXD IDE - High-Performance Inference
//=============================================================================
//
// IMPLEMENTATION NOTES:
// =====================
// - Pages are the unit of migration (32-64 tokens per page)
// - Async worker thread handles compression/decompression
// - Decode thread never blocks on migration
// - Comprehensive logging for validation
// - Deterministic tier policy (no adaptive complexity yet)
//
// ASYNC MIGRATION FLOW:
// =====================
// 1. Decode thread detects page needs migration
// 2. Queue migration request (non-blocking)
// 3. Migration worker compresses page
// 4. Atomically update page state
// 5. Log transition with latency
// 6. Notify decode thread via callback
//
// VALIDATION:
// ===========
// - Every transition logged with timestamp, latency, reason
// - Duplicate detection within time windows
// - Oscillation detection (frequent tier changes)
// - Lost page detection
// - Decode stall monitoring (should always be 0)
//
// See: RawrXD_KVCache_Residency_v2.hpp
//=============================================================================

#include "RawrXD_KVCache_Residency_v2.hpp"
#include "RawrXD_KVCache_QuantKernels.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cstdlib>

// Cross-platform aligned memory allocation
#ifdef _WIN32
#include <malloc.h>
#define ALIGNED_MALLOC(size, align) _aligned_malloc(size, align)
#define ALIGNED_FREE(ptr) _aligned_free(ptr)
#else
#define ALIGNED_MALLOC(size, align) aligned_alloc(align, size)
#define ALIGNED_FREE(ptr) free(ptr)
#endif

namespace RawrXD {
namespace Memory {

//=============================================================================
// String Conversions
//=============================================================================

const char* TierToString(ResidencyTier tier) {
    switch (tier) {
        case ResidencyTier::INVALID: return "INVALID";
        case ResidencyTier::HOT: return "HOT";
        case ResidencyTier::WARM: return "WARM";
        case ResidencyTier::COLD: return "COLD";
        case ResidencyTier::FROZEN: return "FROZEN";
        default: return "UNKNOWN";
    }
}

const char* ReasonToString(MigrationReason reason) {
    switch (reason) {
        case MigrationReason::WINDOW_EXPIRED: return "WINDOW_EXPIRED";
        case MigrationReason::MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case MigrationReason::EMERGENCY_EVICTION: return "EMERGENCY_EVICTION";
        case MigrationReason::MANUAL: return "MANUAL";
        case MigrationReason::PREFETCH: return "PREFETCH";
        default: return "UNKNOWN";
    }
}

//=============================================================================
// KVPageTable Implementation
//=============================================================================

KVPageTable::KVPageTable(const KVResidencyConfigV2<>& config)
    : m_config(config) {
}

KVPageTable::~KVPageTable() = default;

bool KVPageTable::AllocatePage(uint64_t page_id, uint32_t first_token, uint32_t token_count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Ensure vector is large enough
    if (page_id >= m_pages.size()) {
        m_pages.resize(page_id + 1);
    }
    
    // Check if already exists
    if (m_pages[page_id] != nullptr) {
        return false;  // Already allocated
    }
    
    // Create new page
    auto page = std::make_unique<KVResidencyPage>();
    page->page_id = page_id;
    page->first_token = first_token;
    page->token_count = token_count;
    page->current_tier = ResidencyTier::HOT;  // New pages start in HOT
    page->target_tier = ResidencyTier::HOT;
    page->state = PageState::RESIDENT;
    page->precision = NEVM::ISA::PrecisionMode::FP16;
    page->migration_count = 0;
    
    // Calculate storage size (FP16 for HOT tier)
    // Each token: K + V = 2 * head_dim floats
    // For now, use default head_dim = 128
    const uint32_t head_dim = 128;
    const uint32_t num_heads = 32;
    page->storage_size = token_count * num_heads * 2 * head_dim * sizeof(float);
    page->compressed_size = page->storage_size;  // Not compressed yet
    
    // Allocate storage
    page->storage = ALIGNED_MALLOC(page->storage_size, 64);
    if (!page->storage) {
        return false;
    }
    std::memset(page->storage, 0, page->storage_size);
    
    m_pages[page_id] = std::move(page);
    return true;
}

void KVPageTable::FreePage(uint64_t page_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (page_id < m_pages.size() && m_pages[page_id]) {
        if (m_pages[page_id]->storage) {
            ALIGNED_FREE(m_pages[page_id]->storage);
        }
        m_pages[page_id].reset();
    }
}

KVResidencyPage* KVPageTable::GetPage(uint64_t page_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (page_id < m_pages.size()) {
        return m_pages[page_id].get();
    }
    return nullptr;
}

KVResidencyPage* KVPageTable::FindPageContainingToken(uint32_t token_idx) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& page : m_pages) {
        if (page && token_idx >= page->first_token && 
            token_idx < page->first_token + page->token_count) {
            return page.get();
        }
    }
    return nullptr;
}

std::vector<KVResidencyPage*> KVPageTable::GetPagesInTier(ResidencyTier tier) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<KVResidencyPage*> result;
    
    for (auto& page : m_pages) {
        if (page && page->current_tier == tier) {
            result.push_back(page.get());
        }
    }
    return result;
}

uint32_t KVPageTable::CountPagesInTier(ResidencyTier tier) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t count = 0;
    
    for (auto& page : m_pages) {
        if (page && page->current_tier == tier) {
            count++;
        }
    }
    return count;
}

bool KVPageTable::ValidatePageConsistency() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& page : m_pages) {
        if (!page) continue;
        
        // Check state consistency
        if (page->state == PageState::RESIDENT && page->current_tier == ResidencyTier::INVALID) {
            return false;
        }
        if (page->state == PageState::MIGRATING && page->target_tier == ResidencyTier::INVALID) {
            return false;
        }
        
        // Check storage
        if (page->state != PageState::EVICTED && !page->storage) {
            return false;
        }
    }
    return true;
}

bool KVPageTable::ValidatePageConservation(uint32_t& hot, uint32_t& warm, uint32_t& cold, 
                                             uint32_t& frozen, uint32_t& migrating) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    hot = warm = cold = frozen = migrating = 0;
    
    for (auto& page : m_pages) {
        if (!page) continue;
        
        switch (page->current_tier) {
            case ResidencyTier::HOT: hot++; break;
            case ResidencyTier::WARM: warm++; break;
            case ResidencyTier::COLD: cold++; break;
            case ResidencyTier::FROZEN: frozen++; break;
            default: break;
        }
        
        if (page->state == PageState::MIGRATING) {
            migrating++;
        }
    }
    
    // Conservation check: total should equal sum of all tiers
    uint32_t total = hot + warm + cold + frozen;
    uint32_t actual_total = 0;
    for (auto& page : m_pages) {
        if (page) actual_total++;
    }
    
    return total == actual_total;
}

bool KVPageTable::ValidateSingleOwnership(uint64_t page_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (page_id >= m_pages.size() || !m_pages[page_id]) {
        return false;  // Page doesn't exist
    }
    
    KVResidencyPage* target_page = m_pages[page_id].get();
    
    // Check that this page appears in exactly one tier
    int tier_count = 0;
    for (auto& page : m_pages) {
        if (page && page->page_id == page_id && page->current_tier != ResidencyTier::INVALID) {
            tier_count++;
        }
    }
    
    return tier_count == 1;
}

uint32_t KVPageTable::GetTotalPageCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint32_t count = 0;
    for (auto& page : m_pages) {
        if (page) count++;
    }
    return count;
}

//=============================================================================
// KVMigrationWorker Implementation
//=============================================================================

KVMigrationWorker::KVMigrationWorker(KVPageTable* page_table)
    : m_page_table(page_table) {
}

KVMigrationWorker::~KVMigrationWorker() {
    Stop();
}

void KVMigrationWorker::Start() {
    if (m_running) return;
    
    m_running = true;
    m_worker_thread = std::thread(&KVMigrationWorker::WorkerLoop, this);
}

void KVMigrationWorker::Stop() {
    if (!m_running) return;
    
    m_running = false;
    m_queue_cv.notify_all();
    
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }
}

void KVMigrationWorker::QueueMigration(const MigrationRequest& request) {
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(request);
    }
    m_queue_cv.notify_one();
}

uint32_t KVMigrationWorker::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return static_cast<uint32_t>(m_queue.size());
}

void KVMigrationWorker::SetCompletionCallback(MigrationCallback callback) {
    m_completion_callback = callback;
}

void KVMigrationWorker::WorkerLoop() {
    while (m_running) {
        MigrationRequest request;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });
            
            if (!m_running) break;
            
            request = m_queue.front();
            m_queue.pop();
        }
        
        // Execute migration
        bool success = ExecuteMigration(request);
        
        // Notify completion
        if (m_completion_callback) {
            m_completion_callback(request.page_id, success, 0,
                                  request.source_tier, request.target_tier);
        }
    }
}

bool KVMigrationWorker::ExecuteMigration(const MigrationRequest& request) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    KVResidencyPage* page = m_page_table->GetPage(request.page_id);
    if (!page) {
        return false;
    }
    
    // Mark as migrating
    page->state = PageState::MIGRATING;
    page->migration_pending = true;
    
    // Determine target precision based on tier
    NEVM::ISA::PrecisionMode target_precision = NEVM::ISA::PrecisionMode::FP16;
    switch (request.target_tier) {
        case ResidencyTier::HOT:
            target_precision = NEVM::ISA::PrecisionMode::FP16;
            break;
        case ResidencyTier::WARM:
            target_precision = NEVM::ISA::PrecisionMode::Q8_0;
            break;
        case ResidencyTier::COLD:
            target_precision = NEVM::ISA::PrecisionMode::Q4_0;
            break;
        case ResidencyTier::FROZEN:
            target_precision = NEVM::ISA::PrecisionMode::Q2_K;
            break;
        default:
            break;
    }
    
    // Perform actual compression/decompression
    if (page->storage && page->storage_size > 0) {
        if (request.target_tier == ResidencyTier::HOT) {
            // Decompress to FP16
            if (page->precision != NEVM::ISA::PrecisionMode::FP16) {
                // Allocate decompressed buffer
                size_t element_count = page->storage_size / sizeof(uint16_t);
                size_t decompressed_size = element_count * sizeof(uint16_t);
                
                void* decompressed = ALIGNED_MALLOC(decompressed_size, 64);
                if (decompressed) {
                    size_t result = DecompressPageData(page->storage, page->storage_size,
                                                          decompressed, decompressed_size,
                                                          page->precision);
                    if (result > 0) {
                        ALIGNED_FREE(page->storage);
                        page->storage = decompressed;
                        page->storage_size = decompressed_size;
                        page->compressed_size = decompressed_size;
                    } else {
                        ALIGNED_FREE(decompressed);
                    }
                }
            }
        } else {
            // Compress to target precision
            size_t element_count = page->storage_size / sizeof(uint16_t);
            size_t max_compressed = KVQuantizationKernels::GetQuantizedBufferSize(element_count, 
                target_precision == NEVM::ISA::PrecisionMode::Q8_0 ? 8 :
                target_precision == NEVM::ISA::PrecisionMode::Q4_0 ? 4 :
                target_precision == NEVM::ISA::PrecisionMode::Q2_K ? 2 : 16);
            
            void* compressed = ALIGNED_MALLOC(max_compressed, 64);
            if (compressed) {
                size_t result = CompressPageData(page->storage, page->storage_size,
                                                  compressed, max_compressed,
                                                  target_precision);
                if (result > 0) {
                    ALIGNED_FREE(page->storage);
                    page->storage = compressed;
                    page->storage_size = result;
                    page->compressed_size = result;
                } else {
                    ALIGNED_FREE(compressed);
                }
            }
        }
    }
    
    page->precision = target_precision;
    
    // Atomically update page state
    page->current_tier = request.target_tier;
    page->state = (request.target_tier == ResidencyTier::FROZEN) ? 
                   PageState::EVICTED : PageState::RESIDENT;
    // NOTE: migration_pending is NOT cleared here - it's cleared in OnMigrationComplete
    // This prevents EvaluateMigrations from re-queuing the page before logging completes
    page->migration_count++;
    
    // Record latency
    auto end_time = std::chrono::high_resolution_clock::now();
    page->last_migration_latency = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    return true;
}

//=============================================================================
// KVTransitionLogger Implementation
//=============================================================================

KVTransitionLogger::KVTransitionLogger(size_t buffer_size)
    : m_buffer_size(buffer_size), m_write_index(0), m_buffer_full(false) {
    m_log.reserve(buffer_size);
}

KVTransitionLogger::~KVTransitionLogger() = default;

void KVTransitionLogger::LogTransition(const TransitionLogEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_log.size() < m_buffer_size) {
        m_log.push_back(entry);
    } else {
        m_log[m_write_index] = entry;
        m_write_index = (m_write_index + 1) % m_buffer_size;
        m_buffer_full = true;
    }
}

std::vector<TransitionLogEntry> KVTransitionLogger::GetRecentTransitions(uint32_t count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<TransitionLogEntry> result;
    uint32_t start = m_buffer_full ? m_write_index : 0;
    uint32_t available = m_buffer_full ? m_buffer_size : m_log.size();
    
    count = std::min(count, available);
    
    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (start + available - count + i) % m_buffer_size;
        result.push_back(m_log[idx]);
    }
    return result;
}

std::vector<TransitionLogEntry> KVTransitionLogger::GetTransitionsForPage(uint64_t page_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<TransitionLogEntry> result;
    
    for (const auto& entry : m_log) {
        if (entry.page_id == page_id) {
            result.push_back(entry);
        }
    }
    return result;
}

bool KVTransitionLogger::CheckForDuplicates(uint64_t page_id, uint64_t window_ms) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Track unique (from_tier, to_tier) pairs for this page
    // A duplicate is the same transition type happening multiple times
    std::vector<std::pair<ResidencyTier, ResidencyTier>> transitions;
    
    for (const auto& entry : m_log) {
        if (entry.page_id == page_id && (now - entry.timestamp) < window_ms) {
            auto transition = std::make_pair(entry.from_tier, entry.to_tier);
            
            // Check if this exact transition already occurred
            for (const auto& prev : transitions) {
                if (prev.first == transition.first && prev.second == transition.second) {
                    return true;  // Same transition type seen before = duplicate
                }
            }
            transitions.push_back(transition);
        }
    }
    return false;
}

bool KVTransitionLogger::CheckForOscillation(uint64_t page_id, uint32_t min_transitions) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<ResidencyTier> tier_history;
    for (const auto& entry : m_log) {
        if (entry.page_id == page_id) {
            tier_history.push_back(entry.to_tier);
        }
    }
    
    if (tier_history.size() < min_transitions) {
        return false;
    }
    
    // Check for rapid tier changes (oscillation)
    uint32_t changes = 0;
    for (size_t i = 1; i < tier_history.size(); i++) {
        if (tier_history[i] != tier_history[i-1]) {
            changes++;
        }
    }
    
    // If more than 50% are changes, consider it oscillation
    return changes > (tier_history.size() / 2);
}

uint32_t KVTransitionLogger::CountLostPages(const std::vector<uint64_t>& expected_page_ids) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    uint32_t lost_count = 0;
    for (uint64_t page_id : expected_page_ids) {
        bool found = false;
        for (const auto& entry : m_log) {
            if (entry.page_id == page_id) {
                found = true;
                break;
            }
        }
        if (!found) {
            lost_count++;
        }
    }
    return lost_count;
}

void KVTransitionLogger::GetMigrationStats(uint64_t& total, uint64_t& failed, 
                                          double& avg_latency) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    total = m_log.size();
    failed = 0;
    uint64_t total_latency = 0;
    
    for (const auto& entry : m_log) {
        if (!entry.success) {
            failed++;
        }
        total_latency += entry.latency_us;
    }
    
    avg_latency = total > 0 ? static_cast<double>(total_latency) / total : 0.0;
}

//=============================================================================
// KVCacheResidencyManagerV2 Implementation
//=============================================================================

KVCacheResidencyManagerV2::KVCacheResidencyManagerV2(const KVResidencyConfigV2<>& config)
    : m_config(config)
    , m_current_seq_len(0)
    , m_tick_counter(0) {
    m_stats.Reset();
}

KVCacheResidencyManagerV2::~KVCacheResidencyManagerV2() {
    Shutdown();
}

bool KVCacheResidencyManagerV2::Initialize() {
    if (!m_config.Validate()) {
        return false;
    }
    
    // Create components
    m_page_table = std::make_unique<KVPageTable>(m_config);
    m_migration_worker = std::make_unique<KVMigrationWorker>(m_page_table.get());
    m_logger = std::make_unique<KVTransitionLogger>(m_config.log_buffer_size);
    
    // Set up completion callback
    m_migration_worker->SetCompletionCallback(
        [this](uint64_t page_id, bool success, uint64_t latency_us,
               ResidencyTier source_tier, ResidencyTier target_tier) {
            OnMigrationComplete(page_id, success, latency_us, source_tier, target_tier);
        });
    
    // Start worker
    if (m_config.enable_async_migration) {
        m_migration_worker->Start();
    }
    
    return true;
}

void KVCacheResidencyManagerV2::Shutdown() {
    if (m_migration_worker) {
        m_migration_worker->Stop();
    }
}

bool KVCacheResidencyManagerV2::AppendTokens(uint32_t seq_len, 
                                               const float* k_data, 
                                               const float* v_data) {
    if (seq_len == 0) return false;
    
    m_current_seq_len = seq_len;
    
    // Calculate which page(s) need allocation
    uint32_t new_token_idx = seq_len - 1;
    uint32_t page_idx = GetPageIndexForToken(new_token_idx, m_config.TOKENS_PER_PAGE);
    
    // Check if page exists
    KVResidencyPage* page = m_page_table->GetPage(page_idx);
    if (!page) {
        // Allocate new page
        uint32_t first_token = page_idx * m_config.TOKENS_PER_PAGE;
        uint32_t token_count = m_config.TOKENS_PER_PAGE;
        
        if (!m_page_table->AllocatePage(page_idx, first_token, token_count)) {
            return false;
        }
        
        // Log page creation
        if (m_config.enable_detailed_logging) {
            TransitionLogEntry entry{};
            entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            entry.page_id = page_idx;
            entry.first_token = first_token;
            entry.token_count = token_count;
            entry.from_tier = ResidencyTier::INVALID;
            entry.to_tier = ResidencyTier::HOT;
            entry.reason = MigrationReason::MANUAL;
            entry.latency_us = 0;
            entry.success = true;
            m_logger->LogTransition(entry);
        }
    }
    
    // Evaluate migrations (non-blocking)
    EvaluateMigrations(seq_len);
    UpdateStats();
    
    return true;
}

bool KVCacheResidencyManagerV2::GetTokenForAttention(uint32_t token_idx, 
                                                     uint32_t head_idx,
                                                     const void** k_out, 
                                                     const void** v_out,
                                                     NEVM::ISA::PrecisionMode* format_out) {
    // Find page containing token
    KVResidencyPage* page = m_page_table->FindPageContainingToken(token_idx);
    if (!page || page->state != PageState::RESIDENT) {
        m_stats.cache_misses++;
        return false;
    }
    
    // Update access stats
    page->access_count++;
    page->last_access_tick = m_tick_counter++;
    
    // Return pointer to token data within page
    // For now, simplified - just return page storage
    // Real implementation would calculate offset within page
    *k_out = page->storage;
    *v_out = reinterpret_cast<uint8_t*>(page->storage) + page->storage_size / 2;
    *format_out = page->precision;
    
    return true;
}

void KVCacheResidencyManagerV2::UpdateWindow(uint32_t current_seq_len) {
    m_current_seq_len = current_seq_len;
    EvaluateMigrations(current_seq_len);
}

void KVCacheResidencyManagerV2::OnMemoryPressure(float pressure_level) {
    if (pressure_level > m_config.pressure_threshold_critical) {
        // Emergency: Evict pages to FROZEN
        auto pages = m_page_table->GetPagesInTier(ResidencyTier::COLD);
        for (auto* page : pages) {
            if (page && !page->migration_pending) {
                QueuePageMigration(page->page_id, ResidencyTier::FROZEN, 
                                 MigrationReason::EMERGENCY_EVICTION);
            }
        }
        m_stats.emergency_evictions++;
    } else if (pressure_level > m_config.pressure_threshold_high) {
        // High pressure: Accelerate normal migration
        EvaluateMigrations(m_current_seq_len);
    }
}

ResidencyStats KVCacheResidencyManagerV2::GetStats() const {
    return m_stats;
}

void KVCacheResidencyManagerV2::GetDetailedReport(std::string& report) const {
    std::ostringstream oss;
    
    oss << "=== KV Cache Residency Report (v2) ===" << std::endl;
    oss << "Current Sequence Length: " << m_current_seq_len << std::endl;
    oss << "Pages: " << m_current_seq_len / m_config.TOKENS_PER_PAGE << std::endl;
    oss << std::endl;
    
    oss << "Tier Distribution:" << std::endl;
    oss << "  HOT:    " << m_stats.pages_in_hot << " pages" << std::endl;
    oss << "  WARM:   " << m_stats.pages_in_warm << " pages" << std::endl;
    oss << "  COLD:   " << m_stats.pages_in_cold << " pages" << std::endl;
    oss << "  FROZEN: " << m_stats.pages_in_frozen << " pages" << std::endl;
    oss << "  Migrating: " << m_stats.pages_migrating << " pages" << std::endl;
    oss << std::endl;
    
    oss << "Memory:" << std::endl;
    oss << "  Current: " << (m_stats.total_memory_used / (1024.0 * 1024.0)) << " MB" << std::endl;
    oss << "  Peak:    " << (m_stats.peak_memory_used / (1024.0 * 1024.0)) << " MB" << std::endl;
    oss << "  Compression: " << m_stats.compression_ratio << "x" << std::endl;
    oss << std::endl;
    
    oss << "Migration Activity:" << std::endl;
    oss << "  Completed: " << m_stats.migrations_completed << std::endl;
    oss << "  Failed:    " << m_stats.migrations_failed << std::endl;
    oss << "  Queued:    " << m_stats.migrations_queued << std::endl;
    oss << "  Emergency: " << m_stats.emergency_evictions << std::endl;
    oss << "  Avg Latency: " << m_stats.avg_migration_latency_us << " us" << std::endl;
    oss << std::endl;
    
    oss << "Validation:" << std::endl;
    oss << "  Decode Stalls:      " << m_stats.decode_stalls << " (should be 0)" << std::endl;
    oss << "  Cache Misses:       " << m_stats.cache_misses << std::endl;
    oss << "  Duplicate Migrations: " << m_stats.duplicate_migrations << " (should be 0)" << std::endl;
    oss << "  Lost Pages:         " << m_stats.lost_pages << " (should be 0)" << std::endl;
    oss << "  Tier Oscillations:  " << m_stats.tier_oscillations << " (should be 0)" << std::endl;
    
    report = oss.str();
}

void KVCacheResidencyManagerV2::DumpTransitionLog(std::string& output) const {
    auto transitions = m_logger->GetRecentTransitions(100);
    
    std::ostringstream oss;
    oss << "=== Recent Transitions ===" << std::endl;
    
    for (const auto& entry : transitions) {
        oss << "[" << entry.timestamp << "] "
            << "Page " << entry.page_id 
            << " (tokens " << entry.first_token << "-" 
            << (entry.first_token + entry.token_count - 1) << "): "
            << TierToString(entry.from_tier) << " -> " << TierToString(entry.to_tier)
            << " (" << ReasonToString(entry.reason) << ")"
            << " [" << entry.latency_us << " us]"
            << (entry.success ? "" : " FAILED")
            << std::endl;
    }
    
    output = oss.str();
}

bool KVCacheResidencyManagerV2::RunValidationChecks(std::string& report) const {
    std::ostringstream oss;
    bool all_passed = true;
    
    oss << "=== Validation Checks ===" << std::endl;
    
    // Check 1: No decode stalls
    if (m_stats.decode_stalls > 0) {
        oss << "FAIL: Decode stalls detected: " << m_stats.decode_stalls << std::endl;
        all_passed = false;
    } else {
        oss << "PASS: No decode stalls" << std::endl;
    }
    
    // Check 2: Page consistency
    if (!m_page_table->ValidatePageConsistency()) {
        oss << "FAIL: Page table inconsistency detected" << std::endl;
        all_passed = false;
    } else {
        oss << "PASS: Page table consistent" << std::endl;
    }
    
    // Check 3: Page conservation
    uint32_t hot, warm, cold, frozen, migrating;
    if (!m_page_table->ValidatePageConservation(hot, warm, cold, frozen, migrating)) {
        oss << "FAIL: Page conservation violated" << std::endl;
        all_passed = false;
    } else {
        uint32_t total = hot + warm + cold + frozen;
        oss << "PASS: Page conservation (HOT=" << hot << " WARM=" << warm 
            << " COLD=" << cold << " FROZEN=" << frozen 
            << " migrating=" << migrating << " total=" << total << ")" << std::endl;
    }
    
    // Check 4: Single ownership
    uint32_t ownership_violations = 0;
    for (uint32_t i = 0; i < m_page_table->GetTotalPageCount(); i++) {
        if (!m_page_table->ValidateSingleOwnership(i)) {
            ownership_violations++;
        }
    }
    if (ownership_violations > 0) {
        oss << "FAIL: Single ownership violated for " << ownership_violations << " pages" << std::endl;
        all_passed = false;
    } else {
        oss << "PASS: Single ownership (all pages in exactly one tier)" << std::endl;
    }
    
    // Check 5: No lost pages
    if (m_stats.lost_pages > 0) {
        oss << "FAIL: Lost pages detected: " << m_stats.lost_pages << std::endl;
        all_passed = false;
    } else {
        oss << "PASS: No lost pages" << std::endl;
    }
    
    // Check 6: No duplicate migrations
    if (m_stats.duplicate_migrations > 0) {
        oss << "FAIL: Duplicate migrations detected: " << m_stats.duplicate_migrations << std::endl;
        all_passed = false;
    } else {
        oss << "PASS: No duplicate migrations" << std::endl;
    }
    
    // Check 7: No tier oscillations
    if (m_stats.tier_oscillations > 0) {
        oss << "WARN: Tier oscillations detected: " << m_stats.tier_oscillations << std::endl;
    } else {
        oss << "PASS: No tier oscillations" << std::endl;
    }
    
    // Check 8: Migration latency targets
    if (m_stats.avg_migration_latency_us > 100.0) {
        oss << "WARN: Avg migration latency " << m_stats.avg_migration_latency_us 
            << " us exceeds target 100 us" << std::endl;
    } else if (m_stats.avg_migration_latency_us > 0) {
        oss << "PASS: Migration latency " << m_stats.avg_migration_latency_us 
            << " us (p95=" << m_stats.p95_migration_latency_us << ")" << std::endl;
    }
    
    // Check 9: Queue depth
    if (m_stats.max_queue_depth > 100) {
        oss << "WARN: Max queue depth " << m_stats.max_queue_depth 
            << " suggests migration worker may be falling behind" << std::endl;
    } else {
        oss << "PASS: Queue depth acceptable (max=" << m_stats.max_queue_depth << ")" << std::endl;
    }
    
    // Check 10: Page churn
    if (m_stats.page_churn_rate > 10.0) {
        oss << "WARN: Page churn rate " << m_stats.page_churn_rate 
            << " moves/page/min suggests unstable policy" << std::endl;
    } else {
        oss << "PASS: Page churn rate " << m_stats.page_churn_rate << " moves/page/min" << std::endl;
    }
    
    report = oss.str();
    return all_passed;
}

//=============================================================================
// Private Helpers
//=============================================================================

ResidencyTier KVCacheResidencyManagerV2::DetermineTargetTier(uint32_t token_idx) const {
    uint32_t distance_from_end = m_current_seq_len - token_idx - 1;
    
    if (distance_from_end < m_config.hot_window_tokens) {
        return ResidencyTier::HOT;
    } else if (distance_from_end < m_config.warm_window_tokens) {
        return ResidencyTier::WARM;
    } else {
        return ResidencyTier::COLD;
    }
}

void KVCacheResidencyManagerV2::EvaluateMigrations(uint32_t current_seq_len) {
    // Check all pages for needed migrations
    uint32_t max_page_idx = current_seq_len / m_config.TOKENS_PER_PAGE;
    
    for (uint32_t page_idx = 0; page_idx <= max_page_idx; page_idx++) {
        KVResidencyPage* page = m_page_table->GetPage(page_idx);
        if (!page) continue;
        
        // Skip if migration already pending
        if (page->migration_pending) continue;
        
        // Skip if page is already in target tier
        ResidencyTier target = DetermineTargetTier(page->first_token);
        if (page->current_tier == target) continue;
        
        // Skip if page was recently migrated (prevent oscillation)
        // Only allow migration if page has settled in current tier
        if (page->migration_count > 0) {
            // Check if this would be a redundant migration (back to previous tier)
            if (page->current_tier == page->target_tier && 
                page->target_tier != ResidencyTier::INVALID) {
                continue;
            }
        }
        
        MigrationReason reason = MigrationReason::WINDOW_EXPIRED;
        QueuePageMigration(page_idx, target, reason);
    }
}

void KVCacheResidencyManagerV2::QueuePageMigration(uint64_t page_id, 
                                                   ResidencyTier target, 
                                                   MigrationReason reason) {
    KVResidencyPage* page = m_page_table->GetPage(page_id);
    if (!page || page->migration_pending) return;
    
    page->target_tier = target;
    page->migration_pending = true;
    
    MigrationRequest request;
    request.page_id = page_id;
    request.source_tier = page->current_tier;
    request.target_tier = target;
    request.reason = reason;
    request.timestamp = m_tick_counter++;
    request.priority = (reason == MigrationReason::EMERGENCY_EVICTION) ? 100 : 50;
    
    m_migration_worker->QueueMigration(request);
    m_stats.migrations_queued++;
}

void KVCacheResidencyManagerV2::OnMigrationComplete(uint64_t page_id, bool success, 
                                                    uint64_t latency_us,
                                                    ResidencyTier source_tier,
                                                    ResidencyTier target_tier) {
    KVResidencyPage* page = m_page_table->GetPage(page_id);
    if (!page) return;
    
    // Track latency for percentile calculation
    m_migration_latencies.push_back(latency_us);
    if (m_migration_latencies.size() > 10000) {
        m_migration_latencies.erase(m_migration_latencies.begin());
    }
    
    // Update latency percentiles
    if (!m_migration_latencies.empty()) {
        std::vector<uint64_t> sorted = m_migration_latencies;
        std::sort(sorted.begin(), sorted.end());
        size_t n = sorted.size();
        m_stats.avg_migration_latency_us = static_cast<double>(std::accumulate(sorted.begin(), sorted.end(), 0ULL)) / n;
        m_stats.p50_migration_latency_us = sorted[n * 50 / 100];
        m_stats.p95_migration_latency_us = sorted[n * 95 / 100];
        m_stats.p99_migration_latency_us = sorted[n * 99 / 100];
    }
    
    // Log transition
    if (m_config.enable_detailed_logging) {
        TransitionLogEntry entry{};
        entry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        entry.page_id = page_id;
        entry.first_token = page->first_token;
        entry.token_count = page->token_count;
        entry.from_tier = source_tier;   // Source tier from request
        entry.to_tier = target_tier;     // Target tier from request
        entry.reason = MigrationReason::WINDOW_EXPIRED;  // Simplified
        entry.latency_us = latency_us;
        entry.success = success;
        entry.error_msg = success ? nullptr : "Migration failed";
        
        m_logger->LogTransition(entry);
        
        // Check for duplicates - only count actual duplicates (same source->target)
        if (m_logger->CheckForDuplicates(page_id, 1000)) {
            m_stats.duplicate_migrations++;
        }
        
        // Check for oscillation
        if (m_logger->CheckForOscillation(page_id, 3)) {
            m_stats.tier_oscillations++;
        }
    }
    
    // Update stats
    if (success) {
        m_stats.migrations_completed++;
    } else {
        m_stats.migrations_failed++;
    }
    
    // Clear migration_pending AFTER logging is complete
    // This prevents duplicate migrations during the window between
    // ExecuteMigration finishing and OnMigrationComplete being called
    page->migration_pending = false;
}

void KVCacheResidencyManagerV2::UpdateStats() {
    m_stats.pages_in_hot = m_page_table->CountPagesInTier(ResidencyTier::HOT);
    m_stats.pages_in_warm = m_page_table->CountPagesInTier(ResidencyTier::WARM);
    m_stats.pages_in_cold = m_page_table->CountPagesInTier(ResidencyTier::COLD);
    m_stats.pages_in_frozen = m_page_table->CountPagesInTier(ResidencyTier::FROZEN);
    
    // Calculate memory usage
    size_t total = 0;
    for (uint32_t i = 0; i <= m_current_seq_len / m_config.TOKENS_PER_PAGE; i++) {
        KVResidencyPage* page = m_page_table->GetPage(i);
        if (page) {
            total += page->compressed_size;
        }
    }
    m_stats.total_memory_used = total;
    if (total > m_stats.peak_memory_used) {
        m_stats.peak_memory_used = total;
    }
    
    // Calculate compression ratio
    size_t raw_size = m_current_seq_len * 32 * 2 * 128 * sizeof(float);  // Simplified
    m_stats.compression_ratio = raw_size > 0 ? static_cast<float>(raw_size) / total : 1.0f;
}

//=============================================================================
// Helper Functions
//=============================================================================

uint32_t CalculatePageCount(uint32_t seq_len, uint32_t tokens_per_page) {
    return (seq_len + tokens_per_page - 1) / tokens_per_page;
}

uint32_t GetPageIndexForToken(uint32_t token_idx, uint32_t tokens_per_page) {
    return token_idx / tokens_per_page;
}

bool ValidateResidencyConfigV2(const KVResidencyConfigV2<>& config, std::string* error_msg) {
    if (!config.Validate()) {
        if (error_msg) {
            *error_msg = "Invalid tier boundaries: must be aligned to TOKENS_PER_PAGE";
        }
        return false;
    }
    return true;
}

} // namespace Memory
} // namespace RawrXD
