//=============================================================================
// RawrXD KV Residency Scheduler - Implementation
// Phase 3B: Intelligent KV Cache Placement and Migration
//=============================================================================

#include "KVResidencyScheduler.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Utility Functions
//=============================================================================
const char* ResidencyStateToString(ResidencyState state) {
    switch (state) {
        case ResidencyState::HOT_GPU: return "HOT_GPU";
        case ResidencyState::ACTIVE_NUMA: return "ACTIVE_NUMA";
        case ResidencyState::WARM_NUMA: return "WARM_NUMA";
        case ResidencyState::COLD_DRAM: return "COLD_DRAM";
        case ResidencyState::COMPRESSED: return "COMPRESSED";
        case ResidencyState::MAPPED_STORAGE: return "MAPPED_STORAGE";
        case ResidencyState::EVICTED: return "EVICTED";
        default: return "UNKNOWN";
    }
}

static uint64_t GetCurrentTimeNs() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
}

//=============================================================================
// Access Pattern Tracker
//=============================================================================
AccessPatternTracker::AccessPatternTracker(size_t maxSequences) 
    : maxSequences_(maxSequences) {
}

void AccessPatternTracker::RecordAccess(uint64_t sequenceId, uint32_t blockId, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& pattern = patterns_[sequenceId];
    pattern.sequenceId = sequenceId;
    pattern.lastAccessTime = timestamp;
    
    // Add to recent blocks (keep last 16)
    pattern.recentBlockIds.push_back(blockId);
    if (pattern.recentBlockIds.size() > 16) {
        pattern.recentBlockIds.erase(pattern.recentBlockIds.begin());
    }
    
    // Update frequency
    pattern.blockFrequency[blockId]++;
    
    // Detect sequential pattern
    if (pattern.recentBlockIds.size() >= 2) {
        int diff = pattern.recentBlockIds.back() - pattern.recentBlockIds[pattern.recentBlockIds.size() - 2];
        pattern.isSequential = (diff == 1);
    }
    
    // Predict next block
    if (pattern.isSequential && !pattern.recentBlockIds.empty()) {
        pattern.predictedNextBlock = pattern.recentBlockIds.back() + 1;
    } else {
        // Find most frequent block
        uint32_t maxFreq = 0;
        for (const auto& [blk, freq] : pattern.blockFrequency) {
            if (freq > maxFreq) {
                maxFreq = freq;
                pattern.predictedNextBlock = blk;
            }
        }
    }
}

std::vector<uint32_t> AccessPatternTracker::PredictNextBlocks(uint64_t sequenceId, uint32_t numPredictions) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint32_t> predictions;
    auto it = patterns_.find(sequenceId);
    if (it == patterns_.end()) return predictions;
    
    const auto& pattern = it->second;
    
    if (pattern.isSequential && pattern.recentBlockIds.size() >= 2) {
        // Predict sequential continuation
        uint32_t last = pattern.recentBlockIds.back();
        for (uint32_t i = 1; i <= numPredictions; i++) {
            predictions.push_back(last + i);
        }
    } else {
        // Predict based on frequency
        std::vector<std::pair<uint32_t, uint32_t>> freqVec(
            pattern.blockFrequency.begin(), pattern.blockFrequency.end());
        std::sort(freqVec.begin(), freqVec.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (size_t i = 0; i < std::min<size_t>(numPredictions, freqVec.size()); i++) {
            predictions.push_back(freqVec[i].first);
        }
    }
    
    return predictions;
}

AccessPatternTracker::AccessPattern* AccessPatternTracker::GetPattern(uint64_t sequenceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = patterns_.find(sequenceId);
    if (it != patterns_.end()) return &it->second;
    return nullptr;
}

void AccessPatternTracker::Cleanup(uint64_t currentTime, uint64_t maxAge) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto it = patterns_.begin(); it != patterns_.end();) {
        if (currentTime - it->second.lastAccessTime > maxAge) {
            it = patterns_.erase(it);
        } else {
            ++it;
        }
    }
}

//=============================================================================
// Hot/Cold Classifier
//=============================================================================
HotColdClassifier::HotColdClassifier(const ClassificationConfig& config) 
    : config_(config) {
}

ResidencyState HotColdClassifier::Classify(const KVBlockMetadata& metadata, uint64_t currentTime) {
    uint64_t accessCount = metadata.accessCount.load(std::memory_order_relaxed);
    uint64_t age = metadata.GetAge(currentTime);
    
    // HOT: High access count AND recently accessed
    if (accessCount >= config_.hotThreshold && age < config_.hotAgeThresholdNs) {
        return ResidencyState::ACTIVE_NUMA;
    }
    
    // WARM: Moderate access OR recently accessed
    if (accessCount >= config_.warmThreshold || age < config_.warmAgeThresholdNs) {
        return ResidencyState::WARM_NUMA;
    }
    
    // COLD: Low access AND old
    if (age > config_.coldAgeThresholdNs) {
        return ResidencyState::COMPRESSED;
    }
    
    return ResidencyState::COLD_DRAM;
}

void HotColdClassifier::AdaptThresholds(const std::vector<KVBlockMetadata*>& blocks) {
    if (blocks.empty()) return;
    
    // Calculate percentiles
    std::vector<uint64_t> accessCounts;
    accessCounts.reserve(blocks.size());
    for (const auto* block : blocks) {
        accessCounts.push_back(block->accessCount.load());
    }
    std::sort(accessCounts.begin(), accessCounts.end());
    
    // Set hot threshold at 90th percentile
    size_t hotIdx = (accessCounts.size() * 90) / 100;
    config_.hotThreshold = accessCounts[std::min(hotIdx, accessCounts.size() - 1)];
    
    // Set warm threshold at 50th percentile
    size_t warmIdx = (accessCounts.size() * 50) / 100;
    config_.warmThreshold = accessCounts[std::min(warmIdx, accessCounts.size() - 1)];
}

//=============================================================================
// Async Prefetch Queue
//=============================================================================
AsyncPrefetchQueue::AsyncPrefetchQueue(size_t capacity) : capacity_(capacity) {
}

AsyncPrefetchQueue::~AsyncPrefetchQueue() {
    Clear();
}

bool AsyncPrefetchQueue::Enqueue(const PrefetchRequest& request) {
    if (size_.load(std::memory_order_relaxed) >= capacity_) {
        return false;  // Queue full
    }
    
    Node* node = new Node{request, nullptr};
    
    Node* expected = nullptr;
    if (!head_.compare_exchange_strong(expected, node, std::memory_order_release)) {
        // Queue not empty, append to tail
        Node* tail = tail_.load(std::memory_order_acquire);
        while (tail && tail->next.load(std::memory_order_relaxed)) {
            tail = tail->next.load(std::memory_order_relaxed);
        }
        if (tail) {
            tail->next.store(node, std::memory_order_release);
        }
    }
    
    tail_.store(node, std::memory_order_release);
    size_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool AsyncPrefetchQueue::Dequeue(PrefetchRequest& request) {
    Node* head = head_.load(std::memory_order_acquire);
    if (!head) return false;
    
    request = head->data;
    Node* next = head->next.load(std::memory_order_acquire);
    
    head_.store(next, std::memory_order_release);
    if (!next) {
        tail_.store(nullptr, std::memory_order_release);
    }
    
    delete head;
    size_.fetch_sub(1, std::memory_order_relaxed);
    return true;
}

void AsyncPrefetchQueue::Clear() {
    PrefetchRequest dummy;
    while (Dequeue(dummy)) {}
}

//=============================================================================
// Residency Migration Engine
//=============================================================================
ResidencyMigrationEngine::ResidencyMigrationEngine(SovereignMemoryAllocator* allocator)
    : allocator_(allocator), queue_(1024) {
}

ResidencyMigrationEngine::~ResidencyMigrationEngine() {
    Shutdown();
}

bool ResidencyMigrationEngine::Initialize(uint32_t numWorkers) {
    shutdown_.store(false);
    
    for (uint32_t i = 0; i < numWorkers; i++) {
        workers_.emplace_back(&ResidencyMigrationEngine::WorkerThread, this);
    }
    
    return true;
}

void ResidencyMigrationEngine::Shutdown() {
    shutdown_.store(true);
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

bool ResidencyMigrationEngine::RequestMigration(uint64_t blockId, 
                                                ResidencyState targetState,
                                                uint32_t targetNumaNode,
                                                MigrationCallback callback) {
    AsyncPrefetchQueue::PrefetchRequest request;
    request.blockId = blockId;
    request.targetState = targetState;
    request.targetNumaNode = targetNumaNode;
    request.priority = 100;  // Migration is high priority
    request.requestTime = GetCurrentTimeNs();
    
    migrationsRequested_.fetch_add(1, std::memory_order_relaxed);
    return queue_.Enqueue(request);
}

void ResidencyMigrationEngine::WorkerThread() {
    while (!shutdown_.load(std::memory_order_relaxed)) {
        AsyncPrefetchQueue::PrefetchRequest request;
        if (queue_.Dequeue(request)) {
            uint64_t startTime = GetCurrentTimeNs();
            
            bool success = ExecuteMigration(request.blockId, request.targetState, 
                                            request.targetNumaNode);
            
            uint64_t duration = GetCurrentTimeNs() - startTime;
            totalMigrationTimeUs_.fetch_add(duration / 1000, std::memory_order_relaxed);
            
            if (success) {
                migrationsCompleted_.fetch_add(1, std::memory_order_relaxed);
            } else {
                migrationsFailed_.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

bool ResidencyMigrationEngine::ExecuteMigration(uint64_t blockId, 
                                                ResidencyState targetState,
                                                uint32_t targetNumaNode) {
    // This is where the actual memory migration would happen
    // For now, we simulate success
    // In production, this would:
    // 1. Allocate new memory at target location
    // 2. Copy data from old location
    // 3. Update metadata
    // 4. Free old memory
    
    return true;
}

ResidencyMigrationEngine::Stats ResidencyMigrationEngine::GetStats() const {
    Stats stats;
    stats.migrationsRequested = migrationsRequested_.load();
    stats.migrationsCompleted = migrationsCompleted_.load();
    stats.migrationsFailed = migrationsFailed_.load();
    
    uint64_t completed = migrationsCompleted_.load();
    stats.avgMigrationTimeUs = completed > 0 
        ? totalMigrationTimeUs_.load() / completed 
        : 0;
    stats.bytesMigrated = bytesMigrated_.load();
    
    return stats;
}

//=============================================================================
// KV Residency Scheduler
//=============================================================================
KVResidencyScheduler::KVResidencyScheduler(SovereignMemoryAllocator* allocator)
    : allocator_(allocator) {
}

KVResidencyScheduler::~KVResidencyScheduler() {
    Shutdown();
}

bool KVResidencyScheduler::Initialize(const Config& config) {
    config_ = config;
    
    // Initialize classifier
    HotColdClassifier::ClassificationConfig classifierConfig;
    classifierConfig.hotThreshold = 100;
    classifierConfig.warmThreshold = 10;
    classifierConfig.hotAgeThresholdNs = 1000000000ULL;  // 1ms
    classifierConfig.warmAgeThresholdNs = 10000000000ULL; // 10ms
    classifierConfig.coldAgeThresholdNs = 100000000000ULL; // 100ms
    classifier_ = std::make_unique<HotColdClassifier>(classifierConfig);
    
    // Initialize pattern tracker
    patternTracker_ = std::make_unique<AccessPatternTracker>(1024);
    
    // Initialize migration engine
    migrationEngine_ = std::make_unique<ResidencyMigrationEngine>(allocator_);
    if (!migrationEngine_->Initialize(config.numWorkers)) {
        return false;
    }
    
    // Start classification thread
    shutdown_.store(false);
    classificationThread_ = std::thread(&KVResidencyScheduler::ClassificationWorker, this);
    
    return true;
}

void KVResidencyScheduler::Shutdown() {
    shutdown_.store(true);
    cv_.notify_all();
    
    if (classificationThread_.joinable()) {
        classificationThread_.join();
    }
    
    if (migrationEngine_) {
        migrationEngine_->Shutdown();
    }
}

bool KVResidencyScheduler::RegisterBlock(uint64_t blockId, KVBlockMetadata* metadata) {
    std::unique_lock<std::shared_mutex> lock(registryMutex_);
    blockRegistry_[blockId] = metadata;
    return true;
}

void KVResidencyScheduler::UnregisterBlock(uint64_t blockId) {
    std::unique_lock<std::shared_mutex> lock(registryMutex_);
    blockRegistry_.erase(blockId);
}

void KVResidencyScheduler::RecordAccess(uint64_t blockId, uint64_t sequenceId, uint64_t timestamp) {
    totalAccesses_.fetch_add(1, std::memory_order_relaxed);
    
    KVBlockMetadata* metadata = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(registryMutex_);
        auto it = blockRegistry_.find(blockId);
        if (it != blockRegistry_.end()) {
            metadata = it->second;
        }
    }
    
    if (!metadata) {
        residencyMisses_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    // Update metadata
    metadata->accessCount.fetch_add(1, std::memory_order_relaxed);
    metadata->lastAccessTime.store(timestamp, std::memory_order_relaxed);
    
    // Check residency
    if (metadata->IsResident()) {
        residencyHits_.fetch_add(1, std::memory_order_relaxed);
    } else {
        residencyMisses_.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Track pattern
    if (config_.enablePredictivePrefetch) {
        patternTracker_->RecordAccess(sequenceId, static_cast<uint32_t>(blockId), timestamp);
    }
}

bool KVResidencyScheduler::EnsureResidency(uint64_t blockId, ResidencyState desiredState, 
                                           uint32_t numaNode) {
    KVBlockMetadata* metadata = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(registryMutex_);
        auto it = blockRegistry_.find(blockId);
        if (it == blockRegistry_.end()) return false;
        metadata = it->second;
    }
    
    auto currentState = metadata->currentState.load(std::memory_order_acquire);
    
    // Already in desired state
    if (currentState == desiredState) return true;
    
    // Request migration
    return migrationEngine_->RequestMigration(blockId, desiredState, numaNode);
}

bool KVResidencyScheduler::PrefetchBlock(uint64_t blockId, ResidencyState targetState, 
                                         uint32_t priority) {
    prefetchRequests_.fetch_add(1, std::memory_order_relaxed);
    
    // Check if already resident
    KVBlockMetadata* metadata = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(registryMutex_);
        auto it = blockRegistry_.find(blockId);
        if (it != blockRegistry_.end()) {
            metadata = it->second;
        }
    }
    
    if (metadata && metadata->IsResident()) {
        prefetchHits_.fetch_add(1, std::memory_order_relaxed);
        return true;  // Already resident
    }
    
    // Request migration
    return migrationEngine_->RequestMigration(blockId, targetState, 
                                             allocator_->GetCurrentNumaNode());
}

ResidencyState KVResidencyScheduler::GetResidencyState(uint64_t blockId) const {
    std::shared_lock<std::shared_mutex> lock(registryMutex_);
    auto it = blockRegistry_.find(blockId);
    if (it != blockRegistry_.end()) {
        return it->second->currentState.load(std::memory_order_acquire);
    }
    return ResidencyState::EVICTED;
}

KVBlockMetadata* KVResidencyScheduler::GetBlockMetadata(uint64_t blockId) {
    std::shared_lock<std::shared_mutex> lock(registryMutex_);
    auto it = blockRegistry_.find(blockId);
    if (it != blockRegistry_.end()) return it->second;
    return nullptr;
}

void KVResidencyScheduler::RunClassificationPass() {
    ClassifyAllBlocks();
}

void KVResidencyScheduler::RebalanceResidency() {
    // Triggered by memory pressure or periodic timer
    // Moves blocks between tiers based on classification
}

void KVResidencyScheduler::ClassificationWorker() {
    while (!shutdown_.load(std::memory_order_relaxed)) {
        std::unique_lock<std::mutex> lock(cvMutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(config_.classificationIntervalMs),
            [this] { return shutdown_.load(std::memory_order_relaxed); });
        
        if (!shutdown_.load(std::memory_order_relaxed)) {
            ClassifyAllBlocks();
        }
    }
}

void KVResidencyScheduler::ClassifyAllBlocks() {
    uint64_t currentTime = GetCurrentTimeNs();
    
    std::vector<KVBlockMetadata*> blocks;
    {
        std::shared_lock<std::shared_mutex> lock(registryMutex_);
        blocks.reserve(blockRegistry_.size());
        for (const auto& [id, metadata] : blockRegistry_) {
            blocks.push_back(metadata);
        }
    }
    
    // Adapt thresholds if enabled
    if (config_.enableAdaptiveThresholds) {
        classifier_->AdaptThresholds(blocks);
    }
    
    // Classify each block
    for (auto* metadata : blocks) {
        if (!metadata->CanMigrate()) continue;
        
        ResidencyState newState = classifier_->Classify(*metadata, currentTime);
        ResidencyState currentState = metadata->currentState.load(std::memory_order_acquire);
        
        if (newState != currentState) {
            metadata->targetState.store(newState, std::memory_order_release);
            
            // Request migration
            uint32_t targetNuma = allocator_->GetCurrentNumaNode();
            migrationEngine_->RequestMigration(metadata->blockId, newState, targetNuma);
        }
    }
}

void KVResidencyScheduler::IssuePredictivePrefetches(uint64_t sequenceId, uint32_t lastBlockId) {
    if (!config_.enablePredictivePrefetch) return;
    
    auto predictions = patternTracker_->PredictNextBlocks(sequenceId, config_.prefetchLookahead);
    
    for (uint32_t blockId : predictions) {
        PrefetchBlock(blockId, ResidencyState::WARM_NUMA, 50);
    }
}

KVResidencyScheduler::ResidencyReport KVResidencyScheduler::GenerateReport() const {
    ResidencyReport report;
    report.totalBlocks = blockRegistry_.size();
    
    // Count blocks by state
    for (int i = 0; i < static_cast<int>(ResidencyState::STATE_COUNT); i++) {
        report.blocksByState[i] = 0;
    }
    
    {
        std::shared_lock<std::shared_mutex> lock(registryMutex_);
        for (const auto& [id, metadata] : blockRegistry_) {
            auto state = metadata->currentState.load(std::memory_order_acquire);
            if (state < ResidencyState::STATE_COUNT) {
                report.blocksByState[static_cast<int>(state)]++;
            }
        }
    }
    
    report.migrationsInProgress = 0;  // Would need to query migration engine
    report.prefetchQueueDepth = 0;    // Would need to query queue
    report.hitRate = GetHitRate();
    
    return report;
}

std::string KVResidencyScheduler::GetResidencyDashboard() const {
    std::ostringstream dashboard;
    auto report = GenerateReport();
    
    dashboard << "╔════════════════════════════════════════════════════════════════╗\n";
    dashboard << "║         RawrXD KV Residency Scheduler Dashboard                ║\n";
    dashboard << "╠════════════════════════════════════════════════════════════════╣\n";
    
    // Overall stats
    dashboard << "║ Overall Statistics:\n";
    dashboard << "║   Total Blocks: " << report.totalBlocks << "\n";
    dashboard << "║   Total Accesses: " << totalAccesses_.load() << "\n";
    dashboard << "║   Residency Hit Rate: " << std::fixed << std::setprecision(2) 
              << (report.hitRate * 100.0) << "%\n";
    dashboard << "║   Migrations In Progress: " << report.migrationsInProgress << "\n";
    dashboard << "╠════════════════════════════════════════════════════════════════╣\n";
    
    // State distribution
    dashboard << "║ Residency State Distribution:\n";
    for (int i = 0; i < static_cast<int>(ResidencyState::STATE_COUNT); i++) {
        auto state = static_cast<ResidencyState>(i);
        uint64_t count = report.blocksByState[i];
        float percentage = report.totalBlocks > 0 
            ? (100.0f * count / report.totalBlocks) : 0.0f;
        
        dashboard << "║   " << std::setw(15) << std::left << ResidencyStateToString(state)
                  << ": " << std::setw(6) << count 
                  << " (" << std::fixed << std::setprecision(1) << percentage << "%)\n";
    }
    
    // Migration stats
    if (migrationEngine_) {
        auto stats = migrationEngine_->GetStats();
        dashboard << "╠════════════════════════════════════════════════════════════════╣\n";
        dashboard << "║ Migration Statistics:\n";
        dashboard << "║   Requested: " << stats.migrationsRequested << "\n";
        dashboard << "║   Completed: " << stats.migrationsCompleted << "\n";
        dashboard << "║   Failed: " << stats.migrationsFailed << "\n";
        dashboard << "║   Avg Time: " << stats.avgMigrationTimeUs << " us\n";
        dashboard << "║   Bytes Migrated: " << (stats.bytesMigrated / (1024*1024)) << " MB\n";
    }
    
    dashboard << "╚════════════════════════════════════════════════════════════════╝\n";
    
    return dashboard.str();
}

//=============================================================================
// Global Scheduler
//=============================================================================
static std::unique_ptr<KVResidencyScheduler> g_globalScheduler;
static std::once_flag g_schedulerInitFlag;

KVResidencyScheduler& GetGlobalResidencyScheduler() {
    std::call_once(g_schedulerInitFlag, []() {
        g_globalScheduler = std::make_unique<KVResidencyScheduler>(
            &GetGlobalAllocator());
        
        KVResidencyScheduler::Config config;
        g_globalScheduler->Initialize(config);
    });
    return *g_globalScheduler;
}

bool InitializeGlobalResidencyScheduler(SovereignMemoryAllocator* allocator) {
    return GetGlobalResidencyScheduler().Initialize({});
}

void ShutdownGlobalResidencyScheduler() {
    if (g_globalScheduler) {
        g_globalScheduler->Shutdown();
        g_globalScheduler.reset();
    }
}

} // namespace Memory
} // namespace RawrXD
