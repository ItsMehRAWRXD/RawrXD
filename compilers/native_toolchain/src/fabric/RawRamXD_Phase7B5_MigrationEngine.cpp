// =============================================================================
// RawRamXD Phase 7B.5: Migration Engine
// Automatic Tier Movement with Policy-Driven Decisions
// =============================================================================

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <algorithm>
#include <atomic>

#include <windows.h>

namespace RawRamXD {

// =============================================================================
// Migration Types
// =============================================================================

enum class MigrationType {
    PROMOTE = 0,      // Move to faster tier
    DEMOTE = 1,       // Move to slower tier
    SYNC = 2,         // Synchronize dirty data
    PREFETCH = 3,     // Proactive fetch
    EVICT = 4         // Remove from tier
};

const char* MigrationTypeToString(MigrationType type) {
    switch (type) {
        case MigrationType::PROMOTE: return "PROMOTE";
        case MigrationType::DEMOTE: return "DEMOTE";
        case MigrationType::SYNC: return "SYNC";
        case MigrationType::PREFETCH: return "PREFETCH";
        case MigrationType::EVICT: return "EVICT";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// Migration Request
// =============================================================================

struct MigrationRequest {
    uint64_t virtualAddress;
    uint32_t sourceTier;
    uint32_t targetTier;
    MigrationType type;
    uint64_t priority;        // Higher = more urgent
    uint64_t submitTime;
    bool async;             // If true, don't block caller
    std::function<void(bool)> callback;  // Completion callback
};

// =============================================================================
// Migration Policy
// =============================================================================

struct MigrationPolicy {
    // Temperature thresholds
    double promoteThreshold = 0.7;      // Promote if temp > this
    double demoteThreshold = 0.2;        // Demote if temp < this
    
    // Access pattern thresholds
    uint32_t hotAccessThreshold = 100;   // Access count for hot
    uint32_t coldIdleMs = 5000;          // Idle time for cold (ms)
    
    // Capacity thresholds
    double vramPressureThreshold = 0.9;  // Start demoting when VRAM > 90%
    double unifiedTargetUsage = 0.7;     // Target unified memory usage
    
    // Prefetch settings
    bool enablePrefetch = true;
    uint32_t prefetchDistance = 2;       // Layers ahead to prefetch
    
    // Async settings
    bool asyncMigration = true;
    uint32_t maxConcurrentMigrations = 4;
    uint32_t migrationQueueSize = 100;
};

// =============================================================================
// Migration Statistics
// =============================================================================

struct MigrationStats {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> completed{0};
    std::atomic<uint64_t> failed{0};
    std::atomic<uint64_t> cancelled{0};
    
    std::atomic<uint64_t> promotes{0};
    std::atomic<uint64_t> demotes{0};
    std::atomic<uint64_t> syncs{0};
    std::atomic<uint64_t> prefetches{0};
    std::atomic<uint64_t> evicts{0};
    
    std::atomic<uint64_t> totalBytesMoved{0};
    std::atomic<uint64_t> totalMigrationTimeMs{0};
    
    double GetAverageMigrationTimeMs() const {
        uint64_t completed_val = completed.load();
        return completed_val > 0 ? static_cast<double>(totalMigrationTimeMs.load()) / completed_val : 0.0;
    }
    
    double GetThroughputMBps() const {
        double time_sec = totalMigrationTimeMs.load() / 1000.0;
        return time_sec > 0 ? (totalBytesMoved.load() / (1024.0 * 1024.0)) / time_sec : 0.0;
    }
};

// =============================================================================
// Migration Engine
// =============================================================================

class MigrationEngine {
public:
    static MigrationEngine& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Configuration
    void SetPolicy(const MigrationPolicy& policy);
    MigrationPolicy GetPolicy() const;
    
    // Migration requests
    bool RequestMigration(uint64_t vaddr, uint32_t srcTier, uint32_t dstTier, 
                          MigrationType type, bool async = true);
    bool RequestPromote(uint64_t vaddr, bool async = true);
    bool RequestDemote(uint64_t vaddr, bool async = true);
    bool RequestPrefetch(uint64_t vaddr, uint32_t targetTier, bool async = true);
    bool RequestSync(uint64_t vaddr, bool async = true);
    
    // Policy-driven decisions
    bool ShouldPromote(uint64_t vaddr, double temperature, uint32_t accessCount);
    bool ShouldDemote(uint64_t vaddr, double temperature, uint64_t idleTimeMs);
    bool ShouldPrefetch(uint64_t vaddr, uint32_t nextLayer);
    
    // Batch operations
    void ProcessBatch(const std::vector<MigrationRequest>& requests);
    void RunOptimizationPass();
    
    // Status
    bool IsMigrating(uint64_t vaddr);
    uint32_t GetQueueDepth() const;
    uint32_t GetActiveMigrations() const;
    
    // Statistics
    void PrintStats() const;
    const MigrationStats& GetStats() const { return stats_; }
    
    // Emergency pressure relief
    void EmergencyEvict(uint32_t tier, uint64_t targetBytes);
    
private:
    MigrationEngine() = default;
    ~MigrationEngine() = default;
    MigrationEngine(const MigrationEngine&) = delete;
    MigrationEngine& operator=(const MigrationEngine&) = delete;
    
    // Worker thread
    void WorkerLoop();
    bool ExecuteMigration(const MigrationRequest& req);
    
    // Priority queue
    struct PriorityCompare {
        bool operator()(const MigrationRequest& a, const MigrationRequest& b) {
            return a.priority < b.priority;  // Higher priority first
        }
    };
    
    std::priority_queue<MigrationRequest, std::vector<MigrationRequest>, PriorityCompare> queue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    // Worker threads
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
    std::atomic<uint32_t> activeMigrations_{0};
    
    // Tracking
    std::unordered_map<uint64_t, bool> migrating_;
    mutable std::mutex migratingMutex_;
    
    // Configuration
    MigrationPolicy policy_;
    mutable std::mutex policyMutex_;
    
    // Statistics
    MigrationStats stats_;
    
    bool initialized_ = false;
};

// =============================================================================
// Implementation
// =============================================================================

MigrationEngine& MigrationEngine::Instance() {
    static MigrationEngine instance;
    return instance;
}

bool MigrationEngine::Initialize() {
    std::cout << "\n========================================\n";
    std::cout << "RawRamXD Phase 7B.5: Migration Engine\n";
    std::cout << "Automatic Tier Movement\n";
    std::cout << "========================================\n\n";
    
    // Set default policy
    MigrationPolicy defaultPolicy;
    SetPolicy(defaultPolicy);
    
    // Start worker threads
    running_ = true;
    uint32_t numWorkers = std::max(1u, std::thread::hardware_concurrency() / 2);
    numWorkers = std::min(numWorkers, policy_.maxConcurrentMigrations);
    
    std::cout << "[+] Starting migration engine\n";
    std::cout << "    Workers: " << numWorkers << "\n";
    std::cout << "    Async: " << (policy_.asyncMigration ? "enabled" : "disabled") << "\n";
    std::cout << "    Max concurrent: " << policy_.maxConcurrentMigrations << "\n\n";
    
    for (uint32_t i = 0; i < numWorkers; i++) {
        workers_.emplace_back(&MigrationEngine::WorkerLoop, this);
    }
    
    initialized_ = true;
    return true;
}

void MigrationEngine::Shutdown() {
    if (!initialized_) return;
    
    std::cout << "\n[+] Shutting down migration engine...\n";
    
    running_ = false;
    queueCV_.notify_all();
    
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
    
    initialized_ = false;
    std::cout << "    Migration engine stopped\n";
}

void MigrationEngine::SetPolicy(const MigrationPolicy& policy) {
    std::lock_guard<std::mutex> lock(policyMutex_);
    policy_ = policy;
}

MigrationPolicy MigrationEngine::GetPolicy() const {
    std::lock_guard<std::mutex> lock(policyMutex_);
    return policy_;
}

bool MigrationEngine::RequestMigration(uint64_t vaddr, uint32_t srcTier, uint32_t dstTier,
                                        MigrationType type, bool async) {
    if (!initialized_) return false;
    
    // Check if already migrating
    {
        std::lock_guard<std::mutex> lock(migratingMutex_);
        if (migrating_[vaddr]) return false;
    }
    
    MigrationRequest req;
    req.virtualAddress = vaddr;
    req.sourceTier = srcTier;
    req.targetTier = dstTier;
    req.type = type;
    req.async = async;
    req.submitTime = GetTickCount64();
    
    // Calculate priority
    switch (type) {
        case MigrationType::PROMOTE: req.priority = 100; break;
        case MigrationType::DEMOTE: req.priority = 50; break;
        case MigrationType::SYNC: req.priority = 200; break;
        case MigrationType::PREFETCH: req.priority = 25; break;
        case MigrationType::EVICT: req.priority = 10; break;
        default: req.priority = 50;
    }
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (queue_.size() >= policy_.migrationQueueSize) {
            stats_.cancelled++;
            return false;
        }
        queue_.push(req);
    }
    
    stats_.totalRequests++;
    queueCV_.notify_one();
    
    if (!async) {
        // Wait for completion (simplified - would need completion tracking)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return true;
}

bool MigrationEngine::RequestPromote(uint64_t vaddr, bool async) {
    // Promote: typically tier 2 -> 1 -> 0 (slower to faster)
    return RequestMigration(vaddr, 2, 0, MigrationType::PROMOTE, async);
}

bool MigrationEngine::RequestDemote(uint64_t vaddr, bool async) {
    // Demote: typically tier 0 -> 1 -> 2 (faster to slower)
    return RequestMigration(vaddr, 0, 2, MigrationType::DEMOTE, async);
}

bool MigrationEngine::RequestPrefetch(uint64_t vaddr, uint32_t targetTier, bool async) {
    return RequestMigration(vaddr, 3, targetTier, MigrationType::PREFETCH, async);
}

bool MigrationEngine::RequestSync(uint64_t vaddr, bool async) {
    return RequestMigration(vaddr, 0, 0, MigrationType::SYNC, async);
}

bool MigrationEngine::ShouldPromote(uint64_t vaddr, double temperature, uint32_t accessCount) {
    std::lock_guard<std::mutex> lock(policyMutex_);
    
    if (temperature > policy_.promoteThreshold) return true;
    if (accessCount > policy_.hotAccessThreshold) return true;
    
    return false;
}

bool MigrationEngine::ShouldDemote(uint64_t vaddr, double temperature, uint64_t idleTimeMs) {
    std::lock_guard<std::mutex> lock(policyMutex_);
    
    if (temperature < policy_.demoteThreshold) return true;
    if (idleTimeMs > policy_.coldIdleMs) return true;
    
    return false;
}

bool MigrationEngine::ShouldPrefetch(uint64_t vaddr, uint32_t nextLayer) {
    std::lock_guard<std::mutex> lock(policyMutex_);
    
    if (!policy_.enablePrefetch) return false;
    if (nextLayer <= policy_.prefetchDistance) return true;
    
    return false;
}

void MigrationEngine::WorkerLoop() {
    while (running_) {
        MigrationRequest req;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] { return !queue_.empty() || !running_; });
            
            if (!running_) break;
            if (queue_.empty()) continue;
            
            req = queue_.top();
            queue_.pop();
        }
        
        // Mark as migrating
        {
            std::lock_guard<std::mutex> lock(migratingMutex_);
            migrating_[req.virtualAddress] = true;
        }
        
        activeMigrations_++;
        bool success = ExecuteMigration(req);
        activeMigrations_--;
        
        // Unmark
        {
            std::lock_guard<std::mutex> lock(migratingMutex_);
            migrating_.erase(req.virtualAddress);
        }
        
        // Update stats
        if (success) {
            stats_.completed++;
            switch (req.type) {
                case MigrationType::PROMOTE: stats_.promotes++; break;
                case MigrationType::DEMOTE: stats_.demotes++; break;
                case MigrationType::SYNC: stats_.syncs++; break;
                case MigrationType::PREFETCH: stats_.prefetches++; break;
                case MigrationType::EVICT: stats_.evicts++; break;
            }
        } else {
            stats_.failed++;
        }
        
        // Callback
        if (req.callback) {
            req.callback(success);
        }
    }
}

bool MigrationEngine::ExecuteMigration(const MigrationRequest& req) {
    uint64_t startTime = GetTickCount64();
    
    // Simulate migration delay based on type and tiers
    uint64_t delayMs = 0;
    switch (req.type) {
        case MigrationType::PROMOTE:
        case MigrationType::DEMOTE:
            delayMs = 5;  // 5ms for tier migration
            break;
        case MigrationType::SYNC:
            delayMs = 2;  // 2ms for sync
            break;
        case MigrationType::PREFETCH:
            delayMs = 10; // 10ms for prefetch (lower priority)
            break;
        case MigrationType::EVICT:
            delayMs = 1;  // 1ms for eviction
            break;
    }
    
    // Simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    
    uint64_t endTime = GetTickCount64();
    stats_.totalMigrationTimeMs += (endTime - startTime);
    stats_.totalBytesMoved += 4096;  // Assume 4KB pages
    
    std::cout << "[Migration] " << MigrationTypeToString(req.type)
              << " " << req.virtualAddress
              << " tier " << req.sourceTier << " -> " << req.targetTier
              << " (" << (endTime - startTime) << " ms)\n";
    
    return true;
}

void MigrationEngine::ProcessBatch(const std::vector<MigrationRequest>& requests) {
    for (const auto& req : requests) {
        RequestMigration(req.virtualAddress, req.sourceTier, req.targetTier,
                         req.type, req.async);
    }
}

void MigrationEngine::RunOptimizationPass() {
    std::cout << "\n[+] Running migration optimization pass...\n";
    
    // In real implementation:
    // 1. Scan all pages for hot/cold
    // 2. Queue promote/demote operations
    // 3. Balance tier capacities
    
    std::cout << "    Optimization pass complete\n";
}

bool MigrationEngine::IsMigrating(uint64_t vaddr) {
    std::lock_guard<std::mutex> lock(migratingMutex_);
    auto it = migrating_.find(vaddr);
    return it != migrating_.end() && it->second;
}

uint32_t MigrationEngine::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return static_cast<uint32_t>(queue_.size());
}

uint32_t MigrationEngine::GetActiveMigrations() const {
    return activeMigrations_.load();
}

void MigrationEngine::PrintStats() const {
    std::cout << "\nMigration Engine Statistics:\n";
    std::cout << "  Total Requests: " << stats_.totalRequests.load() << "\n";
    std::cout << "  Completed: " << stats_.completed.load() << "\n";
    std::cout << "  Failed: " << stats_.failed.load() << "\n";
    std::cout << "  Cancelled: " << stats_.cancelled.load() << "\n";
    std::cout << "\n  By Type:\n";
    std::cout << "    Promotes: " << stats_.promotes.load() << "\n";
    std::cout << "    Demotes: " << stats_.demotes.load() << "\n";
    std::cout << "    Syncs: " << stats_.syncs.load() << "\n";
    std::cout << "    Prefetches: " << stats_.prefetches.load() << "\n";
    std::cout << "    Evicts: " << stats_.evicts.load() << "\n";
    std::cout << "\n  Performance:\n";
    std::cout << "    Total Bytes: " << (stats_.totalBytesMoved.load() / (1024*1024)) << " MB\n";
    std::cout << "    Avg Time: " << stats_.GetAverageMigrationTimeMs() << " ms\n";
    std::cout << "    Throughput: " << stats_.GetThroughputMBps() << " MB/s\n";
}

void MigrationEngine::EmergencyEvict(uint32_t tier, uint64_t targetBytes) {
    std::cout << "\n[!] Emergency eviction from tier " << tier
              << " target: " << (targetBytes / (1024*1024)) << " MB\n";
    
    // In real implementation: evict coldest pages first
    // For now, just log
}

// =============================================================================
// C API
// =============================================================================

extern "C" {

bool RawRamXD_Migration_Initialize() {
    return MigrationEngine::Instance().Initialize();
}

void RawRamXD_Migration_Shutdown() {
    MigrationEngine::Instance().Shutdown();
}

bool RawRamXD_Migration_Request(uint64_t vaddr, int type, bool async) {
    return MigrationEngine::Instance().RequestMigration(vaddr, 0, 0, 
                                                        static_cast<MigrationType>(type), async);
}

bool RawRamXD_Migration_Promote(uint64_t vaddr, bool async) {
    return MigrationEngine::Instance().RequestPromote(vaddr, async);
}

bool RawRamXD_Migration_Demote(uint64_t vaddr, bool async) {
    return MigrationEngine::Instance().RequestDemote(vaddr, async);
}

bool RawRamXD_Migration_Prefetch(uint64_t vaddr, uint32_t tier, bool async) {
    return MigrationEngine::Instance().RequestPrefetch(vaddr, tier, async);
}

void RawRamXD_Migration_RunOptimization() {
    MigrationEngine::Instance().RunOptimizationPass();
}

void RawRamXD_Migration_PrintStats() {
    MigrationEngine::Instance().PrintStats();
}

void RawRamXD_Migration_EmergencyEvict(int tier, uint64_t bytes) {
    MigrationEngine::Instance().EmergencyEvict(tier, bytes);
}

} // extern "C"

} // namespace RawRamXD

// =============================================================================
// Main Test
// =============================================================================

int main() {
    using namespace RawRamXD;
    
    std::cout << "========================================\n";
    std::cout << "RawRamXD Phase 7B.5: Migration Engine Test\n";
    std::cout << "========================================\n\n";
    
    if (!RawRamXD_Migration_Initialize()) {
        std::cerr << "[!] Failed to initialize migration engine\n";
        return 1;
    }
    
    auto& engine = MigrationEngine::Instance();
    
    // Test 1: Basic migrations
    std::cout << "[+] Test 1: Basic migrations\n";
    for (int i = 0; i < 5; i++) {
        engine.RequestPromote(0x1000ULL * i, true);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Test 2: Policy decisions
    std::cout << "\n[+] Test 2: Policy decisions\n";
    bool shouldPromote = engine.ShouldPromote(0x1000, 0.8, 150);
    bool shouldDemote = engine.ShouldDemote(0x2000, 0.1, 6000);
    
    std::cout << "    Page 0x1000: temp=0.8, accesses=150 -> " 
              << (shouldPromote ? "PROMOTE" : "stay") << "\n";
    std::cout << "    Page 0x2000: temp=0.1, idle=6000ms -> " 
              << (shouldDemote ? "DEMOTE" : "stay") << "\n";
    
    // Test 3: Batch processing
    std::cout << "\n[+] Test 3: Batch processing\n";
    std::vector<MigrationRequest> batch;
    for (int i = 10; i < 15; i++) {
        MigrationRequest req;
        req.virtualAddress = 0x1000ULL * i;
        req.sourceTier = 2;
        req.targetTier = 0;
        req.type = MigrationType::PROMOTE;
        req.async = true;
        batch.push_back(req);
    }
    engine.ProcessBatch(batch);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Test 4: Status check
    std::cout << "\n[+] Test 4: Status check\n";
    std::cout << "    Queue depth: " << engine.GetQueueDepth() << "\n";
    std::cout << "    Active migrations: " << engine.GetActiveMigrations() << "\n";
    
    // Print stats
    std::cout << "\n";
    engine.PrintStats();
    
    // Test 5: Optimization pass
    std::cout << "\n[+] Test 5: Optimization pass\n";
    engine.RunOptimizationPass();
    
    // Cleanup
    std::cout << "\n[+] Shutting down...\n";
    RawRamXD_Migration_Shutdown();
    
    std::cout << "\n========================================\n";
    std::cout << "Phase 7B.5 Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
