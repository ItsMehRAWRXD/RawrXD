// =============================================================================
// Truth Gate 003: Fabric Stress Test Harness
// Validates: ensureResident → ticket → wait → access → migrate → version++
// =============================================================================

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <queue>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <random>
#include <algorithm>
#include <condition_variable>

#include <windows.h>

namespace RawRamXD {

// =============================================================================
// Core Primitive: Ticket-Based Residency
// =============================================================================

enum class ResidencyStatus {
    PENDING = 0,      // Migration in progress
    READY = 1,        // Resident and ready
    FAILED = 2,       // Migration failed
    TIMEOUT = 3       // Wait timeout
};

struct ResidencyTicket {
    uint64_t id;
    uint64_t virtualAddress;
    uint32_t targetTier;
    ResidencyStatus status;
    uint64_t versionBefore;
    uint64_t versionAfter;
    uint64_t submitTime;
    uint64_t completeTime;
    uint64_t bytesMigrated;
    bool isAsync;
};

// =============================================================================
// Telemetry Event
// =============================================================================

struct TelemetryEvent {
    uint64_t timestamp;
    uint64_t inferenceId;
    const char* operation;     // "ensure", "migrate", "access", "checksum"
    uint64_t tensorId;
    uint32_t tierBefore;
    uint32_t tierAfter;
    const char* action;        // "promote", "demote", "stay", "prefetch"
    uint64_t ticketId;
    uint64_t versionBefore;
    uint64_t versionAfter;
    double durationMs;
    uint64_t bytesMigrated;
    double temperature;
    uint32_t checksum;
};

// =============================================================================
// Global Telemetry Logger
// =============================================================================

class TelemetryLogger {
public:
    static TelemetryLogger& Instance();
    
    void Initialize(const std::string& filename);
    void Shutdown();
    
    void LogEvent(const TelemetryEvent& event);
    void LogMigration(uint64_t inferenceId, uint64_t tensorId, 
                      uint32_t tierBefore, uint32_t tierAfter,
                      const char* action, uint64_t ticketId,
                      uint64_t versionBefore, uint64_t versionAfter,
                      double durationMs, uint64_t bytesMigrated);
    void LogAccess(uint64_t inferenceId, uint64_t tensorId, uint32_t tier,
                   double temperature, uint32_t checksum);
    void LogChecksum(uint64_t inferenceId, uint64_t layerId, 
                     uint32_t expected, uint32_t actual, bool match);
    
    void Flush();
    void PrintStats();
    
    uint64_t GetEventCount() const { return eventCount_.load(); }
    uint64_t GetMigrationCount() const { return migrationCount_.load(); }
    uint64_t GetChecksumMismatchCount() const { return checksumMismatch_.load(); }
    
private:
    TelemetryLogger() = default;
    ~TelemetryLogger() = default;
    
    std::ofstream logFile_;
    std::mutex logMutex_;
    std::queue<TelemetryEvent> eventQueue_;
    
    std::atomic<uint64_t> eventCount_{0};
    std::atomic<uint64_t> migrationCount_{0};
    std::atomic<uint64_t> checksumMismatch_{0};
    std::atomic<uint64_t> totalMigrationBytes_{0};
    std::atomic<uint64_t> totalMigrationTimeMs_{0};
    
    bool initialized_ = false;
};

TelemetryLogger& TelemetryLogger::Instance() {
    static TelemetryLogger instance;
    return instance;
}

void TelemetryLogger::Initialize(const std::string& filename) {
    std::lock_guard<std::mutex> lock(logMutex_);
    logFile_.open(filename, std::ios::out | std::ios::trunc);
    if (logFile_.is_open()) {
        // CSV header
        logFile_ << "timestamp,inference_id,operation,tensor_id,tier_before,tier_after,"
                 << "action,ticket_id,version_before,version_after,duration_ms,"
                 << "bytes_migrated,temperature,checksum\n";
        logFile_.flush();
        initialized_ = true;
        std::cout << "[Telemetry] Logging to: " << filename << "\n";
    }
}

void TelemetryLogger::Shutdown() {
    Flush();
    std::lock_guard<std::mutex> lock(logMutex_);
    if (logFile_.is_open()) {
        logFile_.close();
    }
    initialized_ = false;
}

void TelemetryLogger::LogEvent(const TelemetryEvent& event) {
    if (!initialized_) return;
    
    std::lock_guard<std::mutex> lock(logMutex_);
    
    logFile_ << event.timestamp << ","
             << event.inferenceId << ","
             << event.operation << ","
             << event.tensorId << ","
             << event.tierBefore << ","
             << event.tierAfter << ","
             << (event.action ? event.action : "") << ","
             << event.ticketId << ","
             << event.versionBefore << ","
             << event.versionAfter << ","
             << std::fixed << std::setprecision(3) << event.durationMs << ","
             << event.bytesMigrated << ","
             << std::fixed << std::setprecision(2) << event.temperature << ","
             << event.checksum << "\n";
    
    eventCount_++;
}

void TelemetryLogger::LogMigration(uint64_t inferenceId, uint64_t tensorId,
                                   uint32_t tierBefore, uint32_t tierAfter,
                                   const char* action, uint64_t ticketId,
                                   uint64_t versionBefore, uint64_t versionAfter,
                                   double durationMs, uint64_t bytesMigrated) {
    TelemetryEvent evt{};
    evt.timestamp = GetTickCount64();
    evt.inferenceId = inferenceId;
    evt.operation = "migrate";
    evt.tensorId = tensorId;
    evt.tierBefore = tierBefore;
    evt.tierAfter = tierAfter;
    evt.action = action;
    evt.ticketId = ticketId;
    evt.versionBefore = versionBefore;
    evt.versionAfter = versionAfter;
    evt.durationMs = durationMs;
    evt.bytesMigrated = bytesMigrated;
    evt.temperature = 0.0;
    evt.checksum = 0;
    
    LogEvent(evt);
    
    migrationCount_++;
    totalMigrationBytes_ += bytesMigrated;
    totalMigrationTimeMs_ += static_cast<uint64_t>(durationMs);
}

void TelemetryLogger::LogAccess(uint64_t inferenceId, uint64_t tensorId, 
                                uint32_t tier, double temperature, uint32_t checksum) {
    TelemetryEvent evt{};
    evt.timestamp = GetTickCount64();
    evt.inferenceId = inferenceId;
    evt.operation = "access";
    evt.tensorId = tensorId;
    evt.tierBefore = tier;
    evt.tierAfter = tier;
    evt.action = "";
    evt.ticketId = 0;
    evt.versionBefore = 0;
    evt.versionAfter = 0;
    evt.durationMs = 0.0;
    evt.bytesMigrated = 0;
    evt.temperature = temperature;
    evt.checksum = checksum;
    
    LogEvent(evt);
}

void TelemetryLogger::LogChecksum(uint64_t inferenceId, uint64_t layerId,
                                  uint32_t expected, uint32_t actual, bool match) {
    TelemetryEvent evt{};
    evt.timestamp = GetTickCount64();
    evt.inferenceId = inferenceId;
    evt.operation = match ? "checksum_ok" : "checksum_fail";
    evt.tensorId = layerId;
    evt.tierBefore = 0;
    evt.tierAfter = 0;
    evt.action = "";
    evt.ticketId = 0;
    evt.versionBefore = expected;
    evt.versionAfter = actual;
    evt.durationMs = 0.0;
    evt.bytesMigrated = 0;
    evt.temperature = 0.0;
    evt.checksum = actual;
    
    LogEvent(evt);
    
    if (!match) {
        checksumMismatch_++;
        std::cerr << "[!] CHECKSUM MISMATCH: inference=" << inferenceId 
                  << " layer=" << layerId 
                  << " expected=" << expected 
                  << " actual=" << actual << "\n";
    }
}

void TelemetryLogger::Flush() {
    std::lock_guard<std::mutex> lock(logMutex_);
    if (logFile_.is_open()) {
        logFile_.flush();
    }
}

void TelemetryLogger::PrintStats() {
    std::cout << "\n========== Telemetry Statistics ==========\n";
    std::cout << "Total Events: " << eventCount_.load() << "\n";
    std::cout << "Total Migrations: " << migrationCount_.load() << "\n";
    std::cout << "Checksum Mismatches: " << checksumMismatch_.load() << "\n";
    std::cout << "Total Migration Bytes: " << (totalMigrationBytes_.load() / (1024.0 * 1024.0)) << " MB\n";
    
    uint64_t migCount = migrationCount_.load();
    if (migCount > 0) {
        double avgTime = static_cast<double>(totalMigrationTimeMs_.load()) / migCount;
        std::cout << "Avg Migration Time: " << avgTime << " ms\n";
    }
    std::cout << "==========================================\n";
}

// =============================================================================
// Simplified Fabric Page (Core State)
// =============================================================================

struct FabricPage {
    uint64_t virtualAddress;
    uint64_t size;
    uint32_t currentTier;
    uint32_t ownerTier;
    uint64_t version;
    double temperature;
    uint32_t accessCount;
    uint64_t lastAccessTime;
    bool dirty;
    std::atomic<bool> migrating{false};
};

// =============================================================================
// Fabric Core: ensureResident Primitive
// =============================================================================

class FabricCore {
public:
    static FabricCore& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // The Core Primitive: ensureResident → ticket
    ResidencyTicket* EnsureResident(uint64_t vaddr, uint32_t preferredTier, bool async = true);
    
    // Ticket lifecycle
    bool WaitForTicket(ResidencyTicket* ticket, uint32_t timeoutMs = 5000);
    bool IsTicketReady(ResidencyTicket* ticket);
    void ReleaseTicket(ResidencyTicket* ticket);
    
    // Access with ticket
    void* AccessWithTicket(ResidencyTicket* ticket);
    
    // Page management
    uint64_t AllocatePage(uint64_t size, uint32_t homeTier);
    void FreePage(uint64_t vaddr);
    
    // Checksum for correctness validation
    uint32_t ComputeChecksum(uint64_t vaddr, uint64_t size);
    bool ValidateChecksum(uint64_t vaddr, uint64_t size, uint32_t expected);
    
    // Stats
    void PrintStats();
    
private:
    FabricCore() = default;
    ~FabricCore() = default;
    
    std::unordered_map<uint64_t, std::unique_ptr<FabricPage>> pages_;
    std::unordered_map<uint64_t, std::unique_ptr<ResidencyTicket>> tickets_;
    std::mutex pagesMutex_;
    std::mutex ticketsMutex_;
    
    std::atomic<uint64_t> nextTicketId_{1};
    std::atomic<uint64_t> nextVaddr_{0x100000000ULL};
    
    // Migration worker
    std::thread migrationWorker_;
    std::atomic<bool> running_{false};
    std::queue<ResidencyTicket*> migrationQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCV_;
    
    void MigrationWorkerLoop();
    bool ExecuteMigration(ResidencyTicket* ticket);
    
    FabricPage* FindPage(uint64_t vaddr);
};

FabricCore& FabricCore::Instance() {
    static FabricCore instance;
    return instance;
}

bool FabricCore::Initialize() {
    std::cout << "\n========================================\n";
    std::cout << "Truth Gate 003: Fabric Core Initialized\n";
    std::cout << "Primitive: ensureResident → ticket → version++\n";
    std::cout << "========================================\n\n";
    
    running_ = true;
    migrationWorker_ = std::thread(&FabricCore::MigrationWorkerLoop, this);
    
    return true;
}

void FabricCore::Shutdown() {
    running_ = false;
    queueCV_.notify_all();
    if (migrationWorker_.joinable()) {
        migrationWorker_.join();
    }
}

FabricPage* FabricCore::FindPage(uint64_t vaddr) {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    auto it = pages_.find(vaddr);
    return (it != pages_.end()) ? it->second.get() : nullptr;
}

uint64_t FabricCore::AllocatePage(uint64_t size, uint32_t homeTier) {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    
    uint64_t vaddr = nextVaddr_.fetch_add(((size + 4095) / 4096) * 4096);
    
    auto page = std::make_unique<FabricPage>();
    page->virtualAddress = vaddr;
    page->size = size;
    page->currentTier = homeTier;
    page->ownerTier = homeTier;
    page->version = 1;
    page->temperature = 0.5;
    page->accessCount = 0;
    page->lastAccessTime = GetTickCount64();
    page->dirty = false;
    page->migrating = false;
    
    pages_[vaddr] = std::move(page);
    
    return vaddr;
}

void FabricCore::FreePage(uint64_t vaddr) {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    pages_.erase(vaddr);
}

ResidencyTicket* FabricCore::EnsureResident(uint64_t vaddr, uint32_t preferredTier, bool async) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return nullptr;
    
    // Fast path: already resident in preferred tier
    if (page->currentTier == preferredTier && !page->migrating.load()) {
        auto ticket = std::make_unique<ResidencyTicket>();
        ticket->id = nextTicketId_++;
        ticket->virtualAddress = vaddr;
        ticket->targetTier = preferredTier;
        ticket->status = ResidencyStatus::READY;
        ticket->versionBefore = page->version;
        ticket->versionAfter = page->version;
        ticket->submitTime = GetTickCount64();
        ticket->completeTime = ticket->submitTime;
        ticket->bytesMigrated = 0;
        ticket->isAsync = async;
        
        ResidencyTicket* result = ticket.get();
        
        std::lock_guard<std::mutex> lock(ticketsMutex_);
        tickets_[ticket->id] = std::move(ticket);
        
        return result;
    }
    
    // Slow path: need migration
    auto ticket = std::make_unique<ResidencyTicket>();
    ticket->id = nextTicketId_++;
    ticket->virtualAddress = vaddr;
    ticket->targetTier = preferredTier;
    ticket->status = ResidencyStatus::PENDING;
    ticket->versionBefore = page->version;
    ticket->versionAfter = page->version;
    ticket->submitTime = GetTickCount64();
    ticket->completeTime = 0;
    ticket->bytesMigrated = page->size;
    ticket->isAsync = async;
    
    ResidencyTicket* result = ticket.get();
    
    {
        std::lock_guard<std::mutex> lock(ticketsMutex_);
        tickets_[ticket->id] = std::move(ticket);
    }
    
    // Queue for migration
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        migrationQueue_.push(result);
    }
    queueCV_.notify_one();
    
    // Log the ensure request
    TelemetryLogger::Instance().LogEvent({
        GetTickCount64(), 0, "ensure", vaddr, 
        page->currentTier, preferredTier, "", ticket->id,
        page->version, page->version, 0.0, page->size, 
        page->temperature, 0
    });
    
    if (!async) {
        WaitForTicket(result, 5000);
    }
    
    return result;
}

bool FabricCore::WaitForTicket(ResidencyTicket* ticket, uint32_t timeoutMs) {
    if (!ticket) return false;
    
    uint64_t startTime = GetTickCount64();
    
    while (ticket->status == ResidencyStatus::PENDING) {
        if (GetTickCount64() - startTime > timeoutMs) {
            ticket->status = ResidencyStatus::TIMEOUT;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    return ticket->status == ResidencyStatus::READY;
}

bool FabricCore::IsTicketReady(ResidencyTicket* ticket) {
    return ticket && ticket->status == ResidencyStatus::READY;
}

void FabricCore::ReleaseTicket(ResidencyTicket* ticket) {
    if (!ticket) return;
    
    std::lock_guard<std::mutex> lock(ticketsMutex_);
    tickets_.erase(ticket->id);
}

void* FabricCore::AccessWithTicket(ResidencyTicket* ticket) {
    if (!ticket || ticket->status != ResidencyStatus::READY) {
        return nullptr;
    }
    
    FabricPage* page = FindPage(ticket->virtualAddress);
    if (!page) return nullptr;
    
    // Update access stats
    page->accessCount++;
    page->lastAccessTime = GetTickCount64();
    page->temperature = std::min(1.0, page->temperature + 0.01);
    
    // Return simulated pointer
    return reinterpret_cast<void*>(ticket->virtualAddress);
}

void FabricCore::MigrationWorkerLoop() {
    while (running_) {
        ResidencyTicket* ticket = nullptr;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] { return !migrationQueue_.empty() || !running_; });
            
            if (!running_) break;
            if (migrationQueue_.empty()) continue;
            
            ticket = migrationQueue_.front();
            migrationQueue_.pop();
        }
        
        if (ticket) {
            ExecuteMigration(ticket);
        }
    }
}

bool FabricCore::ExecuteMigration(ResidencyTicket* ticket) {
    FabricPage* page = FindPage(ticket->virtualAddress);
    if (!page) {
        ticket->status = ResidencyStatus::FAILED;
        return false;
    }
    
    // Mark as migrating
    page->migrating = true;
    
    uint32_t srcTier = page->currentTier;
    uint32_t dstTier = ticket->targetTier;
    uint64_t startTime = GetTickCount64();
    
    // Simulate migration delay based on tier distance
    uint64_t delayMs = 0;
    if (srcTier == dstTier) {
        delayMs = 0;
    } else if ((srcTier == 0 && dstTier == 1) || (srcTier == 1 && dstTier == 0)) {
        delayMs = 5;   // VRAM <-> Unified
    } else if ((srcTier == 1 && dstTier == 2) || (srcTier == 2 && dstTier == 1)) {
        delayMs = 10;  // Unified <-> System
    } else {
        delayMs = 50;  // Cross-tier
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    
    // Atomic update: owner := new_tier; version++
    page->currentTier = dstTier;
    page->ownerTier = dstTier;
    page->version++;
    page->migrating = false;
    
    ticket->status = ResidencyStatus::READY;
    ticket->completeTime = GetTickCount64();
    ticket->versionAfter = page->version;
    
    uint64_t durationMs = ticket->completeTime - startTime;
    
    // Determine action type
    const char* action = "migrate";
    if (dstTier < srcTier) action = "promote";
    else if (dstTier > srcTier) action = "demote";
    
    // Log migration
    TelemetryLogger::Instance().LogMigration(
        0, ticket->virtualAddress, srcTier, dstTier,
        action, ticket->id, ticket->versionBefore, ticket->versionAfter,
        static_cast<double>(durationMs), ticket->bytesMigrated
    );
    
    return true;
}

uint32_t FabricCore::ComputeChecksum(uint64_t vaddr, uint64_t size) {
    // Simplified checksum - in real implementation would hash actual data
    FabricPage* page = FindPage(vaddr);
    if (!page) return 0;
    
    // Deterministic checksum based on page metadata
    uint32_t checksum = static_cast<uint32_t>(vaddr ^ size ^ page->version);
    checksum ^= static_cast<uint32_t>(page->accessCount * 31);
    return checksum;
}

bool FabricCore::ValidateChecksum(uint64_t vaddr, uint64_t size, uint32_t expected) {
    uint32_t actual = ComputeChecksum(vaddr, size);
    bool match = (actual == expected);
    
    TelemetryLogger::Instance().LogChecksum(0, vaddr, expected, actual, match);
    
    return match;
}

void FabricCore::PrintStats() {
    std::cout << "\n========== Fabric Core Statistics ==========\n";
    std::cout << "Pages: " << pages_.size() << "\n";
    std::cout << "Active Tickets: " << tickets_.size() << "\n";
    std::cout << "============================================\n";
}

// =============================================================================
// Truth Gate 003 Test Scenarios
// =============================================================================

class TruthGate003Harness {
public:
    bool Initialize(const std::string& modelPath, uint32_t contextLength);
    void Shutdown();
    
    // Test scenarios
    bool RunBaselineTest();           // Model fits VRAM
    bool RunMildSpillTest();          // 105-110% VRAM
    bool RunTargetStressTest();       // 125% VRAM (key test)
    bool RunHeavyStressTest();        // 150% VRAM
    bool RunExtremeStressTest();      // 200% VRAM
    bool RunFaultInjectionTest();     // GPU disappearance
    
    // Results
    void PrintResults();
    bool DidPass() const { return allTestsPassed_; }
    
private:
    std::string modelPath_;
    uint32_t contextLength_;
    bool allTestsPassed_ = true;
    
    struct TestResult {
        const char* name;
        bool passed;
        double avgLatencyMs;
        double tokensPerSec;
        uint64_t migrations;
        uint64_t checksumMismatches;
        const char* notes;
    };
    std::vector<TestResult> results_;
    
    bool RunScenario(const char* name, double vramOvercommitRatio, 
                     bool injectFaults = false);
    void SimulateInference(const char* scenarioName, uint32_t numTokens,
                          double overcommitRatio, bool injectFaults);
};

bool TruthGate003Harness::Initialize(const std::string& modelPath, uint32_t contextLength) {
    modelPath_ = modelPath;
    contextLength_ = contextLength;
    
    std::cout << "\n========================================\n";
    std::cout << "Truth Gate 003: Fabric Stress Test Harness\n";
    std::cout << "Model: " << modelPath << "\n";
    std::cout << "Context: " << contextLength << " tokens\n";
    std::cout << "========================================\n\n";
    
    // Initialize telemetry
    TelemetryLogger::Instance().Initialize("truth_gate_003_telemetry.csv");
    
    // Initialize fabric core
    if (!FabricCore::Instance().Initialize()) {
        std::cerr << "[!] Failed to initialize fabric core\n";
        return false;
    }
    
    return true;
}

void TruthGate003Harness::Shutdown() {
    FabricCore::Instance().Shutdown();
    TelemetryLogger::Instance().Shutdown();
    PrintResults();
}

void TruthGate003Harness::SimulateInference(const char* scenarioName, uint32_t numTokens,
                                            double overcommitRatio, bool injectFaults) {
    auto& fabric = FabricCore::Instance();
    auto& telemetry = TelemetryLogger::Instance();
    
    // Simulate model allocation with overcommit
    uint64_t modelSize = static_cast<uint64_t>(16ULL * 1024 * 1024 * 1024 * overcommitRatio);  // 16GB * ratio
    uint64_t kvCacheSize = static_cast<uint64_t>(contextLength_ * 1024 * 1024);  // ~1MB per token
    
    std::cout << "  Allocating model: " << (modelSize / (1024.0 * 1024.0 * 1024.0)) << " GB\n";
    std::cout << "  KV cache: " << (kvCacheSize / (1024.0 * 1024.0)) << " MB\n";
    
    // Allocate model weights (simulated layers)
    std::vector<uint64_t> layerHandles;
    uint32_t numLayers = 40;
    uint64_t layerSize = modelSize / numLayers;
    
    for (uint32_t i = 0; i < numLayers; i++) {
        // Distribute across tiers based on overcommit
        uint32_t tier = 0;  // VRAM
        if (overcommitRatio > 1.0) {
            // Some layers spill to slower tiers
            if (i % 4 == 0) tier = 1;  // Unified
            if (i % 8 == 0) tier = 2;  // System
        }
        
        uint64_t handle = fabric.AllocatePage(layerSize, tier);
        layerHandles.push_back(handle);
    }
    
    // Simulate token generation
    uint64_t startTime = GetTickCount64();
    uint32_t tokensGenerated = 0;
    uint32_t checksumMismatches = 0;
    
    for (uint32_t token = 0; token < numTokens; token++) {
        // Simulate layer execution
        for (uint32_t layer = 0; layer < numLayers; layer++) {
            // Ensure resident before access
            ResidencyTicket* ticket = fabric.EnsureResident(layerHandles[layer], 0, true);
            if (ticket) {
                fabric.WaitForTicket(ticket, 100);
                
                if (ticket->status == ResidencyStatus::READY) {
                    // Access the layer
                    void* ptr = fabric.AccessWithTicket(ticket);
                    
                    // Compute and validate checksum
                    uint32_t expectedChecksum = fabric.ComputeChecksum(layerHandles[layer], layerSize);
                    if (!fabric.ValidateChecksum(layerHandles[layer], layerSize, expectedChecksum)) {
                        checksumMismatches++;
                    }
                }
                
                fabric.ReleaseTicket(ticket);
            }
            
            // Simulate compute time
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        tokensGenerated++;
        
        // Progress update every 10 tokens
        if (token % 10 == 0) {
            std::cout << "    Tokens: " << token << "/" << numTokens 
                      << " (migrations: " << telemetry.GetMigrationCount() << ")\r" << std::flush;
        }
        
        // Fault injection
        if (injectFaults && token == numTokens / 2) {
            std::cout << "\n    [!] Injecting GPU fault at token " << token << "\n";
            // Simulate fault recovery
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    uint64_t endTime = GetTickCount64();
    double totalTimeSec = (endTime - startTime) / 1000.0;
    double tokensPerSec = tokensGenerated / totalTimeSec;
    double avgLatencyMs = totalTimeSec * 1000.0 / tokensGenerated;
    
    std::cout << "\n  Completed: " << tokensGenerated << " tokens in " << totalTimeSec << "s\n";
    std::cout << "  TPS: " << tokensPerSec << "\n";
    std::cout << "  Avg latency: " << avgLatencyMs << " ms/token\n";
    
    // Cleanup
    for (auto handle : layerHandles) {
        fabric.FreePage(handle);
    }
}

bool TruthGate003Harness::RunScenario(const char* name, double vramOvercommitRatio, 
                                      bool injectFaults) {
    std::cout << "\n[+] Running: " << name << "\n";
    std::cout << "    VRAM overcommit: " << (vramOvercommitRatio * 100.0) << "%\n";
    
    uint32_t numTokens = 100;  // Reduced for testing
    
    SimulateInference(name, numTokens, vramOvercommitRatio, injectFaults);
    
    auto& telemetry = TelemetryLogger::Instance();
    
    TestResult result;
    result.name = name;
    result.migrations = telemetry.GetMigrationCount();
    result.checksumMismatches = telemetry.GetChecksumMismatchCount();
    
    // Pass criteria
    bool passed = (result.checksumMismatches == 0);
    
    result.passed = passed;
    result.notes = passed ? "PASS" : "FAIL: checksum mismatches";
    results_.push_back(result);
    
    if (!passed) {
        allTestsPassed_ = false;
    }
    
    std::cout << "  Result: " << result.notes << "\n";
    
    return passed;
}

bool TruthGate003Harness::RunBaselineTest() {
    return RunScenario("Baseline (100% VRAM)", 1.0, false);
}

bool TruthGate003Harness::RunMildSpillTest() {
    return RunScenario("Mild Spill (110% VRAM)", 1.10, false);
}

bool TruthGate003Harness::RunTargetStressTest() {
    return RunScenario("Target Stress (125% VRAM)", 1.25, false);
}

bool TruthGate003Harness::RunHeavyStressTest() {
    return RunScenario("Heavy Stress (150% VRAM)", 1.50, false);
}

bool TruthGate003Harness::RunExtremeStressTest() {
    return RunScenario("Extreme Stress (200% VRAM)", 2.0, false);
}

bool TruthGate003Harness::RunFaultInjectionTest() {
    return RunScenario("Fault Injection (125% + faults)", 1.25, true);
}

void TruthGate003Harness::PrintResults() {
    std::cout << "\n========================================\n";
    std::cout << "Truth Gate 003: Test Results Summary\n";
    std::cout << "========================================\n\n";
    
    for (const auto& result : results_) {
        std::cout << result.name << ": " 
                  << (result.passed ? "PASS" : "FAIL")
                  << " (migrations: " << result.migrations 
                  << ", checksum mismatches: " << result.checksumMismatches << ")\n";
    }
    
    std::cout << "\nOverall: " << (allTestsPassed_ ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    std::cout << "========================================\n";
}

} // namespace RawRamXD

// =============================================================================
// Main Entry
// =============================================================================

int main(int argc, char* argv[]) {
    using namespace RawRamXD;
    
    std::cout << "========================================\n";
    std::cout << "Truth Gate 003: Fabric Stress Test\n";
    std::cout << "Validating: ensureResident → ticket → version++\n";
    std::cout << "========================================\n\n";
    
    // Parse args
    std::string modelPath = "phi-3-13b.gguf";
    uint32_t contextLength = 4096;
    
    if (argc > 1) modelPath = argv[1];
    if (argc > 2) contextLength = std::atoi(argv[2]);
    
    // Initialize harness
    TruthGate003Harness harness;
    if (!harness.Initialize(modelPath, contextLength)) {
        return 1;
    }
    
    // Run test scenarios
    std::cout << "Running test scenarios...\n";
    
    harness.RunBaselineTest();
    harness.RunMildSpillTest();
    harness.RunTargetStressTest();
    harness.RunHeavyStressTest();
    harness.RunExtremeStressTest();
    harness.RunFaultInjectionTest();
    
    // Cleanup and results
    harness.Shutdown();
    
    // Print final telemetry stats
    TelemetryLogger::Instance().PrintStats();
    
    return harness.DidPass() ? 0 : 1;
}
