/**
 * MutationJournal.cpp
 *
 * Phase C.4 Batch 3/5: Autonomous Rollback Engine
 */

#include "MutationJournal.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace Autonomy {

// ============================================================================
// Mutation Type Conversions
// ============================================================================

std::string MutationTypeToString(MutationType type) {
    switch (type) {
        case MutationType::ADD_PARALLEL_PATH: return "ADD_PARALLEL_PATH";
        case MutationType::REMOVE_PARALLEL_PATH: return "REMOVE_PARALLEL_PATH";
        case MutationType::MERGE_NODES: return "MERGE_NODES";
        case MutationType::SPLIT_NODES: return "SPLIT_NODES";
        case MutationType::ADJUST_WEIGHTS: return "ADJUST_WEIGHTS";
        case MutationType::CHANGE_PRIORITY: return "CHANGE_PRIORITY";
        case MutationType::INSERT_ISOLATION: return "INSERT_ISOLATION";
        case MutationType::REMOVE_ISOLATION: return "REMOVE_ISOLATION";
        case MutationType::REMOVE_REDUNDANCY: return "REMOVE_REDUNDANCY";
        case MutationType::RESTORE_REDUNDANCY: return "RESTORE_REDUNDANCY";
        case MutationType::MODIFY_ROLE: return "MODIFY_ROLE";
        case MutationType::ADJUST_INTENT_STRENGTH: return "ADJUST_INTENT_STRENGTH";
        case MutationType::SCHEDULER_RECONFIG: return "SCHEDULER_RECONFIG";
        default: return "UNKNOWN";
    }
}

MutationType StringToMutationType(const std::string& str) {
    if (str == "ADD_PARALLEL_PATH") return MutationType::ADD_PARALLEL_PATH;
    if (str == "REMOVE_PARALLEL_PATH") return MutationType::REMOVE_PARALLEL_PATH;
    if (str == "MERGE_NODES") return MutationType::MERGE_NODES;
    if (str == "SPLIT_NODES") return MutationType::SPLIT_NODES;
    if (str == "ADJUST_WEIGHTS") return MutationType::ADJUST_WEIGHTS;
    if (str == "CHANGE_PRIORITY") return MutationType::CHANGE_PRIORITY;
    if (str == "INSERT_ISOLATION") return MutationType::INSERT_ISOLATION;
    if (str == "REMOVE_ISOLATION") return MutationType::REMOVE_ISOLATION;
    if (str == "REMOVE_REDUNDANCY") return MutationType::REMOVE_REDUNDANCY;
    if (str == "RESTORE_REDUNDANCY") return MutationType::RESTORE_REDUNDANCY;
    if (str == "MODIFY_ROLE") return MutationType::MODIFY_ROLE;
    if (str == "ADJUST_INTENT_STRENGTH") return MutationType::ADJUST_INTENT_STRENGTH;
    if (str == "SCHEDULER_RECONFIG") return MutationType::SCHEDULER_RECONFIG;
    return MutationType::UNKNOWN;
}

// ============================================================================
// Rollback Policy Conversion
// ============================================================================

std::string RollbackPolicyToString(RollbackPolicy policy) {
    switch (policy) {
        case RollbackPolicy::ON_FAILURE: return "ON_FAILURE";
        case RollbackPolicy::ON_OSCILLATION: return "ON_OSCILLATION";
        case RollbackPolicy::ON_CONVERGENCE_DROP: return "ON_CONVERGENCE_DROP";
        case RollbackPolicy::ON_MEMORY_PRESSURE: return "ON_MEMORY_PRESSURE";
        case RollbackPolicy::ON_TIMEOUT: return "ON_TIMEOUT";
        case RollbackPolicy::MANUAL: return "MANUAL";
        case RollbackPolicy::AUTONOMOUS: return "AUTONOMOUS";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// SystemSnapshot Implementation
// ============================================================================

std::string SystemSnapshot::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"snapshotId\":" << snapshotId << ",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"nodeCount\":" << nodeCount << ",";
    json << "\"edgeCount\":" << edgeCount << ",";
    json << "\"cpuUsage\":" << cpuUsage << ",";
    json << "\"memoryUsage\":" << memoryUsage << ",";
    json << "\"convergenceScore\":" << convergenceScore << ",";
    json << "\"stabilityScore\":" << stabilityScore;
    json << "}";
    return json.str();
}

void SystemSnapshot::Print() const {
    std::cout << "Snapshot " << snapshotId << " @ " << timestampMs << "\n";
    std::cout << "  Nodes: " << nodeCount << ", Edges: " << edgeCount << "\n";
    std::cout << "  CPU: " << cpuUsage << "%, Memory: " << memoryUsage << "%\n";
    std::cout << "  Convergence: " << convergenceScore << ", Stability: " << stabilityScore << "\n";
}

// ============================================================================
// PerformanceDelta Implementation
// ============================================================================

bool PerformanceDelta::IsImprovement() const {
    // Improvement if convergence increased and resource usage decreased
    bool convergenceImproved = convergenceAfter > convergenceBefore;
    bool resourceImproved = resourceUsageAfter < resourceUsageBefore;
    return convergenceImproved || resourceImproved;
}

std::string PerformanceDelta::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"convergenceBefore\":" << convergenceBefore << ",";
    json << "\"convergenceAfter\":" << convergenceAfter << ",";
    json << "\"latencyBeforeMs\":" << latencyBeforeMs << ",";
    json << "\"latencyAfterMs\":" << latencyAfterMs << ",";
    json << "\"throughputBefore\":" << throughputBefore << ",";
    json << "\"throughputAfter\":" << throughputAfter << ",";
    json << "\"resourceUsageBefore\":" << resourceUsageBefore << ",";
    json << "\"resourceUsageAfter\":" << resourceUsageAfter;
    json << "}";
    return json.str();
}

// ============================================================================
// DecisionContext Implementation
// ============================================================================

std::string DecisionContext::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"decisionId\":\"" << decisionId << "\",";
    json << "\"decisionType\":\"" << decisionType << "\",";
    json << "\"confidence\":" << confidence << ",";
    json << "\"reasoning\":\"" << reasoning << "\"";
    json << "}";
    return json.str();
}

// ============================================================================
// MutationRecord Implementation
// ============================================================================

std::string MutationRecord::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"mutationId\":" << mutationId << ",";
    json << "\"type\":\"" << MutationTypeToString(type) << "\",";
    json << "\"timestampMs\":" << timestampMs << ",";
    json << "\"committed\":" << (committed ? "true" : "false") << ",";
    json << "\"rolledBack\":" << (rolledBack ? "true" : "false") << ",";
    json << "\"before\":" << before.ToJson() << ",";
    json << "\"after\":" << after.ToJson() << ",";
    json << "\"delta\":" << delta.ToJson();
    json << "}";
    return json.str();
}

void MutationRecord::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  MUTATION RECORD                                                 ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ID:       " << std::left << std::setw(48) << mutationId << " ║\n";
    std::cout << "║  Type:     " << std::setw(48) << MutationTypeToString(type) << " ║\n";
    std::cout << "║  Status:   " << std::setw(48) << 
              (rolledBack ? "ROLLED_BACK" : (committed ? "COMMITTED" : "PENDING")) << " ║\n";
    std::cout << "║  Success:  " << std::setw(48) << (WasSuccessful() ? "YES" : "NO") << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Performance Impact                                              ║\n";
    std::cout << "║  Convergence: " << std::fixed << std::setprecision(3) << delta.convergenceBefore
              << " → " << delta.convergenceAfter << "\n";
    std::cout << "║  Latency:     " << delta.latencyBeforeMs << "ms → " << delta.latencyAfterMs << "ms\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

bool MutationRecord::WasSuccessful() const {
    return committed && !rolledBack && delta.IsImprovement();
}

MutationType MutationRecord::GetReversalType() const {
    switch (type) {
        case MutationType::ADD_PARALLEL_PATH: return MutationType::REMOVE_PARALLEL_PATH;
        case MutationType::REMOVE_PARALLEL_PATH: return MutationType::ADD_PARALLEL_PATH;
        case MutationType::MERGE_NODES: return MutationType::SPLIT_NODES;
        case MutationType::SPLIT_NODES: return MutationType::MERGE_NODES;
        case MutationType::ADJUST_WEIGHTS: return MutationType::ADJUST_WEIGHTS;  // Reversible by storing old weights
        case MutationType::CHANGE_PRIORITY: return MutationType::CHANGE_PRIORITY;  // Reversible by storing old priority
        case MutationType::INSERT_ISOLATION: return MutationType::REMOVE_ISOLATION;
        case MutationType::REMOVE_ISOLATION: return MutationType::INSERT_ISOLATION;
        case MutationType::REMOVE_REDUNDANCY: return MutationType::RESTORE_REDUNDANCY;
        case MutationType::RESTORE_REDUNDANCY: return MutationType::REMOVE_REDUNDANCY;
        default: return MutationType::UNKNOWN;
    }
}

// ============================================================================
// MutationJournalConfig Implementation
// ============================================================================

std::string MutationJournalConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxJournalSize\":" << maxJournalSize << ",";
    json << "\"maxSnapshotHistory\":" << maxSnapshotHistory << ",";
    json << "\"enableCompression\":" << (enableCompression ? "true" : "false") << ",";
    json << "\"enableBranching\":" << (enableBranching ? "true" : "false") << ",";
    json << "\"defaultPolicy\":\"" << RollbackPolicyToString(defaultPolicy) << "\",";
    json << "\"autoRollbackThresholdMs\":" << autoRollbackThresholdMs << ",";
    json << "\"convergenceDropThreshold\":" << convergenceDropThreshold;
    json << "}";
    return json.str();
}

// ============================================================================
// MutationJournal Implementation
// ============================================================================

MutationJournal::MutationJournal() = default;
MutationJournal::~MutationJournal() = default;

bool MutationJournal::Initialize(const MutationJournalConfig& config) {
    config_ = config;
    initialized_ = true;
    
    std::cout << "[MutationJournal] Initialized\n";
    std::cout << "  Max journal size: " << config.maxJournalSize << "\n";
    std::cout << "  Max snapshots: " << config.maxSnapshotHistory << "\n";
    std::cout << "  Default policy: " << RollbackPolicyToString(config.defaultPolicy) << "\n";
    
    return true;
}

uint64_t MutationJournal::BeginMutation(MutationType type,
                                          const SystemSnapshot& before,
                                          const DecisionContext& decision) {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    uint64_t mutationId = GenerateMutationId();
    
    MutationRecord record;
    record.mutationId = mutationId;
    record.type = type;
    record.before = before;
    record.decision = decision;
    record.timestampMs = GetCurrentTimeMs();
    record.committed = false;
    record.rolledBack = false;
    
    mutations_[mutationId] = record;
    
    // Store snapshot
    {
        std::lock_guard<std::mutex> snapLock(snapshotsMutex_);
        snapshots_[before.snapshotId] = before;
    }
    
    PruneIfNeeded();
    
    return mutationId;
}

bool MutationJournal::CompleteMutation(uint64_t mutationId,
                                        const SystemSnapshot& after,
                                        const PerformanceDelta& delta) {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    auto it = mutations_.find(mutationId);
    if (it == mutations_.end()) {
        return false;
    }
    
    it->second.after = after;
    it->second.delta = delta;
    
    // Store after snapshot
    {
        std::lock_guard<std::mutex> snapLock(snapshotsMutex_);
        snapshots_[after.snapshotId] = after;
    }
    
    return true;
}

bool MutationJournal::CommitMutation(uint64_t mutationId) {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    auto it = mutations_.find(mutationId);
    if (it == mutations_.end()) {
        return false;
    }
    
    it->second.committed = true;
    
    std::cout << "[MutationJournal] Committed mutation " << mutationId << "\n";
    
    return true;
}

std::optional<MutationRecord> MutationJournal::GetMutation(uint64_t mutationId) const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    auto it = mutations_.find(mutationId);
    if (it != mutations_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

std::vector<MutationRecord> MutationJournal::GetRecentMutations(int count) const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    std::vector<MutationRecord> recent;
    
    // Get mutations sorted by timestamp (descending)
    std::vector<MutationRecord> sorted;
    for (const auto& [id, record] : mutations_) {
        sorted.push_back(record);
    }
    
    std::sort(sorted.begin(), sorted.end(), 
              [](const MutationRecord& a, const MutationRecord& b) {
                  return a.timestampMs > b.timestampMs;
              });
    
    // Take most recent
    for (size_t i = 0; i < sorted.size() && i < static_cast<size_t>(count); ++i) {
        recent.push_back(sorted[i]);
    }
    
    return recent;
}

std::vector<MutationRecord> MutationJournal::GetMutationChain(uint64_t mutationId) const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    std::vector<MutationRecord> chain;
    
    // Build chain from this mutation backwards
    uint64_t currentId = mutationId;
    while (currentId != 0) {
        auto it = mutations_.find(currentId);
        if (it == mutations_.end()) break;
        
        chain.push_back(it->second);
        
        if (it->second.parentMutation.has_value()) {
            currentId = it->second.parentMutation.value();
        } else {
            break;
        }
    }
    
    // Reverse to get chronological order
    std::reverse(chain.begin(), chain.end());
    
    return chain;
}

std::vector<MutationRecord> MutationJournal::GetMutationsSince(uint64_t snapshotId) const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    std::vector<MutationRecord> result;
    
    // Find mutations with before.snapshotId >= snapshotId
    for (const auto& [id, record] : mutations_) {
        if (record.before.snapshotId >= snapshotId) {
            result.push_back(record);
        }
    }
    
    // Sort by timestamp
    std::sort(result.begin(), result.end(),
              [](const MutationRecord& a, const MutationRecord& b) {
                  return a.timestampMs < b.timestampMs;
              });
    
    return result;
}

bool MutationJournal::MarkRolledBack(uint64_t mutationId, uint64_t rollbackMutationId) {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    auto it = mutations_.find(mutationId);
    if (it == mutations_.end()) {
        return false;
    }
    
    it->second.rolledBack = true;
    it->second.rollbackMutationId = rollbackMutationId;
    
    std::cout << "[MutationJournal] Marked mutation " << mutationId << " as rolled back\n";
    
    return true;
}

std::optional<MutationRecord> MutationJournal::GetLastCommittedMutation() const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    MutationRecord* lastCommitted = nullptr;
    int64_t lastTime = 0;
    
    for (auto& [id, record] : mutations_) {
        if (record.committed && !record.rolledBack && record.timestampMs > lastTime) {
            lastCommitted = &record;
            lastTime = record.timestampMs;
        }
    }
    
    if (lastCommitted) {
        return *lastCommitted;
    }
    
    return std::nullopt;
}

std::optional<MutationRecord> MutationJournal::GetLastStableMutation() const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    MutationRecord* lastStable = nullptr;
    int64_t lastTime = 0;
    
    for (auto& [id, record] : mutations_) {
        if (record.WasSuccessful() && record.timestampMs > lastTime) {
            lastStable = &record;
            lastTime = record.timestampMs;
        }
    }
    
    if (lastStable) {
        return *lastStable;
    }
    
    return std::nullopt;
}

void MutationJournal::PruneOldMutations(size_t keepCount) {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    if (mutations_.size() <= keepCount) return;
    
    // Sort by timestamp
    std::vector<std::pair<uint64_t, MutationRecord>> sorted;
    for (const auto& pair : mutations_) {
        sorted.push_back(pair);
    }
    
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) {
                  return a.second.timestampMs < b.second.timestampMs;
              });
    
    // Remove oldest
    size_t toRemove = sorted.size() - keepCount;
    for (size_t i = 0; i < toRemove; ++i) {
        mutations_.erase(sorted[i].first);
    }
    
    std::cout << "[MutationJournal] Pruned " << toRemove << " old mutations\n";
}

void MutationJournal::Clear() {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    std::lock_guard<std::mutex> snapLock(snapshotsMutex_);
    
    mutations_.clear();
    snapshots_.clear();
    mutationCounter_ = 0;
    snapshotCounter_ = 0;
    
    std::cout << "[MutationJournal] Cleared all records\n";
}

MutationJournal::JournalStats MutationJournal::GetStats() const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    JournalStats stats;
    stats.totalMutations = mutations_.size();
    
    for (const auto& [id, record] : mutations_) {
        if (record.committed) stats.committedMutations++;
        if (record.rolledBack) stats.rolledBackMutations++;
        if (!record.committed && !record.rolledBack) stats.pendingMutations++;
        if (record.WasSuccessful()) stats.successfulMutations++;
    }
    
    if (stats.totalMutations > 0) {
        stats.successRate = static_cast<double>(stats.successfulMutations) / stats.totalMutations;
    }
    
    return stats;
}

void MutationJournal::PrintStatus() const {
    auto stats = GetStats();
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     MUTATION JOURNAL STATUS                                      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Mutations:     " << std::setw(38) << stats.totalMutations << " ║\n";
    std::cout << "║  Committed:          " << std::setw(38) << stats.committedMutations << " ║\n";
    std::cout << "║  Rolled Back:        " << std::setw(38) << stats.rolledBackMutations << " ║\n";
    std::cout << "║  Pending:            " << std::setw(38) << stats.pendingMutations << " ║\n";
    std::cout << "║  Successful:         " << std::setw(38) << stats.successfulMutations << " ║\n";
    std::cout << "║  Success Rate:       " << std::setw(37) << std::fixed << std::setprecision(1) 
              << (stats.successRate * 100.0) << "% ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

std::string MutationJournal::ExportToJson() const {
    std::lock_guard<std::mutex> lock(mutationsMutex_);
    
    std::ostringstream json;
    json << "{";
    json << "\"mutations\":[";
    
    bool first = true;
    for (const auto& [id, record] : mutations_) {
        if (!first) json << ",";
        json << record.ToJson();
        first = false;
    }
    
    json << "]";
    json << "}";
    
    return json.str();
}

bool MutationJournal::ReplayFromSnapshot(uint64_t snapshotId,
                                        std::vector<MutationRecord>& replayed) const {
    auto mutations = GetMutationsSince(snapshotId);
    
    // Filter to only committed, non-rolled-back mutations
    for (const auto& record : mutations) {
        if (record.committed && !record.rolledBack) {
            replayed.push_back(record);
        }
    }
    
    return !replayed.empty();
}

// ============================================================================
// Helpers
// ============================================================================

uint64_t MutationJournal::GenerateMutationId() {
    return ++mutationCounter_;
}

uint64_t MutationJournal::GenerateSnapshotId() {
    return ++snapshotCounter_;
}

int64_t MutationJournal::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void MutationJournal::PruneIfNeeded() {
    if (mutations_.size() > config_.maxJournalSize) {
        PruneOldMutations(config_.maxJournalSize * 0.8);  // Keep 80%
    }
}

// ============================================================================
// CLI Implementation
// ============================================================================

void MutationJournalCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     MUTATION JOURNAL - Phase C.4 Batch 3/5                        ║\n";
    std::cout << "║     Transaction Recording for Rollback                              ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void MutationJournalCLI::PrintUsage() {
    std::cout << "Usage: mutation-journal [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --stats              Show statistics\n";
    std::cout << "  --export             Export to JSON\n";
    std::cout << "  --help               Show this help\n\n";
}

void MutationJournalCLI::InteractiveMode(MutationJournal& journal) {
    std::cout << "\nInteractive Mutation Journal\n";
    std::cout << "Commands: record, commit, stats, list, export, clear, quit\n\n";
    
    std::string command;
    while (true) {
        std::cout << "journal> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        }
        
        if (command == "stats") {
            journal.PrintStatus();
        } else if (command == "list") {
            auto recent = journal.GetRecentMutations(10);
            std::cout << "\nRecent mutations:\n";
            for (const auto& record : recent) {
                record.Print();
            }
        } else if (command == "clear") {
            journal.Clear();
        } else if (command == "export") {
            std::cout << journal.ExportToJson() << "\n";
        } else if (!command.empty()) {
            std::cout << "Unknown command: " << command << "\n";
        }
    }
}

void MutationJournalCLI::SimulateMutation(MutationJournal& journal, MutationType type) {
    // Create sample snapshot
    SystemSnapshot before;
    before.snapshotId = 1;
    before.timestampMs = journal.GetStats().totalMutations;
    before.nodeCount = 10;
    before.edgeCount = 20;
    before.convergenceScore = 0.8;
    
    DecisionContext decision;
    decision.decisionId = "dec_" + std::to_string(journal.GetStats().totalMutations);
    decision.decisionType = "optimize";
    decision.confidence = 0.9;
    
    uint64_t mutationId = journal.BeginMutation(type, before, decision);
    
    // Simulate completion
    SystemSnapshot after = before;
    after.convergenceScore = 0.85;
    
    PerformanceDelta delta;
    delta.convergenceBefore = before.convergenceScore;
    delta.convergenceAfter = after.convergenceScore;
    delta.latencyBeforeMs = 100.0;
    delta.latencyAfterMs = 95.0;
    
    journal.CompleteMutation(mutationId, after, delta);
    journal.CommitMutation(mutationId);
    
    std::cout << "Simulated mutation " << mutationId << "\n";
}

int MutationJournalCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    MutationJournalConfig config;
    MutationJournal journal;
    if (!journal.Initialize(config)) {
        std::cerr << "Failed to initialize mutation journal\n";
        return 1;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(journal);
        return 0;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--stats") {
        journal.PrintStatus();
        return 0;
    }
    
    if (argc > 1 && std::string(argv[1]) == "--export") {
        std::cout << journal.ExportToJson() << "\n";
        return 0;
    }
    
    // Default: show status
    journal.PrintStatus();
    return 0;
}

} // namespace Autonomy
