/*===========================================================================
 * RepairMemory.cpp
 * RawrXD IDE - Accumulated Repair Knowledge Base Implementation
 *===========================================================================*/

#include "RepairMemory.h"
#include <blake3.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <fstream>

namespace RawrXD {

/*===========================================================================
 * REPAIR MEMORY IMPLEMENTATION
 *===========================================================================*/

class RepairMemory::Impl {
public:
    std::unordered_map<std::string, CrashRepairHistory> crashDatabase;
    std::unordered_map<uint64_t, RepairAttempt> attemptDatabase;
    std::unordered_map<uint64_t, uint64_t> attemptToCrash;  // attemptId -> crashSignature hash
    
    GlobalStats globalStats = {};
    std::string dbPath;
    bool initialized = false;
    uint64_t nextAttemptId = 1;
    
    // Callbacks
    std::function<void(const RepairAttempt&)> onRepairRecorded;
    std::function<void(const std::string&)> onPatternLearned;
};

RepairMemory::RepairMemory() 
    : m_impl(std::make_unique<Impl>()) {
}

RepairMemory::~RepairMemory() {
    Shutdown();
}

RepairMemory& RepairMemory::GetInstance() {
    static RepairMemory instance;
    return instance;
}

bool RepairMemory::Initialize(const std::string& databasePath) {
    m_impl->dbPath = databasePath;
    m_impl->initialized = true;
    
    // TODO: Load existing database from disk
    RecomputeStatistics();
    return true;
}

void RepairMemory::Shutdown() {
    if (m_impl->initialized) {
        // TODO: Save database to disk
        m_impl->initialized = false;
    }
}

bool RepairMemory::IsInitialized() const {
    return m_impl->initialized;
}

uint64_t RepairMemory::BeginRepairAttempt(const std::string& crashSignature) {
    uint64_t attemptId = m_impl->nextAttemptId++;
    
    RepairAttempt attempt;
    attempt.attemptId = attemptId;
    attempt.timestamp = GetTickCount64();  // Use Windows high-res timer
    attempt.crashSignature = crashSignature;
    attempt.outcome = RepairOutcome::Unknown;
    
    m_impl->attemptDatabase[attemptId] = attempt;
    
    // Initialize crash history if needed
    if (m_impl->crashDatabase.find(crashSignature) == m_impl->crashDatabase.end()) {
        CrashRepairHistory history;
        history.crashSignature = crashSignature;
        m_impl->crashDatabase[crashSignature] = history;
    }
    
    return attemptId;
}

void RepairMemory::UpdateRepairAttempt(uint64_t attemptId, const RepairAttempt& update) {
    auto it = m_impl->attemptDatabase.find(attemptId);
    if (it != m_impl->attemptDatabase.end()) {
        // Merge updates
        if (!update.crashSignature.empty()) it->second.crashSignature = update.crashSignature;
        if (!update.exceptionType.empty()) it->second.exceptionType = update.exceptionType;
        if (!update.sourceLocation.empty()) it->second.sourceLocation = update.sourceLocation;
        if (!update.surroundingContext.empty()) it->second.surroundingContext = update.surroundingContext;
        if (update.patchFingerprint.fingerprintId != 0) it->second.patchFingerprint = update.patchFingerprint;
        if (!update.patchDescription.empty()) it->second.patchDescription = update.patchDescription;
        if (update.modelConfidence > 0) it->second.modelConfidence = update.modelConfidence;
        if (update.validation.overallValid) it->second.validation = update.validation;
    }
}

void RepairMemory::CompleteRepairAttempt(uint64_t attemptId, RepairOutcome outcome) {
    auto it = m_impl->attemptDatabase.find(attemptId);
    if (it == m_impl->attemptDatabase.end()) return;
    
    RepairAttempt& attempt = it->second;
    attempt.outcome = outcome;
    attempt.timeToFix = GetTickCount64() - attempt.timestamp;
    
    // Update crash history
    auto crashIt = m_impl->crashDatabase.find(attempt.crashSignature);
    if (crashIt != m_impl->crashDatabase.end()) {
        crashIt->second.attempts.push_back(attempt);
        UpdateCrashHistoryStats(attempt.crashSignature);
    }
    
    // Update global stats
    UpdateGlobalStats();
    
    // Notify
    if (m_impl->onRepairRecorded) {
        m_impl->onRepairRecorded(attempt);
    }
}

void RepairMemory::AddUserFeedback(uint64_t attemptId, int rating, const std::string& notes) {
    auto it = m_impl->attemptDatabase.find(attemptId);
    if (it != m_impl->attemptDatabase.end()) {
        it->second.userRating = rating;
        it->second.userNotes = notes;
    }
}

CrashRepairHistory RepairMemory::GetCrashHistory(const std::string& crashSignature) {
    auto it = m_impl->crashDatabase.find(crashSignature);
    if (it != m_impl->crashDatabase.end()) {
        return it->second;
    }
    return CrashRepairHistory();
}

std::vector<RepairAttempt> RepairMemory::GetSuccessfulRepairsForCrash(const std::string& crashSignature) {
    std::vector<RepairAttempt> successful;
    auto history = GetCrashHistory(crashSignature);
    for (const auto& attempt : history.attempts) {
        if (attempt.outcome == RepairOutcome::Success || 
            attempt.outcome == RepairOutcome::PartialSuccess) {
            successful.push_back(attempt);
        }
    }
    return successful;
}

std::vector<RepairAttempt> RepairMemory::GetFailedRepairsForCrash(const std::string& crashSignature) {
    std::vector<RepairAttempt> failed;
    auto history = GetCrashHistory(crashSignature);
    for (const auto& attempt : history.attempts) {
        if (attempt.outcome == RepairOutcome::FailedValidation || 
            attempt.outcome == RepairOutcome::FailedRegression ||
            attempt.outcome == RepairOutcome::RevertedByUser) {
            failed.push_back(attempt);
        }
    }
    return failed;
}

std::vector<RepairAttempt> RepairMemory::FindSimilarRepairs(const std::string& context, float similarityThreshold) {
    std::vector<RepairAttempt> similar;
    
    for (const auto& pair : m_impl->attemptDatabase) {
        // Simple context similarity check
        float similarity = 0.0f;
        if (pair.second.surroundingContext == context) {
            similarity = 1.0f;
        } else {
            // TODO: Implement proper similarity calculation
            similarity = 0.0f;
        }
        
        if (similarity >= similarityThreshold) {
            similar.push_back(pair.second);
        }
    }
    
    return similar;
}

std::vector<RepairAttempt> RepairMemory::GetRepairsForPattern(const std::string& pattern) {
    std::vector<RepairAttempt> matches;
    
    for (const auto& pair : m_impl->attemptDatabase) {
        if (pair.second.patchDescription.find(pattern) != std::string::npos ||
            pair.second.crashSignature.find(pattern) != std::string::npos) {
            matches.push_back(pair.second);
        }
    }
    
    return matches;
}

std::string RepairMemory::SuggestFixStrategy(const std::string& crashSignature) {
    auto history = GetCrashHistory(crashSignature);
    
    if (history.successfulRepairs > 0) {
        // Return strategy from best fix
        return "Apply similar fix to: " + history.bestFix.patchDescription;
    }
    
    if (history.failedRepairs > 0) {
        return "Previous attempts failed. Consider alternative approach.";
    }
    
    return "No prior experience with this crash type. Proceed with standard validation.";
}

float RepairMemory::PredictSuccessProbability(const PatchFingerprint& patch, const std::string& crashSignature) {
    auto history = GetCrashHistory(crashSignature);
    
    if (history.totalAttempts == 0) {
        return 0.5f;  // Unknown - 50/50
    }
    
    // Base rate from crash history
    float baseRate = history.successRate;
    
    // Check if this exact patch was tried before
    for (const auto& attempt : history.attempts) {
        if (attempt.patchFingerprint.fingerprintId == patch.fingerprintId) {
            if (attempt.outcome == RepairOutcome::Success) {
                return 0.95f;  // Exact match succeeded
            } else if (attempt.outcome == RepairOutcome::FailedValidation ||
                       attempt.outcome == RepairOutcome::FailedRegression) {
                return 0.05f;  // Exact match failed
            }
        }
    }
    
    // Check similar patches
    for (const auto& attempt : history.attempts) {
        float similarity = patch.CalculateSimilarity(attempt.patchFingerprint);
        if (similarity > 0.9f) {
            if (attempt.outcome == RepairOutcome::Success) {
                baseRate = std::max(baseRate, 0.85f);
            } else if (attempt.outcome == RepairOutcome::FailedValidation) {
                baseRate = std::min(baseRate, 0.3f);
            }
        }
    }
    
    return baseRate;
}

std::vector<std::string> RepairMemory::GetRecommendedAvoidances(const std::string& crashSignature) {
    std::vector<std::string> avoidances;
    auto failed = GetFailedRepairsForCrash(crashSignature);
    
    for (const auto& attempt : failed) {
        if (!attempt.patchDescription.empty()) {
            avoidances.push_back("Avoid: " + attempt.patchDescription);
        }
        if (!attempt.failureReason.empty()) {
            avoidances.push_back("Failed because: " + attempt.failureReason);
        }
    }
    
    return avoidances;
}

RepairMemory::GlobalStats RepairMemory::GetGlobalStats() const {
    return m_impl->globalStats;
}

void RepairMemory::ExportToJson(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "{\n";
    file << "  \"repairs\": [\n";
    
    bool first = true;
    for (const auto& pair : m_impl->attemptDatabase) {
        if (!first) file << ",\n";
        first = false;
        
        const auto& attempt = pair.second;
        file << "    {\n";
        file << "      \"attemptId\": " << attempt.attemptId << ",\n";
        file << "      \"crashSignature\": \"" << attempt.crashSignature << "\",\n";
        file << "      \"outcome\": " << static_cast<int>(attempt.outcome) << ",\n";
        file << "      \"timeToFix\": " << attempt.timeToFix << "\n";
        file << "    }";
    }
    
    file << "\n  ],\n";
    file << "  \"stats\": {\n";
    file << "    \"totalRepairs\": " << m_impl->globalStats.totalRepairs << ",\n";
    file << "    \"successfulRepairs\": " << m_impl->globalStats.successfulRepairs << ",\n";
    file << "    \"successRate\": " << m_impl->globalStats.overallSuccessRate << "\n";
    file << "  }\n";
    file << "}\n";
}

void RepairMemory::ImportFromJson(const std::string& path) {
    // TODO: Implement JSON import
    (void)path;
}

void RepairMemory::MergeDatabase(const std::string& otherDatabasePath) {
    // TODO: Implement database merge
    (void)otherDatabasePath;
}

void RepairMemory::CompactDatabase() {
    // Remove obsolete records
    // TODO: Implement compaction
}

void RepairMemory::ArchiveOldRepairs(uint64_t olderThanDays) {
    // TODO: Implement archiving
    (void)olderThanDays;
}

void RepairMemory::RecomputeStatistics() {
    m_impl->globalStats = {};
    
    for (const auto& pair : m_impl->attemptDatabase) {
        const auto& attempt = pair.second;
        m_impl->globalStats.totalRepairs++;
        
        if (attempt.outcome == RepairOutcome::Success || 
            attempt.outcome == RepairOutcome::PartialSuccess) {
            m_impl->globalStats.successfulRepairs++;
        } else if (attempt.outcome == RepairOutcome::FailedValidation ||
                   attempt.outcome == RepairOutcome::FailedRegression) {
            m_impl->globalStats.failedRepairs++;
        } else if (attempt.outcome == RepairOutcome::RevertedByUser) {
            m_impl->globalStats.revertedRepairs++;
        }
        
        // Track by exception type
        if (!attempt.exceptionType.empty()) {
            m_impl->globalStats.repairsByExceptionType[attempt.exceptionType]++;
        }
        
        // Track by patch type
        if (!attempt.patchFingerprint.patchType.empty()) {
            m_impl->globalStats.repairsByPatchType[attempt.patchFingerprint.patchType]++;
        }
    }
    
    if (m_impl->globalStats.totalRepairs > 0) {
        m_impl->globalStats.overallSuccessRate = 
            (float)m_impl->globalStats.successfulRepairs / (float)m_impl->globalStats.totalRepairs;
    }
}

void RepairMemory::UpdateCrashHistoryStats(const std::string& crashSignature) {
    auto it = m_impl->crashDatabase.find(crashSignature);
    if (it == m_impl->crashDatabase.end()) return;
    
    CrashRepairHistory& history = it->second;
    history.totalAttempts = (uint32_t)history.attempts.size();
    history.successfulRepairs = 0;
    history.failedRepairs = 0;
    
    RepairAttempt* bestFix = nullptr;
    float bestConfidence = 0.0f;
    
    for (auto& attempt : history.attempts) {
        if (attempt.outcome == RepairOutcome::Success ||
            attempt.outcome == RepairOutcome::PartialSuccess) {
            history.successfulRepairs++;
            if (attempt.modelConfidence > bestConfidence) {
                bestConfidence = attempt.modelConfidence;
                bestFix = &attempt;
            }
        } else if (attempt.outcome == RepairOutcome::FailedValidation ||
                   attempt.outcome == RepairOutcome::FailedRegression) {
            history.failedRepairs++;
        }
    }
    
    if (history.totalAttempts > 0) {
        history.successRate = (float)history.successfulRepairs / (float)history.totalAttempts;
    }
    
    if (bestFix) {
        history.bestFix = *bestFix;
        history.bestFixConfidence = bestConfidence;
    }
}

void RepairMemory::UpdateGlobalStats() {
    RecomputeStatistics();
}

std::string RepairMemory::ComputeContextHash(const std::string& context) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, context.data(), context.size());
    
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

/*===========================================================================
 * FIX PROPOSAL RANKER
 *===========================================================================*/

FixProposalRanker::FixProposalRanker(RepairMemory* memory)
    : m_memory(memory) {
}

std::vector<RankedFixProposal> FixProposalRanker::RankProposals(
    const std::vector<PatchFingerprint>& proposals,
    const std::string& crashSignature,
    const std::string& context) {
    
    std::vector<RankedFixProposal> ranked;
    
    for (const auto& patch : proposals) {
        RankedFixProposal rankedPatch;
        rankedPatch.patch = patch;
        rankedPatch.baseConfidence = 0.7f;  // Default model confidence
        rankedPatch.historicalSuccessRate = CalculateHistoricalScore(patch, crashSignature);
        rankedPatch.contextualSimilarity = CalculateContextualScore(patch, context);
        
        // Combined score
        rankedPatch.finalScore = 
            rankedPatch.baseConfidence * (1.0f - m_historicalWeight - m_contextualWeight) +
            rankedPatch.historicalSuccessRate * m_historicalWeight +
            rankedPatch.contextualSimilarity * m_contextualWeight;
        
        // Generate explanation
        std::stringstream explanation;
        explanation << "Base confidence: " << (int)(rankedPatch.baseConfidence * 100) << "%\n";
        explanation << "Historical success: " << (int)(rankedPatch.historicalSuccessRate * 100) << "%\n";
        explanation << "Context match: " << (int)(rankedPatch.contextualSimilarity * 100) << "%\n";
        explanation << "Final score: " << (int)(rankedPatch.finalScore * 100) << "%";
        rankedPatch.rankingExplanation = explanation.str();
        
        ranked.push_back(rankedPatch);
    }
    
    // Sort by final score
    std::sort(ranked.begin(), ranked.end(), [](const RankedFixProposal& a, const RankedFixProposal& b) {
        return a.finalScore > b.finalScore;
    });
    
    return ranked;
}

float FixProposalRanker::CalculateHistoricalScore(const PatchFingerprint& patch, const std::string& crashSignature) {
    if (!m_memory) return 0.5f;
    
    return m_memory->PredictSuccessProbability(patch, crashSignature);
}

float FixProposalRanker::CalculateContextualScore(const PatchFingerprint& patch, const std::string& context) {
    // TODO: Implement proper context similarity
    (void)patch;
    (void)context;
    return 0.5f;
}

/*===========================================================================
 * REPAIR LEARNING LOOP
 *===========================================================================*/

RepairLearningLoop::RepairLearningLoop(RepairMemory* memory)
    : m_memory(memory) {
}

void RepairLearningLoop::AnalyzeRepairPatterns() {
    // Analyze successful vs failed repairs to identify patterns
    // TODO: Implement pattern analysis
}

void RepairLearningLoop::ExtractSuccessfulPatterns() {
    // Extract common patterns from successful repairs
    // TODO: Implement pattern extraction
}

void RepairLearningLoop::UpdateSuccessPredictors() {
    // Update ML models for success prediction
    // TODO: Implement predictor updates
}

void RepairLearningLoop::GenerateFixTemplates() {
    // Generate reusable fix templates from successful repairs
    // TODO: Implement template generation
}

std::vector<RepairLearningLoop::FixTemplate> RepairLearningLoop::GetFixTemplatesForCrash(const std::string& crashType) {
    std::vector<FixTemplate> templates;
    // TODO: Return templates matching crash type
    (void)crashType;
    return templates;
}

void RepairLearningLoop::RegisterTemplateApplication(const std::string& templateId, bool success) {
    // TODO: Track template success rate
    (void)templateId;
    (void)success;
}

void RepairLearningLoop::RunDailyLearningPass() {
    AnalyzeRepairPatterns();
    ExtractSuccessfulPatterns();
    UpdateSuccessPredictors();
    GenerateFixTemplates();
}

void RepairLearningLoop::IdentifyFalsePositives() {
    // Find repairs that passed validation but failed in production
    // TODO: Implement false positive detection
}

void RepairLearningLoop::IdentifyMissedOpportunities() {
    // Find crashes that could have been auto-fixed but weren't
    // TODO: Implement missed opportunity detection
}

void RepairLearningLoop::SuggestModelImprovements() {
    // Generate suggestions for improving the LLM based on repair history
    // TODO: Implement model improvement suggestions
}

/*===========================================================================
 * REPAIR MEMORY UI
 *===========================================================================*/

namespace RepairMemoryUI {

std::string FormatRepairHistory(const CrashRepairHistory& history) {
    std::stringstream ss;
    ss << "Crash: " << history.crashSignature << "\n";
    ss << "Total attempts: " << history.totalAttempts << "\n";
    ss << "Success rate: " << (int)(history.successRate * 100) << "%\n";
    ss << "Best fix confidence: " << (int)(history.bestFixConfidence * 100) << "%\n";
    return ss.str();
}

std::string FormatRepairAttempt(const RepairAttempt& attempt) {
    std::stringstream ss;
    ss << "Attempt #" << attempt.attemptId << "\n";
    ss << "  Location: " << attempt.sourceLocation << "\n";
    ss << "  Patch: " << attempt.patchDescription << "\n";
    ss << "  Model confidence: " << (int)(attempt.modelConfidence * 100) << "%\n";
    ss << "  Outcome: " << static_cast<int>(attempt.outcome) << "\n";
    ss << "  Time to fix: " << attempt.timeToFix << "ms\n";
    return ss.str();
}

std::string GenerateSuccessRateChart(const std::vector<RepairAttempt>& attempts) {
    // Generate ASCII chart
    std::stringstream ss;
    int success = 0, failed = 0, unknown = 0;
    
    for (const auto& a : attempts) {
        switch (a.outcome) {
            case RepairOutcome::Success:
            case RepairOutcome::PartialSuccess:
                success++;
                break;
            case RepairOutcome::FailedValidation:
            case RepairOutcome::FailedRegression:
            case RepairOutcome::RevertedByUser:
                failed++;
                break;
            default:
                unknown++;
                break;
        }
    }
    
    int total = success + failed + unknown;
    if (total == 0) return "No data";
    
    int successBar = (success * 50) / total;
    int failedBar = (failed * 50) / total;
    int unknownBar = 50 - successBar - failedBar;
    
    ss << "Success:  [" << std::string(successBar, '=') << "] " << success << "\n";
    ss << "Failed:   [" << std::string(failedBar, '-') << "] " << failed << "\n";
    ss << "Unknown:  [" << std::string(unknownBar, '?') << "] " << unknown << "\n";
    
    return ss.str();
}

std::string GenerateHtmlReport(const RepairMemory::GlobalStats& stats) {
    std::stringstream html;
    html <> "<!DOCTYPE html>\n";
    html << "<html>\n";
    html << "<head><title>Repair Memory Report</title></head>\n";
    html << "<body>\n";
    html << "<h1>Repair Memory Statistics</h1>\n";
    html << "<p>Total Repairs: " << stats.totalRepairs << "</p>\n";
    html << "<p>Success Rate: " << (int)(stats.overallSuccessRate * 100) << "%</p>\n";
    html << "</body>\n";
    html << "</html>\n";
    return html.str();
}

std::string GenerateCrashAnalysisPage(const std::string& crashSignature) {
    // TODO: Generate detailed crash analysis
    (void)crashSignature;
    return "<html><body>Crash analysis</body></html>";
}

} // namespace RepairMemoryUI

} // namespace RawrXD
