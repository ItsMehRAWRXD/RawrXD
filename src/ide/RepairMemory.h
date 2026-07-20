/*===========================================================================
 * RepairMemory.h
 * RawrXD IDE - Accumulated Repair Knowledge Base
 * 
 * Prevents repeated failures and enables learning from past repairs
 *===========================================================================*/

#ifndef REPAIR_MEMORY_H
#define REPAIR_MEMORY_H

#include "PatchFingerprint.h"
#include "ValidationEngine.h"
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {

/*===========================================================================
 * REPAIR RECORD
 *===========================================================================*/

enum class RepairOutcome {
    Unknown,
    Success,            // Fixed the crash, no regressions
    PartialSuccess,     // Fixed crash but introduced minor issues
    FailedValidation,   // Failed validation (build/test/replay)
    FailedRegression,   // Passed validation but caused regression later
    RevertedByUser,     // User manually reverted
    Superseded          // Better fix found later
};

struct RepairAttempt {
    uint64_t attemptId;
    uint64_t timestamp;
    uint64_t sessionId;
    
    // Context
    std::string crashSignature;         // Hash of crash
    std::string exceptionType;        // "AccessViolation", "NullPointer", etc.
    std::string sourceLocation;       // File:Line where crash occurred
    std::string surroundingContext;     // Code context around crash
    
    // The fix
    PatchFingerprint patchFingerprint;
    std::string patchDescription;
    float modelConfidence;            // What model reported
    
    // Validation results
    ValidationResult validation;
    
    // Outcome
    RepairOutcome outcome;
    std::string failureReason;          // If failed, why
    uint64_t timeToFix;                 // Milliseconds from crash to commit
    
    // User feedback
    int userRating;                     // -1 to +1 (thumbs down/up)
    std::string userNotes;
    
    // Learning data
    std::vector<std::string> alternativeFixesConsidered;
    std::string chosenFixRationale;
    
    RepairAttempt()
        : attemptId(0)
        , timestamp(0)
        , sessionId(0)
        , modelConfidence(0.0f)
        , outcome(RepairOutcome::Unknown)
        , timeToFix(0)
        , userRating(0) {}
};

/*===========================================================================
 * CRASH REPAIR HISTORY
 *===========================================================================*/

struct CrashRepairHistory {
    std::string crashSignature;
    std::string crashDescription;
    
    std::vector<RepairAttempt> attempts;
    
    // Aggregated stats
    uint32_t totalAttempts;
    uint32_t successfulRepairs;
    uint32_t failedRepairs;
    float successRate;
    
    // Best known fix
    RepairAttempt bestFix;
    float bestFixConfidence;
    
    // Pattern learning
    std::vector<std::string> commonFailurePatterns;
    std::vector<std::string> successfulFixPatterns;
    
    CrashRepairHistory()
        : totalAttempts(0)
        , successfulRepairs(0)
        , failedRepairs(0)
        , successRate(0.0f)
        , bestFixConfidence(0.0f) {}
};

/*===========================================================================
 * REPAIR MEMORY
 *===========================================================================*/

class RepairMemory {
public:
    static RepairMemory& GetInstance();
    
    // Lifecycle
    bool Initialize(const std::string& databasePath);
    void Shutdown();
    bool IsInitialized() const;
    
    // Recording repairs
    uint64_t BeginRepairAttempt(const std::string& crashSignature);
    void UpdateRepairAttempt(uint64_t attemptId, const RepairAttempt& update);
    void CompleteRepairAttempt(uint64_t attemptId, RepairOutcome outcome);
    void AddUserFeedback(uint64_t attemptId, int rating, const std::string& notes);
    
    // Querying
    CrashRepairHistory GetCrashHistory(const std::string& crashSignature);
    std::vector<RepairAttempt> GetSuccessfulRepairsForCrash(const std::string& crashSignature);
    std::vector<RepairAttempt> GetFailedRepairsForCrash(const std::string& crashSignature);
    
    // Pattern matching
    std::vector<RepairAttempt> FindSimilarRepairs(const std::string& context, float similarityThreshold = 0.80f);
    std::vector<RepairAttempt> GetRepairsForPattern(const std::string& pattern);
    
    // Learning
    std::string SuggestFixStrategy(const std::string& crashSignature);
    float PredictSuccessProbability(const PatchFingerprint& patch, const std::string& crashSignature);
    std::vector<std::string> GetRecommendedAvoidances(const std::string& crashSignature);
    
    // Statistics
    struct GlobalStats {
        uint64_t totalRepairs;
        uint64_t successfulRepairs;
        uint64_t failedRepairs;
        uint64_t revertedRepairs;
        
        float overallSuccessRate;
        float averageTimeToFix;
        float averageUserRating;
        
        std::map<std::string, uint32_t> repairsByExceptionType;
        std::map<std::string, uint32_t> repairsByPatchType;
    };
    GlobalStats GetGlobalStats() const;
    
    // Export/Import
    void ExportToJson(const std::string& path);
    void ImportFromJson(const std::string& path);
    void MergeDatabase(const std::string& otherDatabasePath);
    
    // Maintenance
    void CompactDatabase();              // Remove old/obsolete records
    void ArchiveOldRepairs(uint64_t olderThanDays);
    void RecomputeStatistics();

private:
    RepairMemory();
    ~RepairMemory();
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Internal helpers
    void UpdateCrashHistoryStats(const std::string& crashSignature);
    void UpdateGlobalStats();
    std::string ComputeContextHash(const std::string& context);
};

/*===========================================================================
 * FIX PROPOSAL RANKING
 *===========================================================================*/

struct RankedFixProposal {
    PatchFingerprint patch;
    float baseConfidence;               // From model
    float historicalSuccessRate;        // From repair memory
    float contextualSimilarity;         // Similarity to past successes
    float finalScore;                   // Combined ranking score
    
    std::string rankingExplanation;       // Why this score
    std::vector<std::string> similarSuccessfulFixes;
};

class FixProposalRanker {
public:
    FixProposalRanker(RepairMemory* memory);
    
    // Ranking
    std::vector<RankedFixProposal> RankProposals(
        const std::vector<PatchFingerprint>& proposals,
        const std::string& crashSignature,
        const std::string& context
    );
    
    // Scoring
    float CalculateHistoricalScore(const PatchFingerprint& patch, const std::string& crashSignature);
    float CalculateContextualScore(const PatchFingerprint& patch, const std::string& context);
    
    // Configuration
    void SetHistoricalWeight(float weight) { m_historicalWeight = weight; }
    void SetContextualWeight(float weight) { m_contextualWeight = weight; }
    void SetMinimumSuccessRate(float rate) { m_minimumSuccessRate = rate; }

private:
    RepairMemory* m_memory;
    float m_historicalWeight = 0.3f;
    float m_contextualWeight = 0.2f;
    float m_minimumSuccessRate = 0.5f;
};

/*===========================================================================
 * REPAIR LEARNING LOOP
 *===========================================================================*/

class RepairLearningLoop {
public:
    RepairLearningLoop(RepairMemory* memory);
    
    // Learning cycle
    void AnalyzeRepairPatterns();
    void ExtractSuccessfulPatterns();
    void UpdateSuccessPredictors();
    void GenerateFixTemplates();
    
    // Template generation
    struct FixTemplate {
        std::string templateId;
        std::string patternDescription;
        std::string codeTemplate;
        std::vector<std::string> applicableCrashTypes;
        float historicalSuccessRate;
        uint32_t timesApplied;
    };
    
    std::vector<FixTemplate> GetFixTemplatesForCrash(const std::string& crashType);
    void RegisterTemplateApplication(const std::string& templateId, bool success);
    
    // Continuous improvement
    void RunDailyLearningPass();
    void IdentifyFalsePositives();
    void IdentifyMissedOpportunities();
    void SuggestModelImprovements();

private:
    RepairMemory* m_memory;
    std::vector<FixTemplate> m_templates;
};

/*===========================================================================
 * REPAIR MEMORY UI
 *===========================================================================*/

namespace RepairMemoryUI {
    // Visualization
    std::string FormatRepairHistory(const CrashRepairHistory& history);
    std::string FormatRepairAttempt(const RepairAttempt& attempt);
    std::string GenerateSuccessRateChart(const std::vector<RepairAttempt>& attempts);
    
    // HTML report
    std::string GenerateHtmlReport(const RepairMemory::GlobalStats& stats);
    std::string GenerateCrashAnalysisPage(const std::string& crashSignature);
}

} // namespace RawrXD

#endif // REPAIR_MEMORY_H
