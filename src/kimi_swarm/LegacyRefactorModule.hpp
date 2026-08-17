// =============================================================================
// LegacyRefactorModule.hpp — Kimi K2.6 Legacy Refactor Module
// =============================================================================
// Analyzes outdated codebases and automatically decomposes the old project
// to propose a refactoring plan to a modern stack.
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#pragma once

#include "KimiSwarmRoles.hpp"
#include "DeepContextManager.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace KimiSwarm {

// =============================================================================
// LEGACY DETECTION
// =============================================================================

enum class LegacyEra : uint8_t {
    Modern    = 0,   // Current best practices
    Recent    = 1,   // 3-5 years old
    Dated     = 2,   // 5-10 years old
    Legacy    = 3,   // 10-15 years old
    Ancient   = 4    // 15+ years old
};

struct LegacyIndicator {
    std::string indicator;       // What was detected
    std::string filePath;        // Where found
    LegacyEra   era;             // Estimated era
    std::string modernEquivalent;// What to replace with
    uint32_t    severity;        // 0=info, 1=warning, 2=critical
};

struct LegacyAnalysis {
    LegacyEra overallEra;
    std::string detectedStack;    // "jQuery + PHP + MySQL"
    std::string targetStack;      // "React + Node.js + PostgreSQL"
    std::vector<LegacyIndicator> indicators;
    uint32_t    totalFiles;
    uint32_t    legacyFiles;
    uint32_t    modernFiles;
    double      technicalDebtScore;  // 0.0-10.0
    double      refactorEffortHours; // Estimated
    std::vector<std::string> deprecatedDependencies;
    std::vector<std::string> securityConcerns;
    std::vector<std::string> performanceBottlenecks;
};

// =============================================================================
// REFACTORING PLAN
// =============================================================================

struct RefactorStep {
    uint32_t    stepId;
    std::string phase;           // "Analysis", "Migration", "Testing", "Deployment"
    std::string description;
    std::string targetFiles;
    Squad       assignedSquad;
    KimiRole    assignedRole;
    uint32_t    estimatedHours;
    uint32_t    priority;        // 0 = highest
    std::vector<std::string> dependencies;  // Step IDs that must complete first
    std::string riskLevel;       // "low", "medium", "high"
    std::string rollbackPlan;
};

struct RefactorPlan {
    std::string projectName;
    std::string currentStack;
    std::string targetStack;
    std::vector<RefactorStep> steps;
    uint32_t    totalEstimatedHours;
    uint32_t    agentCount;
    std::vector<std::string> migrationRisks;
    std::vector<std::string> quickWins;       // Low-effort high-impact changes
    std::string executiveSummary;
    std::string detailedReport;
};

// =============================================================================
// LEGACY REFACTOR MODULE
// =============================================================================

class LegacyRefactorModule {
public:
    static LegacyRefactorModule& instance();

    // Analyze a codebase for legacy patterns
    LegacyAnalysis analyzeCodebase(DeepContextManager& contextManager);

    // Generate a refactoring plan from analysis
    RefactorPlan generateRefactorPlan(const LegacyAnalysis& analysis,
                                       const std::string& targetStack = "");

    // One-shot: analyze + plan
    RefactorPlan analyzeAndPlan(DeepContextManager& contextManager,
                                 const std::string& targetStack = "");

    // Detect the current technology stack
    std::string detectCurrentStack(DeepContextManager& contextManager);

    // Recommend a modern target stack
    std::string recommendTargetStack(const std::string& currentStack);

    // Get legacy indicators for a specific file
    std::vector<LegacyIndicator> analyzeFile(const std::string& filePath,
                                              const std::string& content,
                                              const std::string& language);

    // Calculate technical debt score
    double calculateTechnicalDebt(const LegacyAnalysis& analysis) const;

    // Estimate refactoring effort
    uint32_t estimateEffortHours(const LegacyAnalysis& analysis) const;

    // Export plan as markdown
    std::string exportPlanAsMarkdown(const RefactorPlan& plan) const;

    // Export plan as JSON
    std::string exportPlanAsJson(const RefactorPlan& plan) const;

private:
    LegacyRefactorModule();

    mutable std::mutex mutex_;

    // Legacy pattern detection rules
    struct LegacyPattern {
        std::string pattern;         // Regex or string to match
        std::string description;
        LegacyEra   era;
        std::string modernEquivalent;
        uint32_t    severity;
        std::string language;        // Which language this applies to
    };

    std::vector<LegacyPattern> patterns_;

    void initializePatterns();
    LegacyEra determineOverallEra(const std::vector<LegacyIndicator>& indicators) const;
    std::string eraToString(LegacyEra era) const;
};

} // namespace KimiSwarm