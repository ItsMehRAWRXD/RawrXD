// ============================================================================
// TokenEstimatorSwarm.hpp - Token Accounting & Slack Analysis
// ============================================================================
// Tracks token estimates vs actuals and "unreverses" spent tokens to identify
// where slack (divergence between estimate and actual) is occurring.
// ============================================================================

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <chrono>
#include <unordered_map>
#include <memory>

namespace RawrXD {
namespace Executive {

// ============================================================================
// Token Breakdown Categories
// ============================================================================
enum class TokenCategory {
    PROMPT_TOKENS = 0,      // Input prompt tokens
    COMPLETION_TOKENS,      // Generated output tokens
    THINKING_TOKENS,        // Chain-of-thought / reasoning tokens
    TOOL_CALL_TOKENS,       // Tool invocation tokens
    TOOL_RESULT_TOKENS,     // Tool result processing tokens
    RETRY_TOKENS,           // Tokens from retries/repairs
    OVERHEAD_TOKENS,        // System overhead (formatting, etc.)
    SLACK_TOKENS,           // Unexplained divergence
    COUNT
};

const char* TokenCategoryToString(TokenCategory cat);

// ============================================================================
// Token Estimation Record
// ============================================================================
struct TokenEstimate {
    uint64_t goalId;
    std::chrono::steady_clock::time_point timestamp;
    
    // Per-category estimates
    float estimatedByCategory[static_cast<int>(TokenCategory::COUNT)];
    float actualByCategory[static_cast<int>(TokenCategory::COUNT)];
    
    // Totals
    float totalEstimated;
    float totalActual;
    float slack;  // actual - estimated (positive = over budget)
    
    // Context
    const char* agentName;
    const char* operationType;
    uint32_t retryCount;
    
    TokenEstimate() : goalId(0), totalEstimated(0), totalActual(0), slack(0), 
                      agentName(nullptr), operationType(nullptr), retryCount(0) {
        for (int i = 0; i < static_cast<int>(TokenCategory::COUNT); i++) {
            estimatedByCategory[i] = 0;
            actualByCategory[i] = 0;
        }
    }
};

// ============================================================================
// Slack Analysis Result
// ============================================================================
struct SlackAnalysis {
    float totalSlack;
    float largestCategorySlack;
    TokenCategory largestSlackCategory;
    
    // Per-category breakdown
    struct CategorySlack {
        TokenCategory category;
        float estimated;
        float actual;
        float slack;
        float slackPercentage;  // (actual - estimated) / estimated * 100
    };
    std::vector<CategorySlack> categorySlack;
    
    // Recommendations
    std::vector<const char*> recommendations;
};

// ============================================================================
// Token Estimator Agent (8 agents in the swarm)
// ============================================================================
enum class EstimatorAgent {
    PROMPT_ANALYZER = 0,      // Analyzes prompt token estimation accuracy
    COMPLETION_PREDICTOR,     // Predicts completion token requirements
    THINKING_MONITOR,         // Monitors reasoning token overhead
    TOOL_COST_TRACKER,        // Tracks tool call/result token costs
    RETRY_ACCOUNTANT,         // Accounts for retry token costs
    OVERHEAD_DETECTOR,        // Detects system overhead tokens
    SLACK_INVESTIGATOR,       // Investigates unexplained token divergence
    PATTERN_LEARNER           // Learns patterns to improve estimates
};

// ============================================================================
// Token Estimator Swarm - Singleton
// ============================================================================
class TokenEstimatorSwarm {
public:
    static TokenEstimatorSwarm& getInstance() {
        static TokenEstimatorSwarm instance;
        return instance;
    }
    
    // Record an estimate before execution
    void recordEstimate(uint64_t goalId, const TokenEstimate& estimate);
    
    // Record actuals after execution (the "unreverse" operation)
    void recordActuals(uint64_t goalId, const TokenEstimate& actuals);
    
    // Analyze slack for a completed goal
    SlackAnalysis analyzeSlack(uint64_t goalId);
    
    // Get historical patterns
    std::vector<TokenEstimate> getHistory(uint64_t goalId = 0, size_t maxRecords = 100);
    
    // Run all 8 estimator agents to analyze patterns
    void runEstimationSwarm(uint64_t goalId);
    
    // Get improved estimate based on historical patterns
    TokenEstimate getImprovedEstimate(const char* operationType, 
                                       const char* agentName,
                                       float baseEstimate);
    
    // Clear history
    void clearHistory();
    
    // Export data for analysis
    void exportToCSV(const char* filename);
    
private:
    TokenEstimatorSwarm() = default;
    ~TokenEstimatorSwarm() = default;
    TokenEstimatorSwarm(const TokenEstimatorSwarm&) = delete;
    TokenEstimatorSwarm& operator=(const TokenEstimatorSwarm&) = delete;
    
    // The 8 estimation agents
    void runPromptAnalyzer(const TokenEstimate& record);
    void runCompletionPredictor(const TokenEstimate& record);
    void runThinkingMonitor(const TokenEstimate& record);
    void runToolCostTracker(const TokenEstimate& record);
    void runRetryAccountant(const TokenEstimate& record);
    void runOverheadDetector(const TokenEstimate& record);
    void runSlackInvestigator(uint64_t goalId);
    void runPatternLearner();
    
    // Storage
    std::unordered_map<uint64_t, std::vector<TokenEstimate>> goalHistory_;
    std::vector<TokenEstimate> recentRecords_;
    static constexpr size_t MAX_RECENT_RECORDS = 1000;
    
    // Pattern learning
    std::unordered_map<std::string, float> operationBias_;  // operation -> avg slack
    std::unordered_map<std::string, float> agentBias_;     // agent -> avg slack
};

// ============================================================================
// C-API for integration
// ============================================================================
extern "C" {
    // Record estimate/actuals
    void RecordTokenEstimate(uint64_t goalId, float estimatedTotal);
    void RecordTokenActuals(uint64_t goalId, float actualTotal, 
                            const char* breakdown);
    
    // Analyze slack
    void AnalyzeTokenSlack(uint64_t goalId, char* outputBuffer, size_t bufferSize);
    
    // Get improved estimate
    float GetImprovedTokenEstimate(const char* operation, const char* agent, 
                                    float baseEstimate);
}

} // namespace Executive
} // namespace RawrXD
