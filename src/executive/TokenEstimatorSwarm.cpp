// ============================================================================
// TokenEstimatorSwarm.cpp - Token Accounting & Slack Analysis Implementation
// ============================================================================

#include "TokenEstimatorSwarm.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <thread>
#include <sstream>
#include <fstream>

namespace RawrXD {
namespace Executive {

// ============================================================================
// Token Category Helpers
// ============================================================================
const char* TokenCategoryToString(TokenCategory cat) {
    switch (cat) {
        case TokenCategory::PROMPT_TOKENS: return "prompt";
        case TokenCategory::COMPLETION_TOKENS: return "completion";
        case TokenCategory::THINKING_TOKENS: return "thinking";
        case TokenCategory::TOOL_CALL_TOKENS: return "tool_call";
        case TokenCategory::TOOL_RESULT_TOKENS: return "tool_result";
        case TokenCategory::RETRY_TOKENS: return "retry";
        case TokenCategory::OVERHEAD_TOKENS: return "overhead";
        case TokenCategory::SLACK_TOKENS: return "slack";
        default: return "unknown";
    }
}

// ============================================================================
// Record Operations
// ============================================================================
void TokenEstimatorSwarm::recordEstimate(uint64_t goalId, const TokenEstimate& estimate) {
    // Store in goal history
    goalHistory_[goalId].push_back(estimate);
    
    // Also store in recent records (circular buffer behavior)
    if (recentRecords_.size() >= MAX_RECENT_RECORDS) {
        recentRecords_.erase(recentRecords_.begin());
    }
    recentRecords_.push_back(estimate);
    
    printf("[TokenEstimator] Recorded estimate for goal %llu: %.0f tokens\n",
           (unsigned long long)goalId, estimate.totalEstimated);
}

void TokenEstimatorSwarm::recordActuals(uint64_t goalId, const TokenEstimate& actuals) {
    // Find the matching estimate
    auto& history = goalHistory_[goalId];
    if (!history.empty()) {
        // Update the last estimate with actuals
        auto& record = history.back();
        for (int i = 0; i < static_cast<int>(TokenCategory::COUNT); i++) {
            record.actualByCategory[i] = actuals.actualByCategory[i];
        }
        record.totalActual = actuals.totalActual;
        record.slack = actuals.totalActual - record.totalEstimated;
        
        // Update agent and operation info
        record.agentName = actuals.agentName;
        record.operationType = actuals.operationType;
        record.retryCount = actuals.retryCount;
        
        printf("[TokenEstimator] Recorded actuals for goal %llu: %.0f tokens (slack: %+.0f)\n",
               (unsigned long long)goalId, actuals.totalActual, record.slack);
        
        // If there's significant slack, run the swarm to analyze
        if (record.slack > record.totalEstimated * 0.2f) {  // >20% over estimate
            runEstimationSwarm(goalId);
        }
    }
}

// ============================================================================
// Slack Analysis
// ============================================================================
SlackAnalysis TokenEstimatorSwarm::analyzeSlack(uint64_t goalId) {
    SlackAnalysis analysis;
    analysis.totalSlack = 0;
    analysis.largestCategorySlack = 0;
    analysis.largestSlackCategory = TokenCategory::SLACK_TOKENS;
    
    auto& history = goalHistory_[goalId];
    if (history.empty()) {
        return analysis;
    }
    
    // Aggregate across all records for this goal
    float categorySlack[static_cast<int>(TokenCategory::COUNT)] = {};
    float categoryEstimated[static_cast<int>(TokenCategory::COUNT)] = {};
    float categoryActual[static_cast<int>(TokenCategory::COUNT)] = {};
    
    for (const auto& record : history) {
        for (int i = 0; i < static_cast<int>(TokenCategory::COUNT); i++) {
            categoryEstimated[i] += record.estimatedByCategory[i];
            categoryActual[i] += record.actualByCategory[i];
            categorySlack[i] += (record.actualByCategory[i] - record.estimatedByCategory[i]);
        }
    }
    
    // Build category breakdown
    for (int i = 0; i < static_cast<int>(TokenCategory::COUNT); i++) {
        SlackAnalysis::CategorySlack cs;
        cs.category = static_cast<TokenCategory>(i);
        cs.estimated = categoryEstimated[i];
        cs.actual = categoryActual[i];
        cs.slack = categorySlack[i];
        cs.slackPercentage = (categoryEstimated[i] > 0) ? 
            (categorySlack[i] / categoryEstimated[i] * 100.0f) : 0.0f;
        
        analysis.categorySlack.push_back(cs);
        analysis.totalSlack += cs.slack;
        
        if (cs.slack > analysis.largestCategorySlack) {
            analysis.largestCategorySlack = cs.slack;
            analysis.largestSlackCategory = cs.category;
        }
    }
    
    // Generate recommendations
    for (const auto& cs : analysis.categorySlack) {
        if (cs.slackPercentage > 50.0f) {
            std::string rec = std::string(TokenCategoryToString(cs.category)) + 
                " tokens exceeded estimate by " + std::to_string((int)cs.slackPercentage) + "%";
            analysis.recommendations.push_back(strdup(rec.c_str()));
        }
    }
    
    return analysis;
}

// ============================================================================
// Run Estimation Swarm (8 agents)
// ============================================================================
void TokenEstimatorSwarm::runEstimationSwarm(uint64_t goalId) {
    printf("\n[TokenEstimatorSwarm] Analyzing slack for goal %llu...\n",
           (unsigned long long)goalId);
    
    auto& history = goalHistory_[goalId];
    if (history.empty()) return;
    
    const auto& record = history.back();
    
    // Launch all 8 agents
    std::vector<std::thread> agents;
    
    agents.emplace_back([this, &record]() { runPromptAnalyzer(record); });
    agents.emplace_back([this, &record]() { runCompletionPredictor(record); });
    agents.emplace_back([this, &record]() { runThinkingMonitor(record); });
    agents.emplace_back([this, &record]() { runToolCostTracker(record); });
    agents.emplace_back([this, &record]() { runRetryAccountant(record); });
    agents.emplace_back([this, &record]() { runOverheadDetector(record); });
    agents.emplace_back([this, goalId]() { runSlackInvestigator(goalId); });
    agents.emplace_back([this]() { runPatternLearner(); });
    
    for (auto& agent : agents) {
        if (agent.joinable()) agent.join();
    }
    
    printf("[TokenEstimatorSwarm] Analysis complete\n\n");
}

// ============================================================================
// Individual Estimator Agents
// ============================================================================

void TokenEstimatorSwarm::runPromptAnalyzer(const TokenEstimate& record) {
    printf("  [Agent:PromptAnalyzer] Analyzing prompt token accuracy...\n");
    
    float promptEstimated = record.estimatedByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)];
    float promptActual = record.actualByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)];
    
    if (promptEstimated > 0) {
        float variance = (promptActual - promptEstimated) / promptEstimated * 100.0f;
        if (variance > 10.0f) {
            printf("    ⚠️ Prompt tokens %.1f%% over estimate\n", variance);
            printf("    💡 Consider: Use tokenizer pre-check for accurate counts\n");
        } else {
            printf("    ✓ Prompt estimate accurate (%.1f%% variance)\n", variance);
        }
    }
}

void TokenEstimatorSwarm::runCompletionPredictor(const TokenEstimate& record) {
    printf("  [Agent:CompletionPredictor] Analyzing completion predictions...\n");
    
    float compEstimated = record.estimatedByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)];
    float compActual = record.actualByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)];
    
    if (compEstimated > 0) {
        float ratio = compActual / compEstimated;
        if (ratio > 2.0f) {
            printf("    ⚠️ Completion %.1fx longer than estimated\n", ratio);
            printf("    💡 Consider: Reduce max_tokens or add stop sequences\n");
        } else if (ratio < 0.5f) {
            printf("    ℹ️ Completion shorter than expected (%.1fx)\n", ratio);
        } else {
            printf("    ✓ Completion within expected range\n");
        }
    }
}

void TokenEstimatorSwarm::runThinkingMonitor(const TokenEstimate& record) {
    printf("  [Agent:ThinkingMonitor] Monitoring reasoning overhead...\n");
    
    float thinkingTokens = record.actualByCategory[static_cast<int>(TokenCategory::THINKING_TOKENS)];
    if (thinkingTokens > 0) {
        float thinkingRatio = thinkingTokens / record.totalActual * 100.0f;
        printf("    ℹ️ Thinking tokens: %.0f (%.1f%% of total)\n", thinkingTokens, thinkingRatio);
        
        if (thinkingRatio > 30.0f) {
            printf("    💡 Consider: Enable reasoning compression or CoT summarization\n");
        }
    }
}

void TokenEstimatorSwarm::runToolCostTracker(const TokenEstimate& record) {
    printf("  [Agent:ToolCostTracker] Tracking tool invocation costs...\n");
    
    float toolCallTokens = record.actualByCategory[static_cast<int>(TokenCategory::TOOL_CALL_TOKENS)];
    float toolResultTokens = record.actualByCategory[static_cast<int>(TokenCategory::TOOL_RESULT_TOKENS)];
    float totalToolTokens = toolCallTokens + toolResultTokens;
    
    if (totalToolTokens > 0) {
        printf("    ℹ️ Tool tokens: %.0f (calls: %.0f, results: %.0f)\n",
               totalToolTokens, toolCallTokens, toolResultTokens);
        
        if (totalToolTokens > record.totalActual * 0.4f) {
            printf("    💡 Consider: Batch tool calls or use cached results\n");
        }
    }
}

void TokenEstimatorSwarm::runRetryAccountant(const TokenEstimate& record) {
    printf("  [Agent:RetryAccountant] Accounting for retry costs...\n");
    
    float retryTokens = record.actualByCategory[static_cast<int>(TokenCategory::RETRY_TOKENS)];
    if (retryTokens > 0) {
        printf("    ⚠️ Retry tokens: %.0f (%.1f%% of total)\n",
               retryTokens, retryTokens / record.totalActual * 100.0f);
        printf("    💡 Consider: Improve prompt quality to reduce retries\n");
    } else if (record.retryCount > 0) {
        printf("    ℹ️ %u retries occurred but no token overhead tracked\n", record.retryCount);
    } else {
        printf("    ✓ No retries\n");
    }
}

void TokenEstimatorSwarm::runOverheadDetector(const TokenEstimate& record) {
    printf("  [Agent:OverheadDetector] Detecting system overhead...\n");
    
    float overheadTokens = record.actualByCategory[static_cast<int>(TokenCategory::OVERHEAD_TOKENS)];
    if (overheadTokens > 0) {
        printf("    ℹ️ Overhead tokens: %.0f\n", overheadTokens);
    }
    
    // Calculate unexplained slack
    float explained = 0;
    for (int i = 0; i < static_cast<int>(TokenCategory::COUNT); i++) {
        explained += record.actualByCategory[i];
    }
    
    float unexplained = record.totalActual - explained;
    if (unexplained > record.totalActual * 0.05f) {  // >5% unexplained
        printf("    ⚠️ Unexplained tokens: %.0f (%.1f%%)\n",
               unexplained, unexplained / record.totalActual * 100.0f);
        printf("    💡 Consider: Add more granular token tracking\n");
    }
}

void TokenEstimatorSwarm::runSlackInvestigator(uint64_t goalId) {
    printf("  [Agent:SlackInvestigator] Investigating slack sources...\n");
    
    auto analysis = analyzeSlack(goalId);
    
    printf("    Total slack: %+.0f tokens\n", analysis.totalSlack);
    printf("    Largest category: %s (%.0f tokens)\n",
           TokenCategoryToString(analysis.largestSlackCategory),
           analysis.largestCategorySlack);
    
    if (!analysis.recommendations.empty()) {
        printf("    Recommendations:\n");
        for (const auto& rec : analysis.recommendations) {
            printf("      - %s\n", rec);
        }
    }
}

void TokenEstimatorSwarm::runPatternLearner() {
    printf("  [Agent:PatternLearner] Learning estimation patterns...\n");
    
    // Update operation bias
    for (const auto& record : recentRecords_) {
        if (record.operationType && record.totalEstimated > 0) {
            float bias = (record.totalActual - record.totalEstimated) / record.totalEstimated;
            auto& currentBias = operationBias_[record.operationType];
            currentBias = currentBias * 0.9f + bias * 0.1f;  // EMA
        }
    }
    
    // Report learned biases
    if (!operationBias_.empty()) {
        printf("    Learned biases by operation:\n");
        for (const auto& [op, bias] : operationBias_) {
            printf("      %s: %+.1f%%\n", op.c_str(), bias * 100.0f);
        }
    }
}

// ============================================================================
// Get Improved Estimate
// ============================================================================
TokenEstimate TokenEstimatorSwarm::getImprovedEstimate(const char* operationType,
                                                        const char* agentName,
                                                        float baseEstimate) {
    TokenEstimate improved;
    improved.totalEstimated = baseEstimate;
    
    // Apply learned bias for this operation
    if (operationType && operationBias_.count(operationType)) {
        float bias = operationBias_[operationType];
        improved.totalEstimated *= (1.0f + bias);
        printf("[TokenEstimator] Applied %.1f%% bias for operation '%s'\n",
               bias * 100.0f, operationType);
    }
    
    // Apply agent-specific bias
    if (agentName && agentBias_.count(agentName)) {
        float bias = agentBias_[agentName];
        improved.totalEstimated *= (1.0f + bias);
    }
    
    return improved;
}

// ============================================================================
// Utility Functions
// ============================================================================
std::vector<TokenEstimate> TokenEstimatorSwarm::getHistory(uint64_t goalId, size_t maxRecords) {
    if (goalId == 0) {
        // Return recent records across all goals
        std::vector<TokenEstimate> result = recentRecords_;
        if (result.size() > maxRecords) {
            result.resize(maxRecords);
        }
        return result;
    }
    
    auto& history = goalHistory_[goalId];
    if (history.size() <= maxRecords) {
        return history;
    }
    
    return std::vector<TokenEstimate>(history.end() - maxRecords, history.end());
}

void TokenEstimatorSwarm::clearHistory() {
    goalHistory_.clear();
    recentRecords_.clear();
    operationBias_.clear();
    agentBias_.clear();
}

void TokenEstimatorSwarm::exportToCSV(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    // Header
    file << "goal_id,timestamp,total_estimated,total_actual,slack,agent,operation\n";
    
    // Data
    for (const auto& [goalId, records] : goalHistory_) {
        for (const auto& record : records) {
            file << goalId << ","
                 << "...,"  // timestamp
                 << record.totalEstimated << ","
                 << record.totalActual << ","
                 << record.slack << ","
                 << (record.agentName ? record.agentName : "unknown") << ","
                 << (record.operationType ? record.operationType : "unknown") << "\n";
        }
    }
    
    file.close();
    printf("[TokenEstimator] Exported history to %s\n", filename);
}

// ============================================================================
// C-API Implementation
// ============================================================================
extern "C" {

void RecordTokenEstimate(uint64_t goalId, float estimatedTotal) {
    RawrXD::Executive::TokenEstimate estimate;
    estimate.goalId = goalId;
    estimate.totalEstimated = estimatedTotal;
    estimate.timestamp = std::chrono::steady_clock::now();
    
    RawrXD::Executive::TokenEstimatorSwarm::getInstance().recordEstimate(goalId, estimate);
}

void RecordTokenActuals(uint64_t goalId, float actualTotal, const char* breakdown) {
    RawrXD::Executive::TokenEstimate actuals;
    actuals.goalId = goalId;
    actuals.totalActual = actualTotal;
    actuals.timestamp = std::chrono::steady_clock::now();
    
    // Parse breakdown string (simplified)
    // Format: "category:value,category:value,..."
    if (breakdown) {
        // Simple parsing would go here
    }
    
    RawrXD::Executive::TokenEstimatorSwarm::getInstance().recordActuals(goalId, actuals);
}

void AnalyzeTokenSlack(uint64_t goalId, char* outputBuffer, size_t bufferSize) {
    auto analysis = RawrXD::Executive::TokenEstimatorSwarm::getInstance().analyzeSlack(goalId);
    
    std::stringstream ss;
    ss << "Slack Analysis for Goal " << goalId << ":\n";
    ss << "Total Slack: " << analysis.totalSlack << " tokens\n";
    ss << "Largest Category: " << RawrXD::Executive::TokenCategoryToString(analysis.largestSlackCategory) << "\n";
    
    std::string result = ss.str();
    strncpy(outputBuffer, result.c_str(), bufferSize - 1);
    outputBuffer[bufferSize - 1] = '\0';
}

float GetImprovedTokenEstimate(const char* operation, const char* agent, float baseEstimate) {
    auto estimate = RawrXD::Executive::TokenEstimatorSwarm::getInstance()
        .getImprovedEstimate(operation, agent, baseEstimate);
    return estimate.totalEstimated;
}

} // extern "C"

} // namespace Executive
} // namespace RawrXD
