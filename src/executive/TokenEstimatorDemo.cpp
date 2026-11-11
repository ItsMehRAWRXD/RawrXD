// ============================================================================
// TokenEstimatorDemo.cpp - Demonstration of Token Estimator Swarm
// ============================================================================
// Shows how to "unreverse" spent tokens to identify where slack occurs
// ============================================================================

#include "TokenEstimatorSwarm.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Executive;

void printHeader(const char* title) {
    printf("\n");
    printf("=================================================================\n");
    printf("  %s\n", title);
    printf("=================================================================\n");
}

void demoBasicEstimation() {
    printHeader("Demo 1: Basic Token Estimation vs Actual");
    
    auto& swarm = TokenEstimatorSwarm::getInstance();
    
    // Goal 1: Simple code generation
    uint64_t goalId = 1;
    
    // Record estimate before execution
    TokenEstimate estimate;
    estimate.goalId = goalId;
    estimate.totalEstimated = 500.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)] = 100.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)] = 400.0f;
    estimate.operationType = "code_generation";
    estimate.agentName = "coder_agent";
    
    swarm.recordEstimate(goalId, estimate);
    
    // Record actuals after execution (THE "UNREVERSE" OPERATION)
    TokenEstimate actuals;
    actuals.goalId = goalId;
    actuals.totalActual = 750.0f;  // 50% over estimate!
    actuals.actualByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)] = 120.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)] = 500.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::THINKING_TOKENS)] = 80.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::RETRY_TOKENS)] = 50.0f;
    actuals.operationType = "code_generation";
    actuals.agentName = "coder_agent";
    actuals.retryCount = 1;
    
    swarm.recordActuals(goalId, actuals);
}

void demoComplexScenario() {
    printHeader("Demo 2: Complex Multi-Agent Scenario");
    
    auto& swarm = TokenEstimatorSwarm::getInstance();
    
    // Goal 2: Complex refactoring with tool calls
    uint64_t goalId = 2;
    
    TokenEstimate estimate;
    estimate.goalId = goalId;
    estimate.totalEstimated = 1000.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)] = 200.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)] = 600.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::TOOL_CALL_TOKENS)] = 100.0f;
    estimate.estimatedByCategory[static_cast<int>(TokenCategory::TOOL_RESULT_TOKENS)] = 100.0f;
    estimate.operationType = "complex_refactoring";
    estimate.agentName = "architect_agent";
    
    swarm.recordEstimate(goalId, estimate);
    
    // Actuals - way over budget
    TokenEstimate actuals;
    actuals.goalId = goalId;
    actuals.totalActual = 2500.0f;  // 2.5x over estimate!
    actuals.actualByCategory[static_cast<int>(TokenCategory::PROMPT_TOKENS)] = 250.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::COMPLETION_TOKENS)] = 1200.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::THINKING_TOKENS)] = 400.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::TOOL_CALL_TOKENS)] = 300.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::TOOL_RESULT_TOKENS)] = 250.0f;
    actuals.actualByCategory[static_cast<int>(TokenCategory::RETRY_TOKENS)] = 100.0f;
    actuals.operationType = "complex_refactoring";
    actuals.agentName = "architect_agent";
    actuals.retryCount = 2;
    
    swarm.recordActuals(goalId, actuals);
}

void demoSlackAnalysis() {
    printHeader("Demo 3: Slack Analysis");
    
    auto& swarm = TokenEstimatorSwarm::getInstance();
    
    // Analyze slack for goal 2
    auto analysis = swarm.analyzeSlack(2);
    
    printf("\nSlack Analysis Results:\n");
    printf("  Total Slack: %+.0f tokens\n", analysis.totalSlack);
    printf("  Largest Category: %s (%.0f tokens)\n",
           TokenCategoryToString(analysis.largestSlackCategory),
           analysis.largestCategorySlack);
    
    printf("\nCategory Breakdown:\n");
    for (const auto& cs : analysis.categorySlack) {
        if (cs.actual > 0 || cs.estimated > 0) {
            printf("  %s: estimated=%.0f, actual=%.0f, slack=%+.0f (%.1f%%)\n",
                   TokenCategoryToString(cs.category),
                   cs.estimated, cs.actual, cs.slack, cs.slackPercentage);
        }
    }
}

void demoImprovedEstimates() {
    printHeader("Demo 4: Improved Estimates Based on Learned Patterns");
    
    auto& swarm = TokenEstimatorSwarm::getInstance();
    
    // Get improved estimate for code_generation
    float baseEstimate = 500.0f;
    auto improved = swarm.getImprovedEstimate("code_generation", "coder_agent", baseEstimate);
    
    printf("Base estimate: %.0f tokens\n", baseEstimate);
    printf("Improved estimate: %.0f tokens\n", improved.totalEstimated);
    
    // Get improved estimate for complex_refactoring
    baseEstimate = 1000.0f;
    improved = swarm.getImprovedEstimate("complex_refactoring", "architect_agent", baseEstimate);
    
    printf("\nBase estimate: %.0f tokens\n", baseEstimate);
    printf("Improved estimate: %.0f tokens\n", improved.totalEstimated);
}

void demoHistory() {
    printHeader("Demo 5: Historical Pattern Analysis");
    
    auto& swarm = TokenEstimatorSwarm::getInstance();
    
    // Get history for all goals
    auto history = swarm.getHistory(0, 10);
    
    printf("Recent token records:\n");
    for (const auto& record : history) {
        printf("  Goal %llu: est=%.0f, actual=%.0f, slack=%+.0f [%s/%s]\n",
               (unsigned long long)record.goalId,
               record.totalEstimated, record.totalActual, record.slack,
               record.operationType ? record.operationType : "?",
               record.agentName ? record.agentName : "?");
    }
}

void demoCAPI() {
    printHeader("Demo 6: C-API Usage");
    
    // Using C-API
    RecordTokenEstimate(3, 300.0f);
    RecordTokenActuals(3, 450.0f, nullptr);
    
    char buffer[1024];
    AnalyzeTokenSlack(3, buffer, sizeof(buffer));
    printf("%s\n", buffer);
    
    float improved = GetImprovedTokenEstimate("code_generation", "coder_agent", 500.0f);
    printf("Improved estimate via C-API: %.0f tokens\n", improved);
}

int main() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║     Token Estimator Swarm - Slack Analysis Demo               ║\n");
    printf("║     'Unreversing' spent tokens to find where slack occurs      ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Run all demos
    demoBasicEstimation();
    demoComplexScenario();
    demoSlackAnalysis();
    demoImprovedEstimates();
    demoHistory();
    demoCAPI();
    
    printHeader("Summary");
    printf("The Token Estimator Swarm has:\n");
    printf("  1. Recorded estimates before execution\n");
    printf("  2. 'Unreversed' actuals after execution\n");
    printf("  3. Analyzed where slack (divergence) occurs\n");
    printf("  4. Learned patterns to improve future estimates\n");
    printf("  5. Provided actionable recommendations\n");
    printf("\nKey insight: Slack is primarily in:\n");
    printf("  - Completion tokens (underestimated output length)\n");
    printf("  - Thinking tokens (unaccounted reasoning overhead)\n");
    printf("  - Retry tokens (failed attempts)\n");
    printf("  - Tool tokens (underestimated tool interaction)\n");
    
    printf("\n");
    return 0;
}
