#pragma once

/**
 * EmergentIntentModel.hpp
 *
 * Phase C.2 Batch 3/5: Emergent Intent Modeling
 *
 * The system predicts its own next actions, forms internal goals,
 * and optimizes for long-term convergence.
 */

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <functional>

namespace Emergent {

/**
 * Intent types the system can form
 */
enum class IntentType {
    MAINTAIN_STABILITY,    // Keep current state stable
    IMPROVE_CONVERGENCE,    // Increase convergence rate
    EXPLORE_NOVEL_STATES,   // Discover new patterns
    OPTIMIZE_EFFICIENCY,    // Reduce resource usage
    RECOVER_FROM_ERROR,     // Handle failures
    ADAPT_TO_CHANGE         // Respond to environmental changes
};

/**
 * Internal goal formed by the system
 */
struct EmergentGoal {
    std::string goalId;
    std::string name;
    std::string description;
    IntentType intent;
    
    // Goal parameters
    double targetValue;
    double currentValue;
    double priority;        // 0-1, higher = more important
    
    // Temporal
    int64_t createdAtMs;
    int64_t deadlineMs;     // 0 = no deadline
    int64_t achievedAtMs;   // 0 = not yet achieved
    
    // Progress
    double progress;        // 0-1
    bool isAchieved;
    std::vector<std::string> subGoals;
    
    std::string ToJson() const;
};

/**
 * Predicted next action
 */
struct PredictedAction {
    std::string actionId;
    std::string name;
    std::string description;
    
    // Prediction confidence
    double confidence;
    double expectedUtility;
    
    // Preconditions and effects
    std::vector<std::string> preconditions;
    std::map<std::string, double> expectedEffects;
    
    // Temporal
    int64_t predictedAtMs;
    int64_t expectedExecutionMs;
    int64_t expectedCompletionMs;
    
    std::string ToJson() const;
};

/**
 * Action outcome (for learning)
 */
struct ActionOutcome {
    std::string actionId;
    bool success;
    double actualUtility;
    std::map<std::string, double> actualEffects;
    int64_t executedAtMs;
    int64_t completedAtMs;
    std::string outcomeDescription;
};

/**
 * Intent model configuration
 */
struct IntentModelConfig {
    // Goal formation
    double minPriorityForGoal = 0.5;
    int maxConcurrentGoals = 5;
    int64_t goalHorizonMs = 60000;  // 1 minute lookahead
    
    // Action prediction
    int maxPredictedActions = 10;
    double minPredictionConfidence = 0.6;
    
    // Learning
    double learningRate = 0.1;
    int historyWindowSize = 100;
    bool enableExploration = true;
    double explorationRate = 0.2;
};

/**
 * Intent modeling result
 */
struct IntentModelResult {
    std::vector<EmergentGoal> activeGoals;
    std::vector<PredictedAction> predictedActions;
    std::map<IntentType, double> intentStrengths;
    
    int64_t modelUpdateMs;
    double overallConfidence;
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * System state for intent modeling
 */
struct SystemState {
    int64_t timestampMs;
    double convergenceScore;
    double stabilityScore;
    double efficiencyScore;
    std::map<std::string, double> metrics;
    std::vector<std::string> activePatterns;
    std::vector<std::string> recentEvents;
};

/**
 * Emergent Intent Model
 *
 * Predicts future actions and forms internal goals
 */
class EmergentIntentModel {
public:
    EmergentIntentModel();
    ~EmergentIntentModel();
    
    // Initialize
    bool Initialize(const IntentModelConfig& config = IntentModelConfig{});
    
    // Update with current state
    void UpdateState(const SystemState& state);
    
    // Run intent modeling
    IntentModelResult ModelIntents();
    
    // Specific modeling functions
    std::vector<EmergentGoal> FormGoals(const SystemState& state);
    std::vector<PredictedAction> PredictActions(const SystemState& state);
    std::map<IntentType, double> CalculateIntentStrengths(const SystemState& state);
    
    // Learn from outcomes
    void LearnFromOutcome(const ActionOutcome& outcome);
    void LearnFromHistory(const std::vector<ActionOutcome>& history);
    
    // Goal management
    void AddGoal(const EmergentGoal& goal);
    void UpdateGoalProgress(const std::string& goalId, double progress);
    void MarkGoalAchieved(const std::string& goalId);
    void AbandonGoal(const std::string& goalId);
    
    // Get current state
    const std::vector<EmergentGoal>& GetActiveGoals() const { return activeGoals_; }
    const std::vector<PredictedAction>& GetPredictedActions() const { return predictedActions_; }
    
    // Export/Import
    bool SaveModel(const std::string& path) const;
    bool LoadModel(const std::string& path);
    
private:
    IntentModelConfig config_;
    std::vector<SystemState> stateHistory_;
    std::vector<EmergentGoal> activeGoals_;
    std::vector<PredictedAction> predictedActions_;
    std::vector<ActionOutcome> actionHistory_;
    
    // Learning model (simplified)
    std::map<std::string, double> actionSuccessRates_;
    std::map<std::string, std::map<std::string, double>> actionEffectModels_;
    
    // Helper methods
    double PredictConvergence(const SystemState& state, const PredictedAction& action);
    double CalculateGoalPriority(IntentType intent, const SystemState& state);
    bool IsGoalAchievable(const EmergentGoal& goal, const SystemState& state);
    std::string GenerateGoalId() const;
    std::string GenerateActionId() const;
};

/**
 * Intent model CLI
 */
class EmergentIntentModelCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintBanner();
    static void PrintUsage();
    static IntentModelConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Emergent
