/**
 * EmergentIntentModel.cpp
 *
 * Phase C.2 Batch 3/5: Emergent Intent Modeling Implementation
 */

#include "EmergentIntentModel.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>
#include <fstream>

namespace Emergent {

// EmergentGoal implementation
std::string EmergentGoal::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"goalId\":\"" << goalId << "\",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"intent\":" << static_cast<int>(intent) << ",";
    json << "\"targetValue\":" << std::fixed << std::setprecision(4) << targetValue << ",";
    json << "\"currentValue\":" << currentValue << ",";
    json << "\"priority\":" << priority << ",";
    json << "\"createdAtMs\":" << createdAtMs << ",";
    json << "\"deadlineMs\":" << deadlineMs << ",";
    json << "\"achievedAtMs\":" << achievedAtMs << ",";
    json << "\"progress\":" << progress << ",";
    json << "\"isAchieved\":" << (isAchieved ? "true" : "false") << ",";
    json << "\"subGoals\":[";
    for (size_t i = 0; i < subGoals.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << subGoals[i] << "\"";
    }
    json << "]}";
    return json.str();
}

// PredictedAction implementation
std::string PredictedAction::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"actionId\":\"" << actionId << "\",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"confidence\":" << std::fixed << std::setprecision(4) << confidence << ",";
    json << "\"expectedUtility\":" << expectedUtility << ",";
    json << "\"preconditions\":[";
    for (size_t i = 0; i < preconditions.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << preconditions[i] << "\"";
    }
    json << "],";
    json << "\"expectedEffects\":{";
    bool first = true;
    for (const auto& [key, val] : expectedEffects) {
        if (!first) json << ",";
        json << "\"" << key << "\":" << val;
        first = false;
    }
    json << "},";
    json << "\"predictedAtMs\":" << predictedAtMs << ",";
    json << "\"expectedExecutionMs\":" << expectedExecutionMs << ",";
    json << "\"expectedCompletionMs\":" << expectedCompletionMs << "}";
    return json.str();
}

// IntentModelResult implementation
std::string IntentModelResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"activeGoals\":[";
    for (size_t i = 0; i < activeGoals.size(); ++i) {
        if (i > 0) json << ",";
        json << activeGoals[i].ToJson();
    }
    json << "],";
    json << "\"predictedActions\":[";
    for (size_t i = 0; i < predictedActions.size(); ++i) {
        if (i > 0) json << ",";
        json << predictedActions[i].ToJson();
    }
    json << "],";
    json << "\"intentStrengths\":{";
    bool first = true;
    for (const auto& [intent, strength] : intentStrengths) {
        if (!first) json << ",";
        json << "\"" << static_cast<int>(intent) << "\":" << strength;
        first = false;
    }
    json << "},";
    json << "\"modelUpdateMs\":" << modelUpdateMs << ",";
    json << "\"overallConfidence\":" << overallConfidence << "}";
    return json.str();
}

void IntentModelResult::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           EMERGENT INTENT MODEL RESULTS                          ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Active Goals:       " << std::setw(10) << activeGoals.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Predicted Actions:  " << std::setw(10) << predictedActions.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Overall Confidence: " << std::setw(10) << std::fixed << std::setprecision(2) << overallConfidence << std::string(26, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    if (!intentStrengths.empty()) {
        std::cout << "║  Intent Strengths:                                             ║\n";
        for (const auto& [intent, strength] : intentStrengths) {
            std::string intentName;
            switch (intent) {
                case IntentType::MAINTAIN_STABILITY: intentName = "Maintain Stability"; break;
                case IntentType::IMPROVE_CONVERGENCE: intentName = "Improve Convergence"; break;
                case IntentType::EXPLORE_NOVEL_STATES: intentName = "Explore Novel States"; break;
                case IntentType::OPTIMIZE_EFFICIENCY: intentName = "Optimize Efficiency"; break;
                case IntentType::RECOVER_FROM_ERROR: intentName = "Recover From Error"; break;
                case IntentType::ADAPT_TO_CHANGE: intentName = "Adapt To Change"; break;
                default: intentName = "Unknown"; break;
            }
            std::cout << "║    " << std::left << std::setw(25) << intentName 
                      << ": " << std::setw(6) << std::fixed << std::setprecision(3) << strength
                      << std::string(20, ' ') << "║\n";
        }
    }
    
    if (!activeGoals.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Active Goals:                                                 ║\n";
        for (const auto& goal : activeGoals) {
            std::cout << "║    " << std::left << std::setw(20) << goal.name 
                      << " (prog: " << std::setw(5) << std::fixed << std::setprecision(1) << (goal.progress * 100) << "%)"
                      << std::string(15, ' ') << "║\n";
        }
    }
    
    if (!predictedActions.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Top Predicted Actions:                                          ║\n";
        int shown = 0;
        for (const auto& action : predictedActions) {
            if (shown >= 3) break;
            std::cout << "║    " << std::left << std::setw(20) << action.name 
                      << " (conf: " << std::setw(5) << std::fixed << std::setprecision(2) << action.confidence << ")"
                      << std::string(15, ' ') << "║\n";
            shown++;
        }
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// EmergentIntentModel implementation
EmergentIntentModel::EmergentIntentModel() = default;
EmergentIntentModel::~EmergentIntentModel() = default;

bool EmergentIntentModel::Initialize(const IntentModelConfig& config) {
    config_ = config;
    stateHistory_.clear();
    activeGoals_.clear();
    predictedActions_.clear();
    actionHistory_.clear();
    actionSuccessRates_.clear();
    actionEffectModels_.clear();
    std::cout << "[EmergentIntentModel] Initialized\n";
    return true;
}

void EmergentIntentModel::UpdateState(const SystemState& state) {
    stateHistory_.push_back(state);
    
    // Keep only recent history
    if (stateHistory_.size() > static_cast<size_t>(config_.historyWindowSize)) {
        stateHistory_.erase(stateHistory_.begin());
    }
}

IntentModelResult EmergentIntentModel::ModelIntents() {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    IntentModelResult result;
    
    if (stateHistory_.empty()) {
        result.overallConfidence = 0.0;
        return result;
    }
    
    const SystemState& currentState = stateHistory_.back();
    
    // Form goals based on current state
    result.activeGoals = FormGoals(currentState);
    
    // Predict next actions
    result.predictedActions = PredictActions(currentState);
    
    // Calculate intent strengths
    result.intentStrengths = CalculateIntentStrengths(currentState);
    
    // Update active goals
    activeGoals_ = result.activeGoals;
    predictedActions_ = result.predictedActions;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.modelUpdateMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Calculate overall confidence
    if (!result.predictedActions.empty()) {
        double totalConfidence = 0.0;
        for (const auto& action : result.predictedActions) {
            totalConfidence += action.confidence;
        }
        result.overallConfidence = totalConfidence / result.predictedActions.size();
    } else {
        result.overallConfidence = 0.5;
    }
    
    return result;
}

std::vector<EmergentGoal> EmergentIntentModel::FormGoals(const SystemState& state) {
    std::vector<EmergentGoal> goals;
    
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    // Goal 1: Maintain stability if currently stable
    if (state.stabilityScore > 0.8) {
        EmergentGoal goal;
        goal.goalId = GenerateGoalId();
        goal.name = "Maintain Stability";
        goal.description = "Keep system stability above 0.8";
        goal.intent = IntentType::MAINTAIN_STABILITY;
        goal.targetValue = 0.9;
        goal.currentValue = state.stabilityScore;
        goal.priority = 0.7;
        goal.createdAtMs = currentTime;
        goal.deadlineMs = currentTime + config_.goalHorizonMs;
        goal.progress = state.stabilityScore / 0.9;
        goal.isAchieved = state.stabilityScore >= 0.9;
        goals.push_back(goal);
    }
    
    // Goal 2: Improve convergence if below target
    if (state.convergenceScore < 0.85) {
        EmergentGoal goal;
        goal.goalId = GenerateGoalId();
        goal.name = "Improve Convergence";
        goal.description = "Increase convergence score to 0.85";
        goal.intent = IntentType::IMPROVE_CONVERGENCE;
        goal.targetValue = 0.85;
        goal.currentValue = state.convergenceScore;
        goal.priority = 0.9;
        goal.createdAtMs = currentTime;
        goal.deadlineMs = currentTime + config_.goalHorizonMs;
        goal.progress = state.convergenceScore / 0.85;
        goal.isAchieved = state.convergenceScore >= 0.85;
        goals.push_back(goal);
    }
    
    // Goal 3: Optimize efficiency if resources are high
    if (state.efficiencyScore < 0.7) {
        EmergentGoal goal;
        goal.goalId = GenerateGoalId();
        goal.name = "Optimize Efficiency";
        goal.description = "Improve resource efficiency";
        goal.intent = IntentType::OPTIMIZE_EFFICIENCY;
        goal.targetValue = 0.8;
        goal.currentValue = state.efficiencyScore;
        goal.priority = 0.6;
        goal.createdAtMs = currentTime;
        goal.deadlineMs = currentTime + config_.goalHorizonMs;
        goal.progress = state.efficiencyScore / 0.8;
        goal.isAchieved = state.efficiencyScore >= 0.8;
        goals.push_back(goal);
    }
    
    // Sort by priority
    std::sort(goals.begin(), goals.end(),
        [](const EmergentGoal& a, const EmergentGoal& b) { return a.priority > b.priority; });
    
    // Keep only top goals
    if (goals.size() > static_cast<size_t>(config_.maxConcurrentGoals)) {
        goals.resize(config_.maxConcurrentGoals);
    }
    
    return goals;
}

std::vector<PredictedAction> EmergentIntentModel::PredictActions(const SystemState& state) {
    std::vector<PredictedAction> actions;
    
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    // Predict action: Execute Workflow
    {
        PredictedAction action;
        action.actionId = GenerateActionId();
        action.name = "Execute Workflow";
        action.description = "Run standard workflow execution";
        action.confidence = 0.85;
        action.expectedUtility = 0.7;
        action.preconditions = {"system_running"};
        action.expectedEffects["convergence"] = state.convergenceScore + 0.05;
        action.predictedAtMs = currentTime;
        action.expectedExecutionMs = currentTime + 100;
        action.expectedCompletionMs = currentTime + 500;
        actions.push_back(action);
    }
    
    // Predict action: Adaptive Scheduling
    {
        PredictedAction action;
        action.actionId = GenerateActionId();
        action.name = "Adjust Scheduling";
        action.description = "Adapt scheduler based on current patterns";
        action.confidence = 0.75;
        action.expectedUtility = 0.8;
        action.preconditions = {"patterns_detected"};
        action.expectedEffects["efficiency"] = state.efficiencyScore + 0.1;
        action.predictedAtMs = currentTime;
        action.expectedExecutionMs = currentTime + 200;
        action.expectedCompletionMs = currentTime + 600;
        actions.push_back(action);
    }
    
    // Predict action: Checkpoint
    {
        PredictedAction action;
        action.actionId = GenerateActionId();
        action.name = "Create Checkpoint";
        action.description = "Save current state for recovery";
        action.confidence = 0.90;
        action.expectedUtility = 0.5;
        action.preconditions = {"stable_state"};
        action.expectedEffects["stability"] = state.stabilityScore + 0.02;
        action.predictedAtMs = currentTime;
        action.expectedExecutionMs = currentTime + 1000;
        action.expectedCompletionMs = currentTime + 1500;
        actions.push_back(action);
    }
    
    // Sort by expected utility
    std::sort(actions.begin(), actions.end(),
        [](const PredictedAction& a, const PredictedAction& b) { return a.expectedUtility > b.expectedUtility; });
    
    // Keep only top predictions
    if (actions.size() > static_cast<size_t>(config_.maxPredictedActions)) {
        actions.resize(config_.maxPredictedActions);
    }
    
    return actions;
}

std::map<IntentType, double> EmergentIntentModel::CalculateIntentStrengths(const SystemState& state) {
    std::map<IntentType, double> strengths;
    
    // Calculate based on current state
    strengths[IntentType::MAINTAIN_STABILITY] = state.stabilityScore;
    strengths[IntentType::IMPROVE_CONVERGENCE] = 1.0 - state.convergenceScore;
    strengths[IntentType::OPTIMIZE_EFFICIENCY] = 1.0 - state.efficiencyScore;
    strengths[IntentType::EXPLORE_NOVEL_STATES] = config_.enableExploration ? config_.explorationRate : 0.0;
    strengths[IntentType::RECOVER_FROM_ERROR] = state.stabilityScore < 0.5 ? 1.0 : 0.0;
    strengths[IntentType::ADAPT_TO_CHANGE] = state.stabilityScore < 0.7 ? 0.8 : 0.2;
    
    return strengths;
}

void EmergentIntentModel::LearnFromOutcome(const ActionOutcome& outcome) {
    actionHistory_.push_back(outcome);
    
    // Update success rate
    auto& rate = actionSuccessRates_[outcome.actionId];
    rate = (rate * 0.9) + (outcome.success ? 0.1 : 0.0);
    
    // Update effect model
    for (const auto& [effect, value] : outcome.actualEffects) {
        auto& model = actionEffectModels_[outcome.actionId][effect];
        model = (model * 0.9) + (value * 0.1);
    }
}

void EmergentIntentModel::LearnFromHistory(const std::vector<ActionOutcome>& history) {
    for (const auto& outcome : history) {
        LearnFromOutcome(outcome);
    }
}

void EmergentIntentModel::AddGoal(const EmergentGoal& goal) {
    activeGoals_.push_back(goal);
}

void EmergentIntentModel::UpdateGoalProgress(const std::string& goalId, double progress) {
    for (auto& goal : activeGoals_) {
        if (goal.goalId == goalId) {
            goal.progress = progress;
            if (progress >= 1.0) {
                goal.isAchieved = true;
                goal.achievedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }
            break;
        }
    }
}

void EmergentIntentModel::MarkGoalAchieved(const std::string& goalId) {
    UpdateGoalProgress(goalId, 1.0);
}

void EmergentIntentModel::AbandonGoal(const std::string& goalId) {
    activeGoals_.erase(
        std::remove_if(activeGoals_.begin(), activeGoals_.end(),
            [&goalId](const EmergentGoal& goal) { return goal.goalId == goalId; }),
        activeGoals_.end()
    );
}

bool EmergentIntentModel::SaveModel(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "{";
    file << "\"goals\":[";
    for (size_t i = 0; i < activeGoals_.size(); ++i) {
        if (i > 0) file << ",";
        file << activeGoals_[i].ToJson();
    }
    file << "],";
    file << "\"predictions\":[";
    for (size_t i = 0; i < predictedActions_.size(); ++i) {
        if (i > 0) file << ",";
        file << predictedActions_[i].ToJson();
    }
    file << "]}";
    return true;
}

bool EmergentIntentModel::LoadModel(const std::string& path) {
    // Simplified load
    return false;
}

// Helper methods
double EmergentIntentModel::PredictConvergence(const SystemState& state, const PredictedAction& action) {
    // Simple prediction based on current convergence and expected effect
    auto it = action.expectedEffects.find("convergence");
    if (it != action.expectedEffects.end()) {
        return it->second;
    }
    return state.convergenceScore;
}

double EmergentIntentModel::CalculateGoalPriority(IntentType intent, const SystemState& state) {
    switch (intent) {
        case IntentType::RECOVER_FROM_ERROR:
            return 1.0;
        case IntentType::IMPROVE_CONVERGENCE:
            return 0.9 * (1.0 - state.convergenceScore);
        case IntentType::MAINTAIN_STABILITY:
            return 0.8 * state.stabilityScore;
        case IntentType::OPTIMIZE_EFFICIENCY:
            return 0.6 * (1.0 - state.efficiencyScore);
        case IntentType::ADAPT_TO_CHANGE:
            return 0.5;
        case IntentType::EXPLORE_NOVEL_STATES:
            return 0.3;
        default:
            return 0.5;
    }
}

bool EmergentIntentModel::IsGoalAchievable(const EmergentGoal& goal, const SystemState& state) {
    // Simple achievability check
    return goal.priority >= config_.minPriorityForGoal;
}

std::string EmergentIntentModel::GenerateGoalId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "goal-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentIntentModel::GenerateActionId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "action-" << ms << "-" << dis(gen);
    return id.str();
}

// CLI Implementation
void EmergentIntentModelCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     EMERGENT INTENT MODEL - Phase C.2                          ║\n";
    std::cout << "║     Predictive Action Modeling & Goal Formation                ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void EmergentIntentModelCLI::PrintUsage() {
    std::cout << "Usage: emergent-intent [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --goals N           Maximum concurrent goals\n";
    std::cout << "  --exploration X     Exploration rate (0-1)\n";
    std::cout << "  --output PATH       Save model to file\n";
    std::cout << "  --json              Output results as JSON\n";
    std::cout << "  --help              Show this help\n\n";
}

IntentModelConfig EmergentIntentModelCLI::ParseArgs(int argc, char* argv[]) {
    IntentModelConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--goals" && i + 1 < argc) {
            config.maxConcurrentGoals = std::stoi(argv[++i]);
        } else if (arg == "--exploration" && i + 1 < argc) {
            config.explorationRate = std::stod(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int EmergentIntentModelCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    IntentModelConfig config = ParseArgs(argc, argv);
    
    // Create intent model
    EmergentIntentModel model;
    model.Initialize(config);
    
    // Generate synthetic system states
    std::cout << "[Demo] Generating synthetic system states...\n";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> scoreDist(0.6, 0.95);
    
    for (int i = 0; i < 20; ++i) {
        SystemState state;
        state.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + (i * 1000);
        state.convergenceScore = scoreDist(gen);
        state.stabilityScore = scoreDist(gen);
        state.efficiencyScore = scoreDist(gen);
        model.UpdateState(state);
    }
    
    // Model intents
    std::cout << "[Demo] Modeling emergent intents...\n";
    auto result = model.ModelIntents();
    
    // Print summary
    result.PrintSummary();
    
    // Check for output path
    std::string outputPath;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--output" && i + 1 < argc) {
            outputPath = argv[i + 1];
        }
    }
    
    if (!outputPath.empty()) {
        if (model.SaveModel(outputPath)) {
            std::cout << "Model saved to: " << outputPath << "\n";
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::cout << "\n" << result.ToJson() << "\n";
        }
    }
    
    return 0;
}

} // namespace Emergent
