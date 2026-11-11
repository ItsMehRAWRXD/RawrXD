// ============================================================================
// IntentCompression.cpp - Compact Machine State Protocol Implementation
// ============================================================================

#include "IntentCompression.hpp"
#include <sstream>
#include <algorithm>
#include <iostream>

namespace Sovereign {

IntentCompression::IntentCompression() = default;
IntentCompression::~IntentCompression() = default;

CompactState IntentCompression::Compress(const std::vector<std::string>& history, const std::string& goal) {
    CompactState state;
    state.goal = goal.empty() ? ExtractGoal(history) : goal;
    state.currentState = history.empty() ? "initial" : history.back();
    state.blockers = ExtractBlockers(history);
    state.nextAction = ExtractNextAction(history);
    state.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    state.iteration = history.size();
    state.progress = EstimateProgress(history);
    
    // Extract recent results and errors
    for (const auto& h : history) {
        if (h.find("error") != std::string::npos || h.find("failed") != std::string::npos) {
            state.recentErrors.push_back(h);
        } else if (h.find("completed") != std::string::npos || h.find("success") != std::string::npos) {
            state.recentResults.push_back(h);
        }
    }
    
    // Keep only last 5
    if (state.recentResults.size() > 5) state.recentResults.erase(state.recentResults.begin(), state.recentResults.end() - 5);
    if (state.recentErrors.size() > 5) state.recentErrors.erase(state.recentErrors.begin(), state.recentErrors.end() - 5);
    
    stats_.totalCompressions++;
    return state;
}

std::string IntentCompression::Decompress(const CompactState& state) {
    stats_.totalDecompressions++;
    
    std::stringstream ss;
    ss << "Goal: " << state.goal << "\n";
    ss << "Current State: " << state.currentState << "\n";
    ss << "Progress: " << (state.progress * 100.0) << "%\n";
    ss << "Iteration: " << state.iteration << "\n";
    
    if (!state.blockers.empty()) {
        ss << "Blockers:\n";
        for (const auto& b : state.blockers) {
            ss << "  - " << b << "\n";
        }
    }
    
    ss << "Next Action: " << state.nextAction << "\n";
    
    if (!state.recentResults.empty()) {
        ss << "Recent Results:\n";
        for (const auto& r : state.recentResults) {
            ss << "  + " << r << "\n";
        }
    }
    
    if (!state.recentErrors.empty()) {
        ss << "Recent Errors:\n";
        for (const auto& e : state.recentErrors) {
            ss << "  ! " << e << "\n";
        }
    }
    
    return ss.str();
}

StateDelta IntentCompression::ComputeDelta(const CompactState& before, const CompactState& after) {
    StateDelta delta;
    delta.timestamp = after.timestamp;
    
    if (before.goal != after.goal) {
        delta.field = "goal";
        delta.oldValue = before.goal;
        delta.newValue = after.goal;
    } else if (before.currentState != after.currentState) {
        delta.field = "currentState";
        delta.oldValue = before.currentState;
        delta.newValue = after.currentState;
    } else if (before.nextAction != after.nextAction) {
        delta.field = "nextAction";
        delta.oldValue = before.nextAction;
        delta.newValue = after.nextAction;
    }
    
    return delta;
}

std::string IntentCompression::ExtractGoal(const std::vector<std::string>& history) const {
    if (history.empty()) return "unknown";
    return history[0].substr(0, std::min(history[0].size(), size_t(100)));
}

std::vector<std::string> IntentCompression::ExtractBlockers(const std::vector<std::string>& history) const {
    std::vector<std::string> blockers;
    for (const auto& h : history) {
        if (h.find("blocked") != std::string::npos || 
            h.find("waiting") != std::string::npos ||
            h.find("stuck") != std::string::npos) {
            blockers.push_back(h);
        }
    }
    return blockers;
}

std::string IntentCompression::ExtractNextAction(const std::vector<std::string>& history) const {
    if (history.empty()) return "analyze";
    return "continue";
}

float IntentCompression::EstimateProgress(const std::vector<std::string>& history) const {
    if (history.empty()) return 0.0f;
    return std::min(1.0f, history.size() / 20.0f);
}

size_t IntentCompression::EstimateTokens(const CompactState& state) const {
    size_t tokens = state.goal.size() / 4;
    tokens += state.currentState.size() / 4;
    tokens += state.nextAction.size() / 4;
    for (const auto& b : state.blockers) tokens += b.size() / 4;
    return tokens;
}

size_t IntentCompression::EstimateTokens(const std::vector<std::string>& history) const {
    size_t tokens = 0;
    for (const auto& h : history) tokens += h.size() / 4;
    return tokens;
}

double IntentCompression::CompressionRatio(const std::vector<std::string>& history, const CompactState& state) const {
    size_t original = EstimateTokens(history);
    size_t compressed = EstimateTokens(state);
    return original > 0 ? (double)original / compressed : 1.0;
}

std::string IntentCompression::Serialize(const CompactState& state) {
    std::stringstream ss;
    ss << state.goal << "|" << state.currentState << "|" << state.nextAction << "|" << state.progress;
    return ss.str();
}

CompactState IntentCompression::Deserialize(const std::string& data) {
    CompactState state;
    std::stringstream ss(data);
    std::getline(ss, state.goal, '|');
    std::getline(ss, state.currentState, '|');
    std::getline(ss, state.nextAction, '|');
    std::string progress;
    std::getline(ss, progress, '|');
    state.progress = std::stof(progress);
    return state;
}

} // namespace Sovereign
