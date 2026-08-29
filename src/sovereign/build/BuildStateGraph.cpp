// BuildStateGraph.cpp
// Implementation of the build state graph

#include "BuildStateGraph.hpp"
#include <algorithm>
#include <fstream>
#include "../../lora/json/json.h"

namespace Sovereign {

BuildStateGraph::BuildStateGraph() 
    : current_state_(BuildState::IDLE)
    , build_active_(false)
    , subscription_counter_(0) {
    metrics_ = {};
}

BuildStateGraph::~BuildStateGraph() = default;

bool BuildStateGraph::TransitionTo(BuildState new_state, const std::string& trigger, const std::string& actor) {
    if (!IsValidTransition(current_state_, new_state)) {
        return false;
    }
    
    StateTransition transition;
    transition.from = current_state_;
    transition.to = new_state;
    transition.trigger = trigger;
    transition.actor = actor;
    transition.timestamp = std::chrono::steady_clock::now();
    
    transitions_.push_back(transition);
    current_state_ = new_state;
    
    // Track build lifecycle
    if (new_state == BuildState::COMPILING && !build_active_) {
        build_active_ = true;
        build_start_time_ = std::chrono::steady_clock::now();
    }
    
    if (IsTerminalState() && build_active_) {
        build_active_ = false;
    }
    
    UpdateMetrics(transition);
    
    BuildEvent event;
    event.type = BuildEventType::STATE_CHANGED;
    event.timestamp = transition.timestamp;
    event.data = transition;
    EmitEvent(event);
    
    return true;
}

bool BuildStateGraph::IsTerminalState() const {
    return current_state_ == BuildState::SUCCEEDED ||
           current_state_ == BuildState::FAILED ||
           current_state_ == BuildState::CANCELLED;
}

bool BuildStateGraph::CanTransitionTo(BuildState state) const {
    return IsValidTransition(current_state_, state);
}

std::vector<BuildState> BuildStateGraph::GetValidTransitions() const {
    std::vector<BuildState> valid;
    BuildState states[] = {
        BuildState::IDLE, BuildState::CONFIGURING, BuildState::GENERATING,
        BuildState::COMPILING, BuildState::LINKING, BuildState::PACKAGING,
        BuildState::VERIFYING, BuildState::SUCCEEDED, BuildState::FAILED,
        BuildState::CANCELLED, BuildState::RECOVERING
    };
    
    for (auto state : states) {
        if (IsValidTransition(current_state_, state)) {
            valid.push_back(state);
        }
    }
    return valid;
}

std::vector<StateTransition> BuildStateGraph::GetTransitionHistory(size_t limit) const {
    if (limit >= transitions_.size()) {
        return transitions_;
    }
    return std::vector<StateTransition>(
        transitions_.end() - limit, 
        transitions_.end()
    );
}

std::optional<StateTransition> BuildStateGraph::GetLastTransition() const {
    if (transitions_.empty()) {
        return std::nullopt;
    }
    return transitions_.back();
}

std::optional<StateTransition> BuildStateGraph::FindTransitionTo(BuildState state) const {
    for (auto it = transitions_.rbegin(); it != transitions_.rend(); ++it) {
        if (it->to == state) {
            return *it;
        }
    }
    return std::nullopt;
}

void BuildStateGraph::RegisterTarget(const TargetNode& target) {
    targets_[target.name] = target;
    
    // Update dependency graph
    dependency_graph_[target.name] = target.dependencies;
}

void BuildStateGraph::UpdateTargetState(const std::string& target_name, BuildState state) {
    auto it = targets_.find(target_name);
    if (it != targets_.end()) {
        it->second.state = state;
        
        BuildEvent event;
        event.type = (state == BuildState::FAILED) ? BuildEventType::TARGET_FAILED :
                     (state == BuildState::SUCCEEDED) ? BuildEventType::TARGET_COMPLETED :
                     BuildEventType::TARGET_STARTED;
        event.timestamp = std::chrono::steady_clock::now();
        event.data = it->second;
        EmitEvent(event);
    }
}

std::optional<TargetNode> BuildStateGraph::GetTarget(const std::string& name) const {
    auto it = targets_.find(name);
    if (it != targets_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<TargetNode> BuildStateGraph::GetTargetsInState(BuildState state) const {
    std::vector<TargetNode> result;
    for (const auto& [name, target] : targets_) {
        if (target.state == state) {
            result.push_back(target);
        }
    }
    return result;
}

std::vector<TargetNode> BuildStateGraph::GetAllTargets() const {
    std::vector<TargetNode> result;
    for (const auto& [name, target] : targets_) {
        result.push_back(target);
    }
    return result;
}

void BuildStateGraph::RegisterArtifact(const ArtifactNode& artifact) {
    artifacts_[artifact.path] = artifact;
}

void BuildStateGraph::UpdateArtifactHash(const std::string& path, const std::string& hash) {
    auto it = artifacts_.find(path);
    if (it != artifacts_.end()) {
        it->second.hash = hash;
        it->second.modified = std::chrono::steady_clock::now();
    }
}

std::optional<ArtifactNode> BuildStateGraph::GetArtifact(const std::string& path) const {
    auto it = artifacts_.find(path);
    if (it != artifacts_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ArtifactNode> BuildStateGraph::GetStaleArtifacts() const {
    std::vector<ArtifactNode> result;
    // In real implementation, would compare timestamps with source files
    return result;
}

std::vector<ArtifactNode> BuildStateGraph::GetOrphanedArtifacts() const {
    std::vector<ArtifactNode> result;
    // In real implementation, would check if artifacts are still referenced
    return result;
}

std::vector<std::string> BuildStateGraph::GetDependencies(const std::string& target) const {
    auto it = dependency_graph_.find(target);
    if (it != dependency_graph_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> BuildStateGraph::GetDependents(const std::string& target) const {
    std::vector<std::string> result;
    for (const auto& [name, deps] : dependency_graph_) {
        if (std::find(deps.begin(), deps.end(), target) != deps.end()) {
            result.push_back(name);
        }
    }
    return result;
}

std::vector<std::string> BuildStateGraph::GetBuildOrder() const {
    // Topological sort
    std::vector<std::string> result;
    std::map<std::string, int> in_degree;
    
    // Calculate in-degrees
    for (const auto& [name, target] : targets_) {
        in_degree[name] = 0;
    }
    for (const auto& [name, deps] : dependency_graph_) {
        for (const auto& dep : deps) {
            if (in_degree.find(dep) != in_degree.end()) {
                in_degree[name]++;
            }
        }
    }
    
    // Kahn's algorithm
    std::vector<std::string> queue;
    for (const auto& [name, degree] : in_degree) {
        if (degree == 0) {
            queue.push_back(name);
        }
    }
    
    while (!queue.empty()) {
        std::string current = queue.back();
        queue.pop_back();
        result.push_back(current);
        
        // Find all targets that depend on current
        for (const auto& [name, deps] : dependency_graph_) {
            if (std::find(deps.begin(), deps.end(), current) != deps.end()) {
                in_degree[name]--;
                if (in_degree[name] == 0) {
                    queue.push_back(name);
                }
            }
        }
    }
    
    return result;
}

bool BuildStateGraph::HasCircularDependency() const {
    return GetBuildOrder().size() != targets_.size();
}

std::vector<std::vector<std::string>> BuildStateGraph::FindCycles() const {
    std::vector<std::vector<std::string>> cycles;
    // In real implementation, would use DFS to find cycles
    return cycles;
}

void BuildStateGraph::SetConfiguration(const BuildConfiguration& config) {
    config_ = config;
}

std::string BuildStateGraph::Subscribe(EventCallback callback) {
    std::string id = "sub_" + std::to_string(subscription_counter_++);
    subscribers_[id] = callback;
    return id;
}

void BuildStateGraph::Unsubscribe(const std::string& subscription_id) {
    subscribers_.erase(subscription_id);
}

BuildStateGraph::BuildMetrics BuildStateGraph::GetMetrics() const {
    return metrics_;
}

BuildStateGraph::CurrentBuild BuildStateGraph::GetCurrentBuild() const {
    CurrentBuild build;
    build.is_active = build_active_;
    build.state = current_state_;
    build.started = build_start_time_;
    build.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - build_start_time_
    );
    build.total_targets = targets_.size();
    build.completed_targets = GetTargetsInState(BuildState::SUCCEEDED).size();
    build.failed_targets = GetTargetsInState(BuildState::FAILED).size();
    build.progress_percent = build.total_targets > 0 
        ? (100.0 * build.completed_targets / build.total_targets) 
        : 0.0;
    return build;
}

void BuildStateGraph::Clear() {
    targets_.clear();
    artifacts_.clear();
    dependency_graph_.clear();
    transitions_.clear();
    current_state_ = BuildState::IDLE;
    build_active_ = false;
}

void BuildStateGraph::ResetMetrics() {
    metrics_ = {};
}

void BuildStateGraph::EmitEvent(const BuildEvent& event) {
    for (const auto& [id, callback] : subscribers_) {
        callback(event);
    }
}

bool BuildStateGraph::IsValidTransition(BuildState from, BuildState to) const {
    // Define valid transitions
    switch (from) {
        case BuildState::IDLE:
            return to == BuildState::CONFIGURING || to == BuildState::CANCELLED;
        case BuildState::CONFIGURING:
            return to == BuildState::GENERATING || to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::GENERATING:
            return to == BuildState::COMPILING || to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::COMPILING:
            return to == BuildState::LINKING || to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::LINKING:
            return to == BuildState::PACKAGING || to == BuildState::VERIFYING || 
                   to == BuildState::SUCCEEDED || to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::PACKAGING:
            return to == BuildState::VERIFYING || to == BuildState::SUCCEEDED || 
                   to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::VERIFYING:
            return to == BuildState::SUCCEEDED || to == BuildState::FAILED || to == BuildState::CANCELLED;
        case BuildState::FAILED:
            return to == BuildState::RECOVERING || to == BuildState::IDLE;
        case BuildState::CANCELLED:
            return to == BuildState::IDLE;
        case BuildState::SUCCEEDED:
            return to == BuildState::IDLE;
        case BuildState::RECOVERING:
            return to == BuildState::CONFIGURING || to == BuildState::FAILED || to == BuildState::IDLE;
        default:
            return false;
    }
}

void BuildStateGraph::UpdateMetrics(const StateTransition& transition) {
    if (transition.to == BuildState::SUCCEEDED) {
        metrics_.successful_builds++;
        metrics_.total_builds++;
    } else if (transition.to == BuildState::FAILED) {
        metrics_.failed_builds++;
        metrics_.total_builds++;
    } else if (transition.to == BuildState::CANCELLED) {
        metrics_.cancelled_builds++;
        metrics_.total_builds++;
    }
}

// Global instance
BuildStateGraph& GetGlobalBuildStateGraph() {
    static BuildStateGraph instance;
    return instance;
}

const char* BuildStateToString(BuildState state) {
    switch (state) {
        case BuildState::IDLE: return "IDLE";
        case BuildState::CONFIGURING: return "CONFIGURING";
        case BuildState::GENERATING: return "GENERATING";
        case BuildState::COMPILING: return "COMPILING";
        case BuildState::LINKING: return "LINKING";
        case BuildState::PACKAGING: return "PACKAGING";
        case BuildState::VERIFYING: return "VERIFYING";
        case BuildState::SUCCEEDED: return "SUCCEEDED";
        case BuildState::FAILED: return "FAILED";
        case BuildState::CANCELLED: return "CANCELLED";
        case BuildState::RECOVERING: return "RECOVERING";
        default: return "UNKNOWN";
    }
}

BuildState BuildStateFromString(const std::string& str) {
    if (str == "IDLE") return BuildState::IDLE;
    if (str == "CONFIGURING") return BuildState::CONFIGURING;
    if (str == "GENERATING") return BuildState::GENERATING;
    if (str == "COMPILING") return BuildState::COMPILING;
    if (str == "LINKING") return BuildState::LINKING;
    if (str == "PACKAGING") return BuildState::PACKAGING;
    if (str == "VERIFYING") return BuildState::VERIFYING;
    if (str == "SUCCEEDED") return BuildState::SUCCEEDED;
    if (str == "FAILED") return BuildState::FAILED;
    if (str == "CANCELLED") return BuildState::CANCELLED;
    if (str == "RECOVERING") return BuildState::RECOVERING;
    return BuildState::IDLE;
}

} // namespace Sovereign
