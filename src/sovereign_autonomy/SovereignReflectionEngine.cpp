/**
 * @file SovereignReflectionEngine.cpp
 * @brief Reflection and learning implementation
 */

#include "SovereignReflectionEngine.hpp"
#include <sstream>
#include <algorithm>

namespace RawrXD::Autonomy {

SovereignReflectionEngine::SovereignReflectionEngine(std::shared_ptr<SovereignBlackboard> blackboard)
    : blackboard_(std::move(blackboard)) {}

Reflection SovereignReflectionEngine::ReflectOnTask(const TaskNode& task, const std::string& mission_context) {
    Reflection r;
    r.mission_id = mission_context;
    r.observation = "Task '" + task.description + "' ended with state " + std::to_string(static_cast<int>(task.state));

    if (task.state == TaskState::Completed) {
        r.analysis = AnalyzeSuccess(task);
        r.lesson = "Approach succeeded; consider reusing for similar tasks.";
        r.recommendation = "No change needed.";
        r.confidence = 0.9f;
        r.actionable = false;
    } else if (task.state == TaskState::Failed) {
        r.analysis = AnalyzeFailure(task);
        r.lesson = "Failure pattern detected: " + task.error_message;
        r.recommendation = "Retry with adjusted parameters or different agent.";
        r.confidence = 0.7f;
        r.actionable = true;
    } else {
        r.analysis = "Task did not reach terminal state.";
        r.lesson = "Monitor for timeout or cancellation.";
        r.recommendation = "Check resource allocation.";
        r.confidence = 0.5f;
        r.actionable = true;
    }

    return r;
}

std::vector<Reflection> SovereignReflectionEngine::ReflectOnMission(const std::string& mission_id,
                                                                    const std::vector<TaskNode>& tasks) {
    std::vector<Reflection> results;
    for (const auto& task : tasks) {
        results.push_back(ReflectOnTask(task, mission_id));
    }
    return results;
}

void SovereignReflectionEngine::StoreReflection(const Reflection& reflection) {
    std::lock_guard<std::mutex> lock(mutex_);
    reflections_.push_back(reflection);

    // Write to blackboard for cross-mission access
    std::string key = "reflection." + reflection.mission_id + "." + std::to_string(reflections_.size());
    blackboard_->WriteString(key + ".observation", reflection.observation, "reflection");
    blackboard_->WriteString(key + ".analysis", reflection.analysis, "reflection");
    blackboard_->WriteString(key + ".lesson", reflection.lesson, "reflection");
    blackboard_->WriteString(key + ".recommendation", reflection.recommendation, "reflection");
    blackboard_->WriteFloat(key + ".confidence", reflection.confidence, "reflection");
}

std::vector<Reflection> SovereignReflectionEngine::RetrieveRelevant(const std::string& query, int max_results) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<Reflection, float>> scored;
    for (const auto& r : reflections_) {
        scored.push_back({r, ScoreRelevance(r, query)});
    }
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    std::vector<Reflection> results;
    for (int i = 0; i < max_results && i < static_cast<int>(scored.size()); ++i) {
        results.push_back(scored[i].first);
    }
    return results;
}

void SovereignReflectionEngine::ApplyLessons(const std::string& mission_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : reflections_) {
        if (r.mission_id == mission_id && r.actionable) {
            // Write actionable lessons to blackboard for planner to pick up
            blackboard_->WriteString("lesson." + r.lesson, r.recommendation, "reflection", 1);
        }
    }
}

void SovereignReflectionEngine::LearnFromMission(const std::string& mission_id,
                                                   const std::vector<TaskNode>& tasks) {
    auto reflections = ReflectOnMission(mission_id, tasks);
    for (const auto& r : reflections) {
        StoreReflection(r);
    }
    ApplyLessons(mission_id);
}

std::string SovereignReflectionEngine::AnalyzeFailure(const TaskNode& task) {
    std::ostringstream oss;
    oss << "Task '" << task.description << "' failed after " << task.retry_count << " retries.";
    if (!task.error_message.empty()) {
        oss << " Error: " << task.error_message;
    }
    return oss.str();
}

std::string SovereignReflectionEngine::AnalyzeSuccess(const TaskNode& task) {
    std::ostringstream oss;
    oss << "Task '" << task.description << "' completed successfully.";
    if (task.duration_ms.has_value()) {
        oss << " Duration: " << task.duration_ms->count() << "ms.";
    }
    return oss.str();
}

float SovereignReflectionEngine::ScoreRelevance(const Reflection& reflection, const std::string& query) {
    // Simple keyword overlap scoring
    float score = 0.0f;
    auto count_matches = [](const std::string& text, const std::string& q) -> float {
        float matches = 0.0f;
        size_t pos = 0;
        while ((pos = text.find(q, pos)) != std::string::npos) {
            ++matches;
            ++pos;
        }
        return matches;
    };
    score += count_matches(reflection.observation, query) * 1.0f;
    score += count_matches(reflection.analysis, query) * 2.0f;
    score += count_matches(reflection.lesson, query) * 3.0f;
    score *= reflection.confidence;
    return score;
}

} // namespace RawrXD::Autonomy
