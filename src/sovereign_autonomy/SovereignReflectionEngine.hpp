/**
 * @file SovereignReflectionEngine.hpp
 * @brief Post-execution reflection and learning system
 *
 * Analyzes mission outcomes, extracts lessons, and updates
 * the knowledge graph and blackboard for future missions.
 */

#pragma once

#include "SovereignBlackboard.hpp"
#include "SovereignTaskGraph.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD::Autonomy {

struct Reflection {
    std::string mission_id;
    std::string observation;      // What happened?
    std::string analysis;           // Why did it happen?
    std::string lesson;             // What should we remember?
    std::string recommendation;     // What to do differently?
    float confidence = 0.0f;        // How sure are we?
    bool actionable = false;        // Can we act on this?
};

class SovereignReflectionEngine {
public:
    explicit SovereignReflectionEngine(std::shared_ptr<SovereignBlackboard> blackboard);
    ~SovereignReflectionEngine() = default;

    // Analyze a completed task
    Reflection ReflectOnTask(const TaskNode& task, const std::string& mission_context);

    // Analyze a full mission
    std::vector<Reflection> ReflectOnMission(const std::string& mission_id,
                                               const std::vector<TaskNode>& tasks);

    // Store reflection for future retrieval
    void StoreReflection(const Reflection& reflection);

    // Retrieve relevant past reflections
    std::vector<Reflection> RetrieveRelevant(const std::string& query, int max_results = 5);

    // Apply lessons to blackboard
    void ApplyLessons(const std::string& mission_id);

    // High-level: reflect and learn from a mission
    void LearnFromMission(const std::string& mission_id,
                          const std::vector<TaskNode>& tasks);

private:
    std::shared_ptr<SovereignBlackboard> blackboard_;
    mutable std::mutex mutex_;
    std::vector<Reflection> reflections_;

    std::string AnalyzeFailure(const TaskNode& task);
    std::string AnalyzeSuccess(const TaskNode& task);
    float ScoreRelevance(const Reflection& reflection, const std::string& query);
};

} // namespace RawrXD::Autonomy
