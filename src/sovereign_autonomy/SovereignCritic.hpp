/**
 * @file SovereignCritic.hpp
 * @brief Plan evaluation and quality assurance system
 *
 * The Critic reviews mission plans before execution and evaluates
 * results after completion, providing feedback for replanning.
 */

#pragma once

#include "SovereignMissionPlanner.hpp"
#include "SovereignBlackboard.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD::Autonomy {

struct CriticReview {
    std::string review_id;
    std::string mission_id;
    bool passed = false;
    float score = 0.0f;           // 0.0 - 1.0
    std::string feedback;
    std::vector<std::string> issues;
    std::vector<std::string> recommendations;
    std::string severity;         // "info", "warning", "critical"
};

class SovereignCritic {
public:
    using ReviewCallback = std::function<void(const CriticReview& review)>;

    explicit SovereignCritic(std::shared_ptr<SovereignBlackboard> blackboard);
    ~SovereignCritic() = default;

    // Pre-execution review
    CriticReview ReviewPlan(const MissionPlan& plan);

    // Post-execution review
    CriticReview ReviewResults(const MissionPlan& plan,
                                const std::vector<TaskNode>& completed_tasks);

    // Evaluate a single task
    CriticReview ReviewTask(const TaskNode& task);

    // Register custom review rules
    void AddRule(std::function<std::optional<CriticReview>(const MissionPlan&)> rule);
    void AddTaskRule(std::function<std::optional<CriticReview>(const TaskNode&)> rule);

    // Batch review
    std::vector<CriticReview> ReviewAll(const std::vector<MissionPlan>& plans);

    // Subscriptions
    void OnReviewComplete(ReviewCallback cb) { on_review_ = std::move(cb); }

private:
    std::shared_ptr<SovereignBlackboard> blackboard_;
    mutable std::mutex mutex_;
    std::vector<std::function<std::optional<CriticReview>(const MissionPlan&)>> plan_rules_;
    std::vector<std::function<std::optional<CriticReview>(const TaskNode&)>> task_rules_;
    ReviewCallback on_review_;

    static int64_t s_review_counter;

    CriticReview BuildDefaultPlanReview(const MissionPlan& plan);
    CriticReview BuildDefaultTaskReview(const TaskNode& task);
    float ScorePlanQuality(const MissionPlan& plan);
    float ScoreTaskQuality(const TaskNode& task);
};

} // namespace RawrXD::Autonomy
