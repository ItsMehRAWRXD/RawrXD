/**
 * @file SovereignCritic.cpp
 * @brief Plan evaluation and quality assurance implementation
 */

#include "SovereignCritic.hpp"
#include <sstream>
#include <algorithm>

namespace RawrXD::Autonomy {

int64_t SovereignCritic::s_review_counter = 0;

SovereignCritic::SovereignCritic(std::shared_ptr<SovereignBlackboard> blackboard)
    : blackboard_(std::move(blackboard)) {}

CriticReview SovereignCritic::ReviewPlan(const MissionPlan& plan) {
    std::lock_guard<std::mutex> lock(mutex_);
    CriticReview review = BuildDefaultPlanReview(plan);

    for (const auto& rule : plan_rules_) {
        auto result = rule(plan);
        if (result.has_value()) {
            review.issues.push_back(result->feedback);
            review.score = std::min(review.score, result->score);
            if (result->severity == "critical") review.passed = false;
        }
    }

    review.score = ScorePlanQuality(plan);
    review.passed = review.score >= 0.6f && review.issues.empty();

    blackboard_->WriteString("review." + review.review_id + ".feedback", review.feedback, "critic");
    blackboard_->WriteFloat("review." + review.review_id + ".score", review.score, "critic");

    if (on_review_) on_review_(review);
    return review;
}

CriticReview SovereignCritic::ReviewResults(const MissionPlan& plan,
                                             const std::vector<TaskNode>& completed_tasks) {
    std::lock_guard<std::mutex> lock(mutex_);
    CriticReview review;
    review.review_id = "review_" + std::to_string(++s_review_counter);
    review.mission_id = plan.mission_id;

    size_t success_count = 0;
    size_t total = completed_tasks.size();
    for (const auto& task : completed_tasks) {
        if (task.state == TaskState::Completed) ++success_count;
    }

    review.score = (total > 0) ? static_cast<float>(success_count) / static_cast<float>(total) : 0.0f;
    review.passed = review.score >= 0.8f;

    std::ostringstream oss;
    oss << "Mission '" << plan.name << "': " << success_count << "/" << total << " tasks succeeded.";
    review.feedback = oss.str();

    if (review.score < 1.0f) {
        review.severity = "warning";
        review.recommendations.push_back("Review failed tasks for retry or replanning.");
    } else {
        review.severity = "info";
    }

    blackboard_->WriteString("review." + review.review_id + ".feedback", review.feedback, "critic");
    blackboard_->WriteFloat("review." + review.review_id + ".score", review.score, "critic");

    if (on_review_) on_review_(review);
    return review;
}

CriticReview SovereignCritic::ReviewTask(const TaskNode& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    CriticReview review = BuildDefaultTaskReview(task);

    for (const auto& rule : task_rules_) {
        auto result = rule(task);
        if (result.has_value()) {
            review.issues.push_back(result->feedback);
            review.score = std::min(review.score, result->score);
            if (result->severity == "critical") review.passed = false;
        }
    }

    review.score = ScoreTaskQuality(task);
    review.passed = task.state == TaskState::Completed && review.score >= 0.5f;

    if (on_review_) on_review_(review);
    return review;
}

void SovereignCritic::AddRule(std::function<std::optional<CriticReview>(const MissionPlan&)> rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    plan_rules_.push_back(std::move(rule));
}

void SovereignCritic::AddTaskRule(std::function<std::optional<CriticReview>(const TaskNode&)> rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    task_rules_.push_back(std::move(rule));
}

std::vector<CriticReview> SovereignCritic::ReviewAll(const std::vector<MissionPlan>& plans) {
    std::vector<CriticReview> results;
    for (const auto& plan : plans) {
        results.push_back(ReviewPlan(plan));
    }
    return results;
}

CriticReview SovereignCritic::BuildDefaultPlanReview(const MissionPlan& plan) {
    CriticReview r;
    r.review_id = "review_" + std::to_string(++s_review_counter);
    r.mission_id = plan.mission_id;
    r.score = 0.5f;
    r.passed = true;
    r.severity = "info";

    if (!plan.task_graph || plan.task_graph->TaskCount() == 0) {
        r.issues.push_back("Plan has no tasks.");
        r.passed = false;
        r.severity = "critical";
    }
    if (plan.goals.empty()) {
        r.issues.push_back("Mission has no goals.");
        r.passed = false;
        r.severity = "critical";
    }
    if (plan.replan_count >= plan.max_replans) {
        r.issues.push_back("Max replans reached; mission may be stuck.");
        r.severity = "warning";
    }

    return r;
}

CriticReview SovereignCritic::BuildDefaultTaskReview(const TaskNode& task) {
    CriticReview r;
    r.review_id = "review_" + std::to_string(++s_review_counter);
    r.mission_id = task.id; // Task ID as proxy
    r.score = 0.5f;
    r.passed = task.state == TaskState::Completed;
    r.severity = "info";

    if (task.retry_count >= task.max_retries) {
        r.issues.push_back("Task exhausted all retries.");
        r.severity = "critical";
        r.passed = false;
    }
    if (task.duration_ms.has_value() && task.duration_ms->count() > 60000) {
        r.issues.push_back("Task took over 60 seconds.");
        r.severity = "warning";
    }

    return r;
}

float SovereignCritic::ScorePlanQuality(const MissionPlan& plan) {
    float score = 0.5f;
    if (plan.task_graph && plan.task_graph->TaskCount() > 0) score += 0.2f;
    if (!plan.goals.empty()) score += 0.2f;
    if (plan.replan_count < plan.max_replans) score += 0.1f;
    return std::min(score, 1.0f);
}

float SovereignCritic::ScoreTaskQuality(const TaskNode& task) {
    if (task.state == TaskState::Completed) return 1.0f;
    if (task.state == TaskState::Failed) return 0.0f;
    if (task.state == TaskState::Cancelled) return 0.2f;
    if (task.state == TaskState::Running) return 0.5f;
    return 0.3f;
}

} // namespace RawrXD::Autonomy
