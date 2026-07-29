// ============================================================
// MultiLevelPlanner.cpp - Implementation
// ============================================================

#include "MultiLevelPlanner.hpp"
#include "ExecutiveDirector.hpp"

namespace RawrXD::Executive {

bool MultiLevelPlanner::initialize(ExecutiveDirector* director) {
    director_ = director;
    printf("[MultiLevelPlanner] Initialized\n");
    return true;
}

void MultiLevelPlanner::shutdown() {
    printf("[MultiLevelPlanner] Shutdown\n");
}

Plan MultiLevelPlanner::createStrategicPlan(const PlanningContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Plan plan;
    plan.id = nextPlanId_++;
    plan.level = PlanLevel::STRATEGIC;
    plan.objective = context.objective;
    plan.missionId = context.missionId;
    plan.createdAtMs = currentTimeMs();
    plan.deadlineMs = context.deadlineMs;
    plan.status = "draft";
    
    printf("[Planner] Strategic plan #%llu created: %s\n",
           (unsigned long long)plan.id, context.objective.c_str());
    
    plans_[plan.id] = plan;
    return plan;
}

Plan MultiLevelPlanner::createOperationalPlan(const PlanningContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Plan plan;
    plan.id = nextPlanId_++;
    plan.level = PlanLevel::OPERATIONAL;
    plan.objective = context.objective;
    plan.missionId = context.missionId;
    plan.parentPlanId = context.parentPlanId;
    plan.createdAtMs = currentTimeMs();
    plan.deadlineMs = context.deadlineMs;
    plan.status = "draft";
    
    printf("[Planner] Operational plan #%llu created: %s\n",
           (unsigned long long)plan.id, context.objective.c_str());
    
    plans_[plan.id] = plan;
    return plan;
}

Plan MultiLevelPlanner::createTacticalPlan(const PlanningContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Plan plan;
    plan.id = nextPlanId_++;
    plan.level = PlanLevel::TACTICAL;
    plan.objective = context.objective;
    plan.missionId = context.missionId;
    plan.parentPlanId = context.parentPlanId;
    plan.createdAtMs = currentTimeMs();
    plan.deadlineMs = context.deadlineMs;
    plan.status = "draft";
    
    printf("[Planner] Tactical plan #%llu created: %s\n",
           (unsigned long long)plan.id, context.objective.c_str());
    
    plans_[plan.id] = plan;
    return plan;
}

void MultiLevelPlanner::decomposeStrategicToOperational(uint64_t strategicPlanId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(strategicPlanId);
    if (it == plans_.end() || it->second.level != PlanLevel::STRATEGIC) return;
    
    // Create 2-3 operational sub-plans
    for (int i = 0; i < 3; ++i) {
        PlanningContext ctx;
        ctx.missionId = it->second.missionId;
        ctx.objective = it->second.objective + " (phase " + std::to_string(i + 1) + ")";
        ctx.level = PlanLevel::OPERATIONAL;
        ctx.parentPlanId = strategicPlanId;
        
        Plan sub = createOperationalPlan(ctx);
        it->second.subPlanIds.push_back(sub.id);
    }
    printf("[Planner] Strategic plan #%llu decomposed into %zu operational plans\n",
           (unsigned long long)strategicPlanId, it->second.subPlanIds.size());
}

void MultiLevelPlanner::decomposeOperationalToTactical(uint64_t operationalPlanId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(operationalPlanId);
    if (it == plans_.end() || it->second.level != PlanLevel::OPERATIONAL) return;
    
    // Create tactical steps
    for (int i = 0; i < 5; ++i) {
        PlanStep step;
        step.stepId = nextStepId_++;
        step.description = "Step " + std::to_string(i + 1) + " of " + it->second.objective;
        step.actionType = "invoke_agent";
        step.status = "pending";
        step.expectedSuccessRate = 0.8f;
        it->second.steps.push_back(step);
    }
    printf("[Planner] Operational plan #%llu decomposed into %zu tactical steps\n",
           (unsigned long long)operationalPlanId, it->second.steps.size());
}

void MultiLevelPlanner::startPlan(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it != plans_.end()) {
        it->second.status = "executing";
        it->second.startedAtMs = currentTimeMs();
        printf("[Planner] Plan #%llu STARTED\n", (unsigned long long)planId);
    }
}

void MultiLevelPlanner::updateStepStatus(uint64_t planId, uint64_t stepId, 
                                          const std::string& status, float progress) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return;
    
    for (auto& step : it->second.steps) {
        if (step.stepId == stepId) {
            step.status = status;
            step.progress = progress;
            break;
        }
    }
    
    // Recalculate overall progress
    if (!it->second.steps.empty()) {
        float totalProgress = 0.0f;
        for (const auto& step : it->second.steps) {
            totalProgress += step.progress;
        }
        it->second.overallProgress = totalProgress / it->second.steps.size();
    }
}

void MultiLevelPlanner::completePlan(uint64_t planId, bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it != plans_.end()) {
        it->second.status = success ? "completed" : "failed";
        it->second.completedAtMs = currentTimeMs();
        if (it->second.startedAtMs > 0) {
            it->second.actualDurationMs = static_cast<double>(
                it->second.completedAtMs - it->second.startedAtMs);
        }
        printf("[Planner] Plan #%llu %s\n", 
               (unsigned long long)planId, success ? "COMPLETED" : "FAILED");
    }
}

bool MultiLevelPlanner::shouldReplan(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return false;
    
    // Replan if failed steps > 30%
    size_t failedSteps = 0;
    for (const auto& step : it->second.steps) {
        if (step.status == "failed") failedSteps++;
    }
    if (!it->second.steps.empty() && 
        static_cast<float>(failedSteps) / it->second.steps.size() > 0.3f) {
        return true;
    }
    
    // Replan if deadline approaching and not on track
    if (it->second.deadlineMs > 0) {
        uint64_t now = currentTimeMs();
        if (now > it->second.deadlineMs && it->second.overallProgress < 1.0f) {
            return true;
        }
    }
    
    return false;
}

ReplanTrigger MultiLevelPlanner::detectReplanNeed(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    ReplanTrigger trigger;
    trigger.affectedPlanId = planId;
    
    auto it = plans_.find(planId);
    if (it == plans_.end()) {
        trigger.triggerType = "not_found";
        trigger.description = "Plan not found";
        trigger.severity = 0.0f;
        return trigger;
    }
    
    size_t failedSteps = 0;
    for (const auto& step : it->second.steps) {
        if (step.status == "failed") failedSteps++;
    }
    
    if (!it->second.steps.empty() && 
        static_cast<float>(failedSteps) / it->second.steps.size() > 0.3f) {
        trigger.triggerType = "failure";
        trigger.description = "Too many failed steps";
        trigger.severity = 0.8f;
    } else if (it->second.deadlineMs > 0 && currentTimeMs() > it->second.deadlineMs) {
        trigger.triggerType = "deadline";
        trigger.description = "Deadline exceeded";
        trigger.severity = 1.0f;
    } else {
        trigger.triggerType = "none";
        trigger.description = "No replan needed";
        trigger.severity = 0.0f;
    }
    
    return trigger;
}

Plan MultiLevelPlanner::replan(uint64_t planId, const ReplanTrigger& trigger) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return Plan{};
    
    printf("[Planner] Replanning #%llu due to %s\n",
           (unsigned long long)planId, trigger.triggerType.c_str());
    
    // Create new plan based on old one
    Plan newPlan = it->second;
    newPlan.id = nextPlanId_++;
    newPlan.status = "draft";
    newPlan.overallProgress = 0.0f;
    newPlan.createdAtMs = currentTimeMs();
    
    // Reset failed steps
    for (auto& step : newPlan.steps) {
        if (step.status == "failed") {
            step.status = "pending";
            step.progress = 0.0f;
        }
    }
    
    plans_[newPlan.id] = newPlan;
    return newPlan;
}

std::optional<Plan> MultiLevelPlanner::getPlan(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it != plans_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Plan> MultiLevelPlanner::getActivePlans() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Plan> results;
    for (const auto& [id, plan] : plans_) {
        if (plan.status == "executing") {
            results.push_back(plan);
        }
    }
    return results;
}

std::vector<Plan> MultiLevelPlanner::getPlansForMission(uint64_t missionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Plan> results;
    for (const auto& [id, plan] : plans_) {
        if (plan.missionId == missionId) {
            results.push_back(plan);
        }
    }
    return results;
}

void MultiLevelPlanner::optimizePlan(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return;
    
    // Simple optimization: sort steps by expected success rate
    std::sort(it->second.steps.begin(), it->second.steps.end(),
        [](const PlanStep& a, const PlanStep& b) {
            return a.expectedSuccessRate > b.expectedSuccessRate;
        });
    printf("[Planner] Plan #%llu optimized\n", (unsigned long long)planId);
}

void MultiLevelPlanner::parallelizeSteps(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return;
    
    // Mark independent steps as ready to run in parallel
    for (auto& step : it->second.steps) {
        if (step.dependsOn.empty() && step.status == "pending") {
            step.status = "ready";
        }
    }
    printf("[Planner] Plan #%llu parallelized\n", (unsigned long long)planId);
}

void MultiLevelPlanner::pruneUnnecessarySteps(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return;
    
    // Remove steps with very low expected success rate
    auto newEnd = std::remove_if(it->second.steps.begin(), it->second.steps.end(),
        [](const PlanStep& step) {
            return step.expectedSuccessRate < 0.2f && step.status == "pending";
        });
    size_t removed = std::distance(newEnd, it->second.steps.end());
    it->second.steps.erase(newEnd, it->second.steps.end());
    
    if (removed > 0) {
        printf("[Planner] Plan #%llu pruned %zu low-confidence steps\n",
               (unsigned long long)planId, removed);
    }
}

void MultiLevelPlanner::learnFromPlanExecution(uint64_t planId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return;
    
    // Update expected durations based on actuals
    for (auto& step : it->second.steps) {
        if (step.actualDurationMs > 0) {
            step.estimatedDurationMs = step.actualDurationMs * 0.7 + 
                                       step.estimatedDurationMs * 0.3;
        }
    }
    printf("[Planner] Learned from plan #%llu execution\n", (unsigned long long)planId);
}

std::vector<std::string> MultiLevelPlanner::suggestPlanImprovements(uint64_t planId) {
    std::vector<std::string> suggestions;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = plans_.find(planId);
    if (it == plans_.end()) return suggestions;
    
    // Suggest based on failed steps
    for (const auto& step : it->second.steps) {
        if (step.status == "failed") {
            suggestions.push_back("Retry step " + std::to_string(step.stepId) + 
                                 " with different parameters");
        }
    }
    
    // Suggest based on duration
    if (it->second.actualDurationMs > it->second.estimatedTotalDurationMs * 1.5) {
        suggestions.push_back("Plan took 50% longer than estimated — review step durations");
    }
    
    return suggestions;
}

uint64_t MultiLevelPlanner::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace RawrXD::Executive
