// ============================================================================
// GenerationCore.cpp — Handwritten generation pipeline implementation
// ============================================================================
#include "GenerationCore.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace rawrxd::generation {

std::string GenerationCore::makeId(const std::string& prefix) {
    int n = receiptCounter_.fetch_add(1, std::memory_order_relaxed);
    std::ostringstream oss;
    oss << prefix << "-" << std::hex << n;
    return oss.str();
}

Intent GenerationCore::ingestIntent(const std::string& description,
                                     const std::string& category) {
    Intent intent;
    intent.description = description;
    intent.category = category;
    return intent;
}

Goal GenerationCore::decomposeGoal(const Intent& intent) {
    Goal goal;
    goal.id = makeId("goal");
    goal.description = intent.description;

    // Simple decomposition: if description contains "and", split into subgoals
    std::string desc = intent.description;
    std::string delim = " and ";
    size_t pos = 0;
    std::string token;
    while ((pos = desc.find(delim)) != std::string::npos) {
        token = desc.substr(0, pos);
        goal.subGoals.push_back(token);
        desc = desc.substr(pos + delim.length());
    }
    if (!desc.empty()) goal.subGoals.push_back(desc);

    goal.priority = 0;
    goal.achievable = !goal.subGoals.empty();
    return goal;
}

Plan GenerationCore::planGoal(const Goal& goal) {
    Plan plan;
    if (!goal.achievable) {
        plan.valid = false;
        plan.failureReason = "Goal not achievable: " + goal.description;
        return plan;
    }

    // Create one step per subgoal
    for (size_t i = 0; i < goal.subGoals.size(); ++i) {
        PlanStep step;
        step.action = "execute";
        step.input = goal.subGoals[i];
        step.expectedOutput = "result:" + goal.subGoals[i];
        if (i > 0) step.dependsOn.push_back(i - 1);
        plan.steps.push_back(step);
    }
    plan.valid = !plan.steps.empty();
    return plan;
}

Candidate GenerationCore::executePlan(const Plan& plan, const Goal& goal,
                                       const std::string& generatedContent) {
    Candidate candidate;
    candidate.id = makeId("candidate");
    candidate.goalId = goal.id;
    candidate.content = generatedContent;
    candidate.createdAt = std::chrono::steady_clock::now();

    // Confidence: based on plan validity and step count
    if (plan.valid) {
        candidate.confidence = 1.0 / (1.0 + plan.steps.size() * 0.1);
    }
    candidate.evidence.push_back("plan_valid=" + std::string(plan.valid ? "true" : "false"));
    candidate.evidence.push_back("plan_steps=" + std::to_string(plan.steps.size()));
    return candidate;
}

GenerationReceipt GenerationCore::produceReceipt(
    const Intent& intent, const Goal& goal, const Plan& plan,
    const Candidate& candidate) {

    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - candidate.createdAt).count();

    GenerationReceipt receipt;
    receipt.receiptId = makeId("gen-receipt");
    receipt.intentDescription = intent.description;
    receipt.goalId = goal.id;
    receipt.candidateId = candidate.id;
    receipt.candidateContent = candidate.content;
    receipt.confidence = candidate.confidence;
    receipt.planSteps = static_cast<int>(plan.steps.size());
    receipt.durationMs = static_cast<uint64_t>(duration);
    receipt.evidence = candidate.evidence;
    receipt.valid = plan.valid && goal.achievable && !candidate.content.empty();

    // Timestamp
    auto t = std::chrono::system_clock::now();
    auto t_time = std::chrono::system_clock::to_time_t(t);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&t_time), "%Y-%m-%dT%H:%M:%SZ");
    receipt.timestamp = ts.str();

    return receipt;
}

GenerationReceipt GenerationCore::generate(const std::string& description,
                                            const std::string& category,
                                            const std::string& generatedContent) {
    totalGen_.fetch_add(1, std::memory_order_relaxed);

    auto intent = ingestIntent(description, category);
    auto goal = decomposeGoal(intent);
    auto plan = planGoal(goal);
    auto candidate = executePlan(plan, goal, generatedContent);
    auto receipt = produceReceipt(intent, goal, plan, candidate);

    if (receipt.valid) {
        successGen_.fetch_add(1, std::memory_order_relaxed);
    }
    return receipt;
}

} // namespace rawrxd::generation