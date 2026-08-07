#include "planner_agent.hpp"
#include <iostream>
#include <algorithm>
#include <cctype>

namespace rawrxd {
namespace agent {

PlannerAgent::PlannerAgent() = default;
PlannerAgent::~PlannerAgent() = default;

bool PlannerAgent::initialize() {
    std::cout << "[PlannerAgent] Initialized" << std::endl;
    return true;
}

AgentPlan PlannerAgent::generatePlan(const TaskRequest& request) {
    AgentPlan plan;
    plan.valid = true;
    plan.description = "Plan for: " + request.goal;

    // Convert goal to lowercase for keyword matching
    std::string lowerGoal = request.goal;
    std::transform(lowerGoal.begin(), lowerGoal.end(), lowerGoal.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Determine plan steps based on task type
    if (request.requires_code || lowerGoal.find("implement") != std::string::npos ||
        lowerGoal.find("write") != std::string::npos || lowerGoal.find("create") != std::string::npos ||
        lowerGoal.find("add") != std::string::npos || lowerGoal.find("feature") != std::string::npos) {
        
        plan.reasoning = "Code generation task detected. Will implement the requested feature.";
        plan.steps.push_back({"read_context", request.target_file, "Read existing code context", {}});
        plan.steps.push_back({"generate_code", request.target_file, "Generate implementation", {"read_context"}});
        plan.steps.push_back({"apply_patch", request.target_file, "Apply code changes", {"generate_code"}});
        plan.steps.push_back({"verify_build", request.target_file, "Verify build compiles", {"apply_patch"}});
    } 
    else if (request.requires_reasoning || lowerGoal.find("explain") != std::string::npos ||
             lowerGoal.find("why") != std::string::npos || lowerGoal.find("analyze") != std::string::npos) {
        
        plan.reasoning = "Analysis task detected. Will analyze and explain.";
        plan.steps.push_back({"read_context", request.target_file, "Read relevant files", {}});
        plan.steps.push_back({"analyze", request.target_file, "Analyze the codebase", {"read_context"}});
        plan.steps.push_back({"generate_explanation", "", "Generate explanation", {"analyze"}});
    }
    else if (lowerGoal.find("fix") != std::string::npos || lowerGoal.find("bug") != std::string::npos ||
             lowerGoal.find("error") != std::string::npos || lowerGoal.find("repair") != std::string::npos) {
        
        plan.reasoning = "Bug fix task detected. Will diagnose and repair.";
        plan.steps.push_back({"read_context", request.target_file, "Read failing code", {}});
        plan.steps.push_back({"diagnose", request.target_file, "Diagnose the issue", {"read_context"}});
        plan.steps.push_back({"generate_fix", request.target_file, "Generate fix", {"diagnose"}});
        plan.steps.push_back({"apply_patch", request.target_file, "Apply the fix", {"generate_fix"}});
        plan.steps.push_back({"verify_build", request.target_file, "Verify fix compiles", {"apply_patch"}});
    }
    else {
        // Default plan for general tasks
        plan.reasoning = "General task. Will process step by step.";
        plan.steps.push_back({"read_context", request.target_file, "Gather context", {}});
        plan.steps.push_back({"process", request.target_file, "Process the request", {"read_context"}});
        plan.steps.push_back({"verify", request.target_file, "Verify the result", {"process"}});
    }

    std::cout << "[PlannerAgent] Generated plan with " << plan.steps.size() << " steps" << std::endl;
    return plan;
}

} // namespace agent
} // namespace rawrxd
