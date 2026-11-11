// ============================================================================
// AgentPlanner.cpp - Autonomous Task Planner Implementation
// ============================================================================

#include "AgentPlanner.hpp"
#include <algorithm>
#include <sstream>
#include <iostream>

namespace Sovereign {

AgentPlanner::AgentPlanner() = default;
AgentPlanner::~AgentPlanner() = default;

void AgentPlanner::Configure(const PlannerConfig& config) {
    config_ = config;
}

TaskPlan AgentPlanner::GeneratePlan(const std::string& goal, const std::string& workspace) {
    TaskPlan plan;
    plan.goal = goal;
    plan.workspace = workspace;
    
    // Decompose goal into steps
    plan.steps = DecomposeGoal(goal, workspace);
    
    // Analyze dependencies
    AddDependencies(plan.steps);
    
    // Detect parallelizable steps
    if (config_.enableParallelSteps) {
        DetectParallelizable(plan.steps);
    }
    
    // Estimate cost
    plan.totalEstimatedCost = EstimateCost(plan);
    
    // Analyze risks
    plan.risks = AnalyzeRisks(plan);
    
    // Check if human approval needed
    plan.requiresHumanApproval = RequiresApproval(plan);
    
    return plan;
}

TaskPlan AgentPlanner::GeneratePlanWithContext(const std::string& goal, const std::string& workspace,
                                                const std::vector<std::string>& availableTools) {
    auto plan = GeneratePlan(goal, workspace);
    
    // Filter steps to only use available tools
    plan.steps.erase(
        std::remove_if(plan.steps.begin(), plan.steps.end(),
            [&availableTools](const PlanStep& step) {
                return std::find(availableTools.begin(), availableTools.end(), step.tool) == availableTools.end();
            }),
        plan.steps.end());
    
    return plan;
}

std::vector<PlanStep> AgentPlanner::DecomposeGoal(const std::string& goal, const std::string& workspace) {
    std::string lower = goal;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    if (lower.find("audit") != std::string::npos) {
        return DecomposeAudit(workspace);
    } else if (lower.find("build") != std::string::npos) {
        return DecomposeBuild(workspace);
    } else if (lower.find("test") != std::string::npos) {
        return DecomposeTest(workspace);
    } else if (lower.find("refactor") != std::string::npos) {
        return DecomposeRefactor(workspace, goal);
    } else if (lower.find("debug") != std::string::npos || lower.find("fix") != std::string::npos) {
        return DecomposeDebug(workspace, goal);
    }
    
    // Generic decomposition
    std::vector<PlanStep> steps;
    
    PlanStep scan;
    scan.id = "1";
    scan.description = "Scan workspace";
    scan.agent = "scanner";
    scan.tool = "search_files";
    scan.input = workspace;
    steps.push_back(scan);
    
    PlanStep analyze;
    analyze.id = "2";
    analyze.description = "Analyze workspace structure";
    analyze.agent = "analyzer";
    analyze.tool = "read_file";
    analyze.input = workspace;
    analyze.dependencies.push_back("1");
    steps.push_back(analyze);
    
    return steps;
}

std::vector<PlanStep> AgentPlanner::DecomposeAudit(const std::string& workspace) {
    std::vector<PlanStep> steps;
    int id = 1;
    
    // Step 1: Scan filesystem
    PlanStep scan;
    scan.id = std::to_string(id++);
    scan.description = "Scan workspace filesystem";
    scan.agent = "scanner";
    scan.tool = "search_files";
    scan.input = workspace;
    steps.push_back(scan);
    
    // Step 2: Read build configuration
    PlanStep buildConfig;
    buildConfig.id = std::to_string(id++);
    buildConfig.description = "Read build configuration";
    buildConfig.agent = "analyzer";
    buildConfig.tool = "read_file";
    buildConfig.input = workspace + "/CMakeLists.txt";
    buildConfig.dependencies.push_back("1");
    steps.push_back(buildConfig);
    
    // Step 3: Analyze source structure
    PlanStep source;
    source.id = std::to_string(id++);
    source.description = "Analyze source file structure";
    source.agent = "analyzer";
    source.tool = "search_files";
    source.input = workspace + "/src";
    source.dependencies.push_back("1");
    steps.push_back(source);
    
    // Step 4: Check git status
    PlanStep git;
    git.id = std::to_string(id++);
    git.description = "Check git repository status";
    git.agent = "git";
    git.tool = "git_status";
    git.input = workspace;
    git.dependencies.push_back("1");
    steps.push_back(git);
    
    // Step 5: Check for issues
    PlanStep issues;
    issues.id = std::to_string(id++);
    issues.description = "Check for common issues";
    issues.agent = "reviewer";
    issues.tool = "grep_search";
    issues.input = "TODO|FIXME|HACK|XXX";
    issues.dependencies.push_back("3");
    steps.push_back(issues);
    
    // Step 6: Generate report
    PlanStep report;
    report.id = std::to_string(id++);
    report.description = "Generate audit report";
    report.agent = "reporter";
    report.tool = "write_file";
    report.input = workspace + "/AUDIT_REPORT.md";
    report.dependencies.push_back("2");
    report.dependencies.push_back("4");
    report.dependencies.push_back("5");
    steps.push_back(report);
    
    return steps;
}

std::vector<PlanStep> AgentPlanner::DecomposeBuild(const std::string& workspace) {
    std::vector<PlanStep> steps;
    int id = 1;
    
    PlanStep check;
    check.id = std::to_string(id++);
    check.description = "Check build system";
    check.agent = "builder";
    check.tool = "read_file";
    check.input = workspace + "/CMakeLists.txt";
    steps.push_back(check);
    
    PlanStep build;
    build.id = std::to_string(id++);
    build.description = "Execute build";
    build.agent = "builder";
    build.tool = "terminal";
    build.input = "cd " + workspace + " && cmake --build build";
    build.dependencies.push_back("1");
    build.requiresApproval = true;
    steps.push_back(build);
    
    PlanStep verify;
    verify.id = std::to_string(id++);
    verify.description = "Verify build output";
    verify.agent = "builder";
    verify.tool = "search_files";
    verify.input = workspace + "/build/bin";
    verify.dependencies.push_back("2");
    steps.push_back(verify);
    
    return steps;
}

std::vector<PlanStep> AgentPlanner::DecomposeTest(const std::string& workspace) {
    std::vector<PlanStep> steps;
    int id = 1;
    
    PlanStep build;
    build.id = std::to_string(id++);
    build.description = "Build project";
    build.agent = "builder";
    build.tool = "terminal";
    build.input = "cd " + workspace + " && cmake --build build";
    steps.push_back(build);
    
    PlanStep test;
    test.id = std::to_string(id++);
    test.description = "Run tests";
    test.agent = "tester";
    test.tool = "terminal";
    test.input = "cd " + workspace + " && ctest --output-on-failure";
    test.dependencies.push_back("1");
    steps.push_back(test);
    
    PlanStep report;
    report.id = std::to_string(id++);
    report.description = "Report test results";
    report.agent = "reporter";
    report.tool = "write_file";
    report.input = workspace + "/TEST_REPORT.md";
    report.dependencies.push_back("2");
    steps.push_back(report);
    
    return steps;
}

std::vector<PlanStep> AgentPlanner::DecomposeRefactor(const std::string& workspace, const std::string& target) {
    std::vector<PlanStep> steps;
    int id = 1;
    
    PlanStep analyze;
    analyze.id = std::to_string(id++);
    analyze.description = "Analyze target code";
    analyze.agent = "analyzer";
    analyze.tool = "read_file";
    analyze.input = target;
    steps.push_back(analyze);
    
    PlanStep findRefs;
    findRefs.id = std::to_string(id++);
    findRefs.description = "Find all references";
    findRefs.agent = "analyzer";
    findRefs.tool = "grep_search";
    findRefs.input = target;
    findRefs.dependencies.push_back("1");
    steps.push_back(findRefs);
    
    PlanStep plan;
    plan.id = std::to_string(id++);
    plan.description = "Create refactoring plan";
    plan.agent = "planner";
    plan.tool = "write_file";
    plan.input = workspace + "/REFACTOR_PLAN.md";
    plan.dependencies.push_back("2");
    plan.requiresApproval = true;
    steps.push_back(plan);
    
    return steps;
}

std::vector<PlanStep> AgentPlanner::DecomposeDebug(const std::string& workspace, const std::string& issue) {
    std::vector<PlanStep> steps;
    int id = 1;
    
    PlanStep reproduce;
    reproduce.id = std::to_string(id++);
    reproduce.description = "Reproduce issue";
    reproduce.agent = "debugger";
    reproduce.tool = "terminal";
    reproduce.input = issue;
    steps.push_back(reproduce);
    
    PlanStep analyze;
    analyze.id = std::to_string(id++);
    analyze.description = "Analyze error output";
    analyze.agent = "debugger";
    analyze.tool = "grep_search";
    analyze.input = "error|ERROR|Error|failed|FAILED";
    analyze.dependencies.push_back("1");
    steps.push_back(analyze);
    
    PlanStep fix;
    fix.id = std::to_string(id++);
    fix.description = "Generate fix";
    fix.agent = "debugger";
    fix.tool = "write_file";
    fix.input = workspace + "/FIX.md";
    fix.dependencies.push_back("2");
    fix.requiresApproval = true;
    steps.push_back(fix);
    
    return steps;
}

void AgentPlanner::AddDependencies(std::vector<PlanStep>& steps) {
    // Ensure sequential ordering for steps without explicit dependencies
    std::string lastId;
    for (auto& step : steps) {
        if (step.dependencies.empty() && !lastId.empty()) {
            step.dependencies.push_back(lastId);
        }
        lastId = step.id;
    }
}

void AgentPlanner::DetectParallelizable(std::vector<PlanStep>& steps) {
    // Group independent steps
    for (size_t i = 0; i < steps.size(); ++i) {
        for (size_t j = i + 1; j < steps.size(); ++j) {
            bool independent = true;
            for (const auto& dep : steps[j].dependencies) {
                if (dep == steps[i].id) {
                    independent = false;
                    break;
                }
            }
            // If independent, they can run in parallel
        }
    }
}

std::vector<std::string> AgentPlanner::AnalyzeRisks(const TaskPlan& plan) {
    std::vector<std::string> risks;
    
    for (const auto& step : plan.steps) {
        if (step.tool == "write_file" || step.tool == "terminal") {
            risks.push_back("Step " + step.id + " modifies files or executes commands");
        }
        if (step.requiresApproval) {
            risks.push_back("Step " + step.id + " requires human approval");
        }
    }
    
    return risks;
}

int AgentPlanner::EstimateCost(const TaskPlan& plan) {
    int cost = 0;
    for (const auto& step : plan.steps) {
        cost += step.estimatedCost > 0 ? step.estimatedCost : 10;
    }
    return cost;
}

bool AgentPlanner::RequiresApproval(const TaskPlan& plan) {
    for (const auto& step : plan.steps) {
        if (step.requiresApproval) return true;
        if (config_.requireApprovalForWrite && step.tool == "write_file") return true;
        if (config_.requireApprovalForExecute && step.tool == "terminal") return true;
    }
    return false;
}

bool AgentPlanner::ValidatePlan(const TaskPlan& plan) {
    return GetValidationErrors(plan).empty();
}

std::vector<std::string> AgentPlanner::GetValidationErrors(const TaskPlan& plan) {
    std::vector<std::string> errors;
    
    if (plan.steps.empty()) {
        errors.push_back("Plan has no steps");
    }
    if (plan.steps.size() > config_.maxSteps) {
        errors.push_back("Plan exceeds maximum steps");
    }
    if (plan.totalEstimatedCost > config_.maxCost) {
        errors.push_back("Plan exceeds maximum cost");
    }
    
    // Check for circular dependencies
    for (const auto& step : plan.steps) {
        for (const auto& dep : step.dependencies) {
            if (dep == step.id) {
                errors.push_back("Step " + step.id + " depends on itself");
            }
        }
    }
    
    return errors;
}

std::string AgentPlanner::SerializePlan(const TaskPlan& plan) {
    std::stringstream ss;
    ss << "Goal: " << plan.goal << "\n";
    ss << "Workspace: " << plan.workspace << "\n";
    ss << "Steps:\n";
    for (const auto& step : plan.steps) {
        ss << "  [" << step.id << "] " << step.description
           << " (agent: " << step.agent << ", tool: " << step.tool << ")\n";
        if (!step.dependencies.empty()) {
            ss << "       depends on: ";
            for (const auto& dep : step.dependencies) {
                ss << dep << " ";
            }
            ss << "\n";
        }
    }
    ss << "Estimated cost: " << plan.totalEstimatedCost << "\n";
    ss << "Requires approval: " << (plan.requiresHumanApproval ? "yes" : "no") << "\n";
    return ss.str();
}

TaskPlan AgentPlanner::DeserializePlan(const std::string& json) {
    TaskPlan plan;
    // Simplified JSON parsing
    plan.goal = "deserialized plan";
    return plan;
}

} // namespace Sovereign
