// agentic_orchestrator_integration.cpp
// Integration: wires AgenticPlanningOrchestrator into RawrXD IDE lifecycle

#include "agentic_orchestrator_integration.hpp"
#include "observability/Logger.hpp"
#include "../agent/model_invoker.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>

namespace Agentic
{

namespace {

void tryLoadApprovalPolicyFromDisk(AgenticPlanningOrchestrator& orch)
{
    std::vector<std::string> candidates;
    if (const char* root = std::getenv("RAWRXD_REPO_ROOT"))
    {
        candidates.push_back(std::string(root) + "\\config\\approval_policy.json");
    }
    candidates.push_back("config\\approval_policy.json");
    candidates.push_back("approval_policy.json");
    if (const char* ad = std::getenv("APPDATA"))
    {
        candidates.push_back(std::string(ad) + "\\RawrXD\\approval_policy.json");
    }

    for (const auto& path : candidates)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in)
            continue;
        std::ostringstream ss;
        ss << in.rdbuf();
        try
        {
            auto j = nlohmann::json::parse(ss.str());
            orch.setApprovalPolicy(ApprovalPolicy::fromJson(j));
            LOG_INFO("AgenticOrch", "Loaded approval policy from " + path);
            return;
        }
        catch (...)
        {
            LOG_INFO("AgenticOrch", "approval_policy.json present but invalid JSON: " + path);
        }
    }
}

}  // namespace

OrchestratorIntegration::OrchestratorIntegration() : m_orchestrator(std::make_unique<AgenticPlanningOrchestrator>()) {}

OrchestratorIntegration::~OrchestratorIntegration() {}

void OrchestratorIntegration::initialize()
{
    if (!m_orchestrator || m_initialized)
    {
        return;
    }

    // Wire planner: use ModelInvoker to generate plans via LLM
    m_orchestrator->setPlanGenerationFn(
        [this](const std::string& task) -> ExecutionPlan
        {
            ExecutionPlan plan;
            plan.description = task;
            plan.source_task = task;
            plan.planner_model = "llm_planner";

            // Attempt LLM-based plan generation
            try {
                ModelInvoker invoker;
                invoker.setLLMBackend("ollama", "http://localhost:11434");

                InvocationParams params;
                params.wish = "Generate a step-by-step execution plan for the following task. "
                               "Return ONLY a JSON array of steps, each with 'id', 'title', 'description', 'is_mutating' (true/false), and 'risk_level' (VeryLow/Low/Medium/High/Critical).\n\nTask: " + task;
                params.maxTokens = 2000;
                params.temperature = 0.3;

                auto response = invoker.invoke(params);
                if (response.success && response.parsedPlan.is_array()) {
                    for (const auto& stepJson : response.parsedPlan) {
                        PlanStep step;
                        step.id = stepJson.value("id", "step_" + std::to_string(plan.steps.size() + 1));
                        step.title = stepJson.value("title", "Untitled step");
                        step.description = stepJson.value("description", "");
                        step.is_mutating = stepJson.value("is_mutating", false);
                        std::string riskStr = stepJson.value("risk_level", "Low");
                        if (riskStr == "VeryLow") step.risk_level = StepRisk::VeryLow;
                        else if (riskStr == "Low") step.risk_level = StepRisk::Low;
                        else if (riskStr == "Medium") step.risk_level = StepRisk::Medium;
                        else if (riskStr == "High") step.risk_level = StepRisk::High;
                        else step.risk_level = StepRisk::Critical;

                        // Wire dependencies: each step depends on the previous
                        if (!plan.steps.empty()) {
                            step.dependencies.push_back(plan.steps.back().id);
                        }
                        plan.steps.push_back(step);
                    }
                    plan.confidence_score = 0.85f;
                    LOG_INFO("AgenticOrch", "Generated LLM plan with " + std::to_string(plan.steps.size()) + " steps");
                    return plan;
                }
            } catch (const std::exception& e) {
                LOG_INFO("AgenticOrch", std::string("LLM planner failed: ") + e.what() + ", falling back to heuristic");
            }

            // Fallback heuristic planner when LLM is unavailable
            plan.confidence_score = 0.65f;
            plan.planner_model = "heuristic_fallback";

            PlanStep step1;
            step1.id = "step_1_analyze";
            step1.title = "Analyze task requirements";
            step1.description = "Parse task to understand scope and dependencies";
            step1.is_mutating = false;
            step1.risk_level = StepRisk::VeryLow;
            plan.steps.push_back(step1);

            PlanStep step2;
            step2.id = "step_2_prepare";
            step2.title = "Prepare workspace";
            step2.description = "Set up build environment and dependencies";
            step2.is_mutating = false;
            step2.risk_level = StepRisk::Low;
            step2.dependencies.push_back(step1.id);
            plan.steps.push_back(step2);

            PlanStep step3;
            step3.id = "step_3_implement";
            step3.title = "Implement changes";
            step3.description = "Execute code modifications as planned";
            step3.is_mutating = true;
            step3.risk_level = StepRisk::Medium;
            step3.dependencies.push_back(step2.id);
            plan.steps.push_back(step3);

            PlanStep step4;
            step4.id = "step_4_validate";
            step4.title = "Validate and test";
            step4.description = "Run tests to verify implementation";
            step4.is_mutating = false;
            step4.risk_level = StepRisk::VeryLow;
            step4.dependencies.push_back(step3.id);
            plan.steps.push_back(step4);

            return plan;
        });

    if (m_riskAnalyzer)
    {
        m_orchestrator->setRiskAnalysisFn(m_riskAnalyzer);
    }

    m_orchestrator->setExecutionLogFn([](const std::string& log_entry) { LOG_INFO("AgenticOrch", log_entry); });

    // Wire tool executor: delegates to the integration's callback
    m_orchestrator->setToolExecutorFn(
        [this](const std::string& tool_name, const std::string& args, std::string& output) -> bool
        {
            if (m_toolExecutor)
            {
                return m_toolExecutor(tool_name, args, output);
            }
            output = "No tool executor configured";
            return false;
        });

    // Wire rollback executor: delegates to the integration's callback
    m_orchestrator->setRollbackExecutorFn(
        [this](const PlanStep& step)
        {
            if (m_rollbackExecutor)
            {
                m_rollbackExecutor(step);
            }
        });

    // Default policy, optionally overridden by machine-readable config (E07)
    m_orchestrator->setApprovalPolicy(ApprovalPolicy::Standard());
    tryLoadApprovalPolicyFromDisk(*m_orchestrator);
    m_initialized = true;
}

ExecutionPlan* OrchestratorIntegration::planAndApproveTask(const std::string& task_description)
{
    if (!m_orchestrator)
    {
        return nullptr;
    }

    // Step 1: Generate the plan
    auto* plan = m_orchestrator->generatePlanForTask(task_description);
    if (!plan)
        return nullptr;

    // Step 2: Analyze risk for each step
    for (size_t i = 0; i < plan->steps.size(); ++i)
    {
        auto& step = plan->steps[i];

        // Use custom analyzer if provided, otherwise use built-in
        if (m_riskAnalyzer)
        {
            step.risk_level = m_riskAnalyzer(step);
        }
        else
        {
            step.risk_level = m_orchestrator->analyzeStepRisk(step);
        }
    }

    // Step 3: Check approval policy and request approvals as needed
    for (size_t i = 0; i < plan->steps.size(); ++i)
    {
        auto& step = plan->steps[i];

        // Determine eligibility for auto-approval based on policy and risk
        auto policy = m_orchestrator->getApprovalPolicy();

        bool should_auto_approve = false;
        if (step.risk_level == StepRisk::VeryLow && policy.auto_approve_very_low_risk)
        {
            should_auto_approve = true;
        }
        else if (step.risk_level == StepRisk::Low && policy.auto_approve_low_risk)
        {
            should_auto_approve = true;
        }

        if (should_auto_approve)
        {
            step.approval_status = ApprovalStatus::ApprovedAuto;
            step.approval_user = "system";
            step.approval_reason = "Auto-approved by policy";
        }
        else
        {
            // Request human approval
            m_orchestrator->requestApproval(plan, i);
        }
    }

    return plan;
}

int OrchestratorIntegration::getPendingApprovalCount() const
{
    if (!m_orchestrator)
        return 0;
    return m_orchestrator->getPendingApprovalCount();
}

std::vector<std::pair<ExecutionPlan*, int>> OrchestratorIntegration::getPendingApprovals() const
{
    if (!m_orchestrator)
        return {};
    return m_orchestrator->getPendingApprovals();
}

void OrchestratorIntegration::onPlanGeneration(const std::string& task, ExecutionPlan& plan)
{
    // Called during plan generation; allows customization
    // (Currently used internally)
}

void OrchestratorIntegration::onStepExecution(ExecutionPlan* plan, int step_idx)
{
    if (!plan || !m_toolExecutor)
        return;

    auto& step = plan->steps[step_idx];

    // Execute each action in the step
    for (const auto& action : step.actions)
    {
        std::string output;
        if (m_toolExecutor(action, "", output))
        {
            step.execution_result += output + "\n";
        }
        else
        {
            step.error_message = "Tool execution failed: " + action;
            step.status = ExecutionStatus::Failed;
            return;
        }
    }

    step.status = ExecutionStatus::Success;
}

void OrchestratorIntegration::onRollbackRequest(ExecutionPlan* plan, int step_idx)
{
    if (!plan || !m_rollbackExecutor)
        return;

    auto& step = plan->steps[step_idx];
    m_rollbackExecutor(step);
}

}  // namespace Agentic
