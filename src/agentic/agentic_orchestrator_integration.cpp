// agentic_orchestrator_integration.cpp
// Integration: wires AgenticPlanningOrchestrator into RawrXD IDE lifecycle

#include "agentic_orchestrator_integration.hpp"
#include "observability/Logger.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>

namespace Agentic
{

namespace {

std::string toLowerCopy(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool containsAny(const std::string& haystackLower, std::initializer_list<const char*> needles)
{
    for (const char* n : needles)
    {
        if (haystackLower.find(n) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

std::string resolvePlannerModel()
{
    if (const char* env = std::getenv("RAWRXD_PLANNER_MODEL"))
    {
        if (*env != '\0')
        {
            return std::string(env);
        }
    }
    return "rule_based_planner";
}

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
    std::lock_guard<std::mutex> lock(m_integrationMutex);
    if (!m_orchestrator || m_initialized)
    {
        return;
    }

    // Wire planner: deterministic rule-based generation for baseline production behavior.
    m_orchestrator->setPlanGenerationFn(
        [this](const std::string& task) -> ExecutionPlan
        {
            ExecutionPlan plan;
            plan.description = task;
            plan.source_task = task;
            plan.planner_model = resolvePlannerModel();
            plan.confidence_score = 0.75f;

            const std::string taskLower = toLowerCopy(task);
            const bool hasBuild = containsAny(taskLower, {"build", "compile", "link", "cmake", "ninja"});
            const bool hasTest = containsAny(taskLower, {"test", "validate", "verify", "smoke"});
            const bool hasCodeChange = containsAny(taskLower, {"edit", "patch", "fix", "refactor", "audit"});

            PlanStep step1;
            step1.id = "step_1_analyze";
            step1.title = "Analyze task requirements";
            step1.description = "Parse task to understand scope and dependencies";
            step1.is_mutating = false;
            step1.risk_level = StepRisk::VeryLow;
            plan.steps.push_back(step1);

            if (hasBuild)
            {
                PlanStep stepPrepare;
                stepPrepare.id = "step_2_prepare_build";
                stepPrepare.title = "Prepare build workspace";
                stepPrepare.description = "Resolve toolchain and build graph prerequisites";
                stepPrepare.is_mutating = false;
                stepPrepare.risk_level = StepRisk::Low;
                stepPrepare.dependencies.push_back(step1.id);
                plan.steps.push_back(stepPrepare);
            }

            PlanStep step3;
            step3.id = "step_3_implement";
            step3.title = "Implement changes";
            step3.description = "Execute code modifications as planned";
            step3.is_mutating = hasCodeChange;
            step3.risk_level = hasCodeChange ? StepRisk::Medium : StepRisk::Low;
            if (!plan.steps.empty())
            {
                step3.dependencies.push_back(plan.steps.back().id);
            }
            step3.affected_files.push_back("workspace");
            plan.steps.push_back(step3);

            if (hasTest || hasBuild)
            {
                PlanStep step4;
                step4.id = "step_4_validate";
                step4.title = "Validate and test";
                step4.description = "Run tests and checks to verify implementation";
                step4.is_mutating = false;
                step4.risk_level = StepRisk::VeryLow;
                step4.dependencies.push_back(step3.id);
                plan.steps.push_back(step4);
            }

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
            ToolExecutorFn exec;
            {
                std::lock_guard<std::mutex> cbLock(m_integrationMutex);
                exec = m_toolExecutor;
            }
            if (exec)
            {
                return exec(tool_name, args, output);
            }
            output = "No tool executor configured";
            return false;
        });

    // Wire rollback executor: delegates to the integration's callback
    m_orchestrator->setRollbackExecutorFn(
        [this](const PlanStep& step)
        {
            RollbackExecutorFn exec;
            {
                std::lock_guard<std::mutex> cbLock(m_integrationMutex);
                exec = m_rollbackExecutor;
            }
            if (exec)
            {
                exec(step);
            }
        });

    // Default policy, optionally overridden by machine-readable config (E07)
    m_orchestrator->setApprovalPolicy(ApprovalPolicy::Standard());
    tryLoadApprovalPolicyFromDisk(*m_orchestrator);
    m_initialized = true;
}

ExecutionPlan* OrchestratorIntegration::planAndApproveTask(const std::string& task_description)
{
    AgenticPlanningOrchestrator* orchestrator = nullptr;
    RiskAnalyzerFn riskAnalyzer;
    {
        std::lock_guard<std::mutex> lock(m_integrationMutex);
        if (!m_orchestrator)
        {
            return nullptr;
        }
        orchestrator = m_orchestrator.get();
        riskAnalyzer = m_riskAnalyzer;
    }

    if (!orchestrator)
    {
        return nullptr;
    }

    // Step 1: Generate the plan
    auto* plan = orchestrator->generatePlanForTask(task_description);
    if (!plan)
        return nullptr;

    // Step 2: Analyze risk for each step
    for (size_t i = 0; i < plan->steps.size(); ++i)
    {
        auto& step = plan->steps[i];

        // Use custom analyzer if provided, otherwise use built-in
        if (riskAnalyzer)
        {
            step.risk_level = riskAnalyzer(step);
        }
        else
        {
            step.risk_level = orchestrator->analyzeStepRisk(step);
        }
    }

    // Step 3: Check approval policy and request approvals as needed
    for (size_t i = 0; i < plan->steps.size(); ++i)
    {
        auto& step = plan->steps[i];

        // Determine eligibility for auto-approval based on policy and risk
        auto policy = orchestrator->getApprovalPolicy();

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
            m_orchestrator->requestApproval(plan, static_cast<int>(i));
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
    if (!plan)
        return;

    if (step_idx < 0 || static_cast<size_t>(step_idx) >= plan->steps.size())
    {
        return;
    }

    ToolExecutorFn exec;
    {
        std::lock_guard<std::mutex> lock(m_integrationMutex);
        exec = m_toolExecutor;
    }
    if (!exec)
    {
        return;
    }

    auto& step = plan->steps[step_idx];

    // Execute each action in the step
    for (const auto& action : step.actions)
    {
        std::string output;
        if (exec(action, "", output))
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
    if (!plan)
        return;

    if (step_idx < 0 || static_cast<size_t>(step_idx) >= plan->steps.size())
    {
        return;
    }

    RollbackExecutorFn exec;
    {
        std::lock_guard<std::mutex> lock(m_integrationMutex);
        exec = m_rollbackExecutor;
    }
    if (!exec)
    {
        return;
    }

    auto& step = plan->steps[step_idx];
    exec(step);
}

}  // namespace Agentic
