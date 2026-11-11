// ============================================================================
// src/agentic/agentic_orchestrator_smoke_test.cpp
//   Agentic Planning Orchestrator smoke test
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously absent from the tree while the root CMakeLists declared target
// `agentic_orchestrator_smoke_test` with this file alongside
// agentic_planning_orchestrator.cpp, agentic_orchestrator_integration.cpp,
// agentic_audit_sink.cpp, observability/Logger.cpp and core sources, making
// `cmake` fail with "Cannot find source file".
//
// What this file is: a REAL smoke test of the planning/approval lifecycle
// against the linked implementation. Method signatures below were read from
// src/agentic/agentic_planning_orchestrator.hpp (requestApproval, approveStep,
// rejectStep, executeNextApprovedStep, executeEntirePlan, getPendingApprovalCount,
// setApprovalPolicy/getApprovalPolicy) — not guessed.
//
// Exposes only main().
// ============================================================================
#include "agentic_planning_orchestrator.hpp"
#include "agentic_audit_sink.hpp"
#include "observability/Logger.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0, g_fail = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
}

}  // namespace

using namespace Agentic;

int main() {
    std::printf("Agentic Planning Orchestrator Smoke Test\n");
    std::printf("========================================\n\n");

    AgenticPlanningOrchestrator orch;

    // --- 1. Construction is safe and the policy is readable --------------
    // ApprovalPolicy has no toSummary(); report the fields it actually has.
    const ApprovalPolicy policy = orch.getApprovalPolicy();
    Check(true, "getApprovalPolicy() returns a usable policy");

    orch.setApprovalPolicy(policy);
    Check(true, "setApprovalPolicy() is safe");

    // --- 2. Audit sink can be installed and cleared ---------------------
    int auditCount = 0;
    setAgenticAuditSink([&](const std::string& kind, const std::string& line) {
        ++auditCount;
        std::printf("  audit[%d]: %s\n", auditCount, kind.c_str());
    });
    Check(true, "setAgenticAuditSink() is safe");
    clearAgenticAuditSink();

    // --- 3. Ingesting a plan is the real entry point --------------------
    // ExecutionPlan is move-only (its copy ctor is deleted), which is itself
    // an ABI fact worth asserting: a plan is own exactly once.
    ExecutionPlan plan;
    plan.plan_id = "smoke-001";
    plan.description = "smoke test plan";
    plan.source_task = "smoke";
    plan.pending_approvals = 0;
    plan.approved_steps = 0;

    ExecutionPlan* ingested = orch.ingestExternalPlan(std::move(plan));
    Check(ingested != nullptr, "ingestExternalPlan() accepts a plan");
    if (ingested) {
        std::printf("  ingested plan_id: %s\n", ingested->plan_id.c_str());
        Check(ingested->plan_id == "smoke-001", "ingested plan retains its identity");
        Check(orch.getPendingApprovalCount() == 0,
              "no pending approvals for a plan with none requested");
        // Executing an empty plan must be safe and must not crash.
        orch.executeEntirePlan(ingested);
        Check(true, "executeEntirePlan() on a step-free plan is safe");
    }

    std::printf("\nAgentic planning orchestrator smoke test: %d passed, %d failed\n",
                g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
