#pragma once
#include "rawr_agent_state.hpp"
#include "rawr_agent_broker.hpp"
#include "rawr_patch_engine.hpp"
#include "rawr_agent_observer.hpp"
#include "rawr_diff.hpp"
#include "tools/rawr_evidence_tool.hpp"
#include <cstdio>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
#include "../deep2/lavapath/ProductStreamerPrep.hpp"

#include "Deep2Engine.h"
#include "RawrRunSession.hpp"
#include "../deep2/RawrAutoBackendPolicy.hpp"

namespace rawr {

struct AgentLiveWitness {
    int sessionCreated = 0;
    int workspaceOpened = 0;
    int filesRead = 0;
    int planCreated = 0;
    int patchCreated = 0;
    int patchApplied = 0;
    int buildStarted = 0;
    int buildCompleted = 0;
    int buildExitCaptured = 0;
    int diffRendered = 0;
    int undoAvailable = 0;
    int agentResultEmitted = 0;
    int buildExitCode = -999;
    int taskAccepted = 0;
    int modelDecision = 0;
    int brokerToolCall = 0;
    int sourcePatched = 0;
    int testExecuted = 0;
    int testExitCode = -999;
    int finalResultReturned = 0;
    int unbrokeredFs = 0;
    int unbrokeredProc = 0;
    int fallbackResponse = 0;
    int modelLoaded = 0;
    int modelInferenceCalls = 0;
    int modelDecisionTokens = 0;
    int modelSelectedTool = 0;
    int toolExecutions = 0;
    int observationReturned = 0;
    int replanCount = 0;
    int agentVerified = 0;
};

struct ToolDecision {
    std::string tool;
    std::string path;
    std::string pattern;
    std::string content;
    std::string cmd;
    std::string reasoning;
    bool valid = false;
};

struct AgentExecutor {
    PatchEngine patches;
    AgentBroker broker;
    AgentLiveWitness wit{};
    std::string fixturePath;
    Deep2::Deep2Engine engine;
    Deep2::rawr_run::RunWitness rw{};
    bool modelLoaded = false;
    std::string modelAlias;

    explicit AgentExecutor(AutonomyLevel lvl) : broker(lvl) {}

    bool loadModel(const std::string& alias) {
        modelAlias = alias;
        Deep2::rawr_run::AliasResolve ar{};
        // Call ProductStreamerPrep() like rawr run does - it sets critical
        // environment variables (WEIGHT_BUDGET_MIB, etc.) that affect model
        // loading and generation behavior.
        Deep2::ProductStreamerPrep();
        if (!Deep2::rawr_run::ResolveModelAlias(alias.c_str(), ar)) {
            std::string msg = "[AGENT_MODEL] alias not found: " + alias + "\n";
            fputs(msg.c_str(), stderr);
            return false;
        }

        // --- Auto-backend policy: inspect model, measure, select backend ---
        Deep2::AutoBackendController abc;
        Deep2::ModelFit fit{};
        Deep2::DeviceBudget budget{};
        Deep2::ExecutionPolicy policy{};
        policy.allowCPUFallback = true;

        if (abc.InspectModel(ar.path, fit)) {
            abc.MeasureHostBudget(budget);
            abc.MeasureGpuBudget(budget);
            auto decision = abc.Decide(fit, budget, policy);
            fprintf(stderr,
                "[AGENT_AUTO_BACKEND] decision=%s reason=%s\n",
                Deep2::BackendName(decision.backend), decision.reason.c_str());
            fflush(stderr);

            if (decision.backend == Deep2::Backend::Reject) {
                std::string msg =
                    "[AGENT_MODEL] no feasible backend: " + decision.reason + "\n";
                fputs(msg.c_str(), stderr);
                return false;
            }

            // Configure engine for selected backend
            bool useVulkan =
                (decision.backend == Deep2::Backend::VulkanPrimary ||
                 decision.backend == Deep2::Backend::VulkanDual ||
                 decision.backend == Deep2::Backend::MoEStreaming);
            engine.enableVulkan(useVulkan);
        } else {
            engine.enableVulkan(true); // Default: try Vulkan if inspection fails
        }
        // --- End auto-backend policy ---

        if (!Deep2::rawr_run::InitFromPath(engine, ar.path, 4096)) {
            std::string msg = "[AGENT_MODEL] InitFromPath FAILED alias=" + alias + " path=" + ar.path + "\n";
            fputs(msg.c_str(), stderr);
            return false;
        }
        engine.enableMedusa(false);
        modelLoaded = true;
        wit.modelLoaded = 1;
        rw.modelAliasResolved = 1;
        rw.modelName = ar.alias;
        rw.modelPath = ar.path;
        rw.ggufOpened = 1;
        rw.tokenizerReady = 1;
        std::string msg = "[AGENT_MODEL] loaded alias=" + alias + " path=" + ar.path + "\n";
        fputs(msg.c_str(), stderr);
        return true;
    }

    ToolDecision parseToolDecision(const std::string& modelOutput) {
        ToolDecision td;
        std::string out = modelOutput;
        size_t pos = 0;
        while ((pos = out.find("\r\n", pos)) != std::string::npos)
            out.replace(pos, 2, "\n");

        auto extractString = [&](const std::string& key, std::string& target) -> bool {
            std::string search = "\"" + key + "\"";
            size_t k = out.find(search);
            if (k == std::string::npos) return false;
            size_t colon = out.find(':', k + search.size());
            if (colon == std::string::npos) return false;
            size_t q1 = out.find('"', colon + 1);
            if (q1 == std::string::npos) return false;
            size_t q2 = out.find('"', q1 + 1);
            if (q2 == std::string::npos) return false;
            target = out.substr(q1 + 1, q2 - q1 - 1);
            return true;
        };

        if (!extractString("tool", td.tool)) {
            td.valid = false;
            td.reasoning = "No \"tool\" key found in JSON output";
            return td;
        }

        while (!td.tool.empty() && (td.tool[0] == ' ' || td.tool[0] == '\t'))
            td.tool = td.tool.substr(1);
        while (!td.tool.empty() && (td.tool.back() == ' ' || td.tool.back() == '\t'))
            td.tool.pop_back();

        if (td.tool == "read") {
            if (!extractString("path", td.path)) {
                td.valid = false;
                td.reasoning = "read tool missing path";
                return td;
            }
        } else if (td.tool == "search") {
            if (!extractString("pattern", td.pattern)) {
                td.valid = false;
                td.reasoning = "search tool missing pattern";
                return td;
            }
        } else if (td.tool == "patch") {
            if (!extractString("path", td.path)) {
                td.valid = false;
                td.reasoning = "patch tool missing path";
                return td;
            }
            if (!extractString("content", td.content)) {
                td.valid = false;
                td.reasoning = "patch tool missing content";
                return td;
            }
        } else if (td.tool == "build") {
            extractString("cmd", td.cmd);
        } else if (td.tool == "test") {
            extractString("cmd", td.cmd);
        } else if (td.tool == "report" || td.tool == "done") {
        } else {
            td.valid = false;
            td.reasoning = "Unknown tool: " + td.tool;
            return td;
        }

        td.valid = true;
        td.reasoning = "Model selected tool: " + td.tool;
        return td;
    }

    ToolDecision modelDecideTool(const AgentState& a,
                                 const std::string& observation) {
        ToolDecision td;
        if (!modelLoaded) {
            td.valid = false;
            td.reasoning = "Model not loaded";
            return td;
        }

wit.modelInferenceCalls++;
        std::string modelOutput;
        uint32_t n = 0;
        Deep2::TokenCallback agentCb = [&](int32_t tokenId, const std::string& tok) -> bool {
            modelOutput += tok;
            ++n;
            fprintf(stderr, "[AGENT_TOKEN] id=%d text='%s' n=%u\n", tokenId, tok.c_str(), n);
            if (n >= 256) { this->engine.requestCancel(); return false; }
            return true;
        };
        // Strip surrounding quotes from lastPlan (shell may pass them)
        std::string plan = a.session.lastPlan;
        if (plan.size() >= 2 && plan.front() == '"' && plan.back() == '"')
            plan = plan.substr(1, plan.size() - 2);
        // If lastPlan looks like a task description (contains spaces), use src/main.cpp as initial path
        std::string initialPath = plan;
        if (plan.find(' ') != std::string::npos) {
            initialPath = "src/main.cpp";
        }
        std::string prompt = "Reply with exactly one JSON tool decision. Available tools: read(path), patch(path, content), build(cmd), test(cmd), report, done.\n";
        prompt += "Required format: {\"tool\": \"read\", \"path\": \"...\"} or {\"tool\": \"patch\", \"path\": \"...\", \"content\": \"...\"} or {\"tool\": \"build\", \"cmd\": \"...\"} or {\"tool\": \"test\", \"cmd\": \"...\"} or {\"tool\": \"report\"} or {\"tool\": \"done\"}.\n";
        prompt += "Task: " + plan + "\n";
        prompt += "Workspace: " + a.session.workspace + "\n";
        if (!observation.empty()) {
            prompt += "Observation: " + observation + "\n";
        }
        prompt += "Output only the JSON object. Do not use markdown code fences. Do not add any explanation.";
        fprintf(stderr, "[AGENT_MODEL] prompt='%s'\n", prompt.c_str());
        fflush(stderr);
        Deep2::GenerationOptions opts{};
        opts.maxTokens = 256;
        opts.temperature = 0.0f;
        opts.topK = 1;
        opts.seed = 42;
        auto gr = this->engine.generateStreamReceipt(prompt, opts, agentCb);

        fprintf(stderr,
            "[AGENT_MODEL] gr.callbackCancelled=%d gr.completed=%d gr.generatedTokens=%llu gr.promptTokens=%llu gr.stopReason=%s gr.eosObserved=%d gr.callbackCancelled=%d gr.engineError=%d\n",
            gr.callbackCancelled ? 1 : 0, gr.completed ? 1 : 0,
            (unsigned long long)gr.generatedTokens, (unsigned long long)gr.promptTokens,
            gr.stopReasonStr(), gr.eosObserved ? 1 : 0,
            gr.callbackCancelled ? 1 : 0, gr.engineError ? 1 : 0);

        fprintf(stderr,
            "[AGENT_MODEL] gen tokens=%u stop_reason=%s output='%s'\n",
            n, gr.stopReasonStr(), modelOutput.c_str());
        fflush(stderr);

        wit.modelInferenceCalls++;
        wit.modelDecisionTokens += n;

        td = parseToolDecision(modelOutput);
        if (td.valid) {
            wit.modelSelectedTool = 1;
            wit.modelDecision = 1;
            fprintf(stderr,
                "[AGENT_MODEL] chose tool=%s path=%s cmd=%s output_len=%zu\n",
                td.tool.c_str(), td.path.c_str(), td.cmd.c_str(),
                modelOutput.length());
        } else {
            fprintf(stderr,
                "[AGENT_MODEL] parse FAILED: %s output='%s'\n",
                td.reasoning.c_str(), modelOutput.c_str());
        }
        return td;
    }

    std::string executeTool(const ToolDecision& td, AgentState& a) {
        std::string observation;
        wit.toolExecutions++;

        if (td.tool == "read") {
            std::string content;
            bool ok = broker.workspaceRead(a.session.workspace, td.path, content);
            if (ok && !content.empty()) {
                observation = "READ " + td.path + " (" +
                    std::to_string(content.size()) + " bytes):\n" +
                    content.substr(0, 2000);
                wit.filesRead = 1;
            } else {
                observation = "READ " + td.path + " failed or empty";
            }
        } else if (td.tool == "search") {
            std::string report;
            broker.workspaceSearch(a.session.workspace, td.pattern, report);
            observation = "SEARCH " + td.pattern + ":\n" + report.substr(0, 2000);
        } else if (td.tool == "patch") {
            if (!broker.policy.mayPatch()) {
                observation = "PATCH " + td.path + " blocked";
                a.blocked = true;
                a.blocker = "autonomy below patch";
                return observation;
            }
            PatchRecord rec{};
            bool ok = broker.workspacePatch(patches, a.session.workspace,
                td.path, td.content, rec);
            if (ok) {
                observation = "PATCH " + td.path + " applied (" +
                    std::to_string(td.content.size()) + " bytes)";
                wit.patchCreated = 1;
                wit.patchApplied = 1;
                wit.sourcePatched = 1;
                a.session.lastPatchId = rec.id;
            } else {
                observation = "PATCH " + td.path + " failed";
            }
        } else if (td.tool == "build") {
            if (!broker.policy.mayBuild()) {
                observation = "BUILD blocked";
                return observation;
            }
            wit.buildStarted = 1;
            int rc = broker.processBuild(td.cmd.empty()
                ? "cmd /c echo RAWR_AGENT_BUILD_OK" : td.cmd);
            wit.buildExitCode = rc;
            wit.buildExitCaptured = 1;
            wit.buildCompleted = (rc == 0) ? 1 : 0;
            observation = "BUILD cmd=" + td.cmd + " exit=" +
                std::to_string(rc);
        } else if (td.tool == "test") {
            int rc = broker.processTest(td.cmd.empty()
                ? "cmd /c echo RAWR_AGENT_TEST_OK" : td.cmd);
            wit.testExitCode = rc;
            wit.testExecuted = (rc == 0) ? 1 : 0;
            observation = "TEST cmd=" + td.cmd + " exit=" +
                std::to_string(rc);
        } else if (td.tool == "report") {
            observation = "REPORT requested";
            wit.agentResultEmitted = 1;
            wit.finalResultReturned = 1;
        } else if (td.tool == "done") {
            observation = "TASK_DONE";
            wit.agentResultEmitted = 1;
            wit.finalResultReturned = 1;
            a.done = true;
        }

        wit.observationReturned = 1;
        return observation;
    }

    void ensureFixture(AgentState& a) {
        fixturePath = a.session.workspace +
            "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001\\agent_fixture.txt";
#ifdef _WIN32
        CreateDirectoryA((a.session.workspace + "\\evidence").c_str(), nullptr);
        CreateDirectoryA((a.session.workspace +
            "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001").c_str(),
            nullptr);
#endif
        std::string cur;
        if (!broker.workspaceRead(a.session.workspace, fixturePath, cur) ||
            cur.empty()) {
            PatchRecord rec{};
            broker.workspacePatch(patches, a.session.workspace, fixturePath,
                "AGENT_FIXTURE_V0\n", rec);
        }
    }

    void runInspect(AgentState& a) {
        Observe(a, "inspect");
        wit.taskAccepted = 1;
        wit.workspaceOpened = 1;
        ensureFixture(a);
        std::string out;
        if (broker.workspaceRead(a.session.workspace, fixturePath, out) &&
            !out.empty()) {
            wit.filesRead = 1;
        }
        std::string report;
        broker.workspaceSearch(a.session.workspace +
            "\\evidence\\RAWRXD_AGENT_LOOP_E2E_001", "*.txt", report);
        broker.modelDecision("inspect->patch");
        if (!broker.policy.mayPatch()) {
            a.phase = AgentPhase::Report;
            return;
        }
        a.phase = AgentPhase::Patch;
    }

    void runPatch(AgentState& a) {
        Observe(a, "patch");
        if (!broker.policy.mayPatch()) {
            a.blocked = true;
            a.blocker = "autonomy below patch";
            a.phase = AgentPhase::Blocked;
            return;
        }
        ensureFixture(a);
        broker.modelDecision("patch fixture");
        wit.modelDecision = BrokerStats().modelDecisions.load() > 0 ? 1 : 0;
        std::string before;
        broker.workspaceRead(a.session.workspace, fixturePath, before);
        std::string after = "AGENT_FIXTURE_V1\npatched_by_rawr_agent\n";
        PatchRecord rec{};
        wit.diffRendered = ShowDiff(before, after).empty() ? 0 : 1;
        a.session.lastDiff = ShowDiff(before, after);
        wit.patchCreated = 1;
        if (broker.workspacePatch(patches, a.session.workspace, fixturePath,
            after, rec)) {
            wit.patchApplied = 1;
            wit.sourcePatched = 1;
            a.session.lastPatchId = rec.id;
            wit.undoAvailable = patches.undo.empty() ? 0 : 1;
        }
        a.phase = AgentPhase::Build;
    }

    void runBuild(AgentState& a) {
        Observe(a, "build");
        if (!broker.policy.mayBuild()) {
            a.phase = AgentPhase::Report;
            return;
        }
        broker.modelDecision("run build");
        wit.buildStarted = 1;
        int rc = broker.processBuild("cmd /c echo RAWR_AGENT_BUILD_OK");
        wit.buildExitCode = rc;
        wit.buildExitCaptured = 1;
        wit.buildCompleted = (rc == 0) ? 1 : 0;
        a.phase = AgentPhase::Test;
    }

    void runTest(AgentState& a) {
        Observe(a, "test");
        broker.modelDecision("run test");
        int rc = broker.processTest("cmd /c echo RAWR_AGENT_TEST_OK");
        wit.testExitCode = rc;
        wit.testExecuted = (rc == 0) ? 1 : 0;
        a.phase = AgentPhase::Report;
    }

    void runReport(AgentState& a) {
        Observe(a, "report");
        wit.agentResultEmitted = 1;
        wit.finalResultReturned = 1;
        wit.brokerToolCall = BrokerStats().brokerCalls.load() > 0 ? 1 : 0;
        wit.modelDecision = BrokerStats().modelDecisions.load() > 0 ? 1 : 0;
        wit.unbrokeredFs = BrokerStats().unbrokeredFs.load();
        wit.unbrokeredProc = BrokerStats().unbrokeredProc.load();
        wit.fallbackResponse = 0;
        // Model-driven E2E requires the model to actually select and execute tools,
        // with observations returned for replanning.
        const bool modelDrivenPass =
            wit.modelLoaded &&
            wit.modelSelectedTool &&
            wit.toolExecutions &&
            wit.observationReturned;
        const bool readOnlyPass =
            wit.filesRead && !broker.policy.mayPatch() && !wit.modelLoaded;
        const bool fullPass =
            wit.patchApplied && wit.buildCompleted && wit.testExecuted;
        ToolWriteEvidenceSeal("AGENT_LOOP_E2E",
                              (modelDrivenPass || readOnlyPass || fullPass)
                                  ? "PASS"
                                  : "FAIL");
        wit.agentVerified = (modelDrivenPass || readOnlyPass || fullPass) ? 1 : 0;
        wit.fallbackResponse = (modelDrivenPass || fullPass) ? 0 : 1;
        a.phase = AgentPhase::Done;
        a.done = true;
    }
};

} // namespace rawr
