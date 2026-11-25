// =============================================================================
// subagent_acceptance_test.cpp — A6/HexMag shared-backend acceptance.
// =============================================================================
// Real executable proof for the previously-missing dependencies:
//   agent_history.cpp, agent_policy.cpp, bulk_fix.cpp, subagent_core.cpp,
//   agentic/SubAgentManager.cpp — fail-closed without an engine, real
//   recording/querying, policy CRUD + evaluation, bulk-fix verdicts.
// =============================================================================
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "agent_history.h"
#include "agent_policy.h"
#include "agent/autonomous_subagent.hpp"
#include "agentic/agentic_engine_iface.h"
#include "subagent_core.h"
#include "agentic/SubAgentManager.h"

// Test-only engine (fixture, not product code): deterministic echo.
class EchoEngine : public AgenticEngine {
public:
    std::string chat(const std::string& prompt) override {
        return "FIXED[echo] " + prompt.substr(0, 32);
    }
};

static int g_fail = 0;
static void Check(const char* name, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("A6 acceptance start\n");
    const std::string tmp = getenv("TEMP") ? getenv("TEMP") : ".";
    const std::string dir = tmp + "/subagent_acceptance";
    std::filesystem::create_directories(dir);
    std::filesystem::remove(dir + "/agent_history.jsonl");
    std::filesystem::remove(dir + "/policies.json");

    // ---- AgentHistoryRecorder: record + query + JSONL roundtrip ----
    {
        AgentHistoryRecorder hist(dir);
        hist.setSessionId("acceptance");
        hist.recordAgentSpawn("a1", "p", "desc", "prompt");
        hist.recordToolInvoke("a1", "readFile", "x.txt");
        hist.recordAgentComplete("a1", "done", 5);
        Check("history.count", hist.eventCount() == 3);
        Check("history.byType",
              hist.getEventsByType("tool_invoke").size() == 1);
        hist.flush();
        AgentHistoryRecorder hist2(dir);
        Check("history.jsonl_roundtrip", hist2.eventCount() == 3);
    }

    // ---- PolicyEngine: CRUD + fail-closed evaluation ----
    {
        PolicyEngine eng(dir);
        Check("policy.empty_failclosed", !eng.evaluate("agent_fail", "x").hasMatch);
        AgentPolicy p;
        p.name = "retry on fail";
        p.trigger.eventType = "agent_fail";
        p.action.maxRetries = 2;
        const std::string id = eng.addPolicy(p);
        Check("policy.add", !id.empty() && eng.policyCount() == 1);
        const auto r = eng.evaluate("agent_fail", "boom");
        Check("policy.match", r.hasMatch && r.mergedAction.maxRetries == 2);
        Check("policy.approval_flag", r.needsUserApproval);  // default true
        eng.setEnabled(id, false);
        Check("policy.disable", !eng.evaluate("agent_fail", "boom").hasMatch);
        eng.setEnabled(id, true);  // persist an ENABLED policy
        eng.save();
        PolicyEngine eng2(dir);
        Check("policy.persistence", eng2.policyCount() == 1);
    }

    // ---- BulkFixOrchestrator: null engine -> all failed (fail closed) ----
    {
        BulkFixOrchestrator orch(nullptr, nullptr, nullptr, nullptr);
        std::vector<BulkFixTarget> targets{{"t1", "a.txt", "ctx"}};
        const auto res = orch.applyBulkRefactor(
            "p", BulkFixOrchestrator::makeCompileErrorFixStrategy(), targets);
        Check("bulkfix.failclosed",
              res.fixedCount() == 0 && res.failedCount() == 1);
    }

    // ---- BulkFixOrchestrator: real engine writes the file ----
    {
        const std::string victim = dir + "/bulkfix_target.txt";
        { std::ofstream(victim) << "original content"; }
        EchoEngine engine;
        BulkFixOrchestrator orch(nullptr, &engine, nullptr, nullptr);
        std::vector<BulkFixTarget> targets{{"t1", victim, "ctx"}};
        const auto res = orch.applyBulkRefactor(
            "p", BulkFixOrchestrator::makeLintFixStrategy(), targets);
        std::ifstream in(victim);
        std::stringstream ss;
        ss << in.rdbuf();
        Check("bulkfix.engine_fixed", res.fixedCount() == 1);
        Check("bulkfix.file_written",
              ss.str().rfind("FIXED[echo]", 0) == 0);
        Check("bulkfix.stats", orch.getStats().totalFixed == 1);
    }

    // ---- subagent_core: spawn without engine fails closed ----
    {
        SubAgentManager mgr(nullptr);
        bool threw = false;
        try {
            mgr.spawnSubAgent("p", "desc", "prompt");
        } catch (...) {
            threw = true;
        }
        Check("subagent.failclosed", threw);
    }

    // ---- subagent_core: real engine executes the subagent ----
    {
        EchoEngine engine;
        SubAgentManager mgr(&engine);
        const std::string id = mgr.spawnSubAgent("p", "do work", "prompt");
        Check("subagent.spawn_id", !id.empty());
        const bool done = mgr.waitForSubAgent(id, 10000);
        Check("subagent.completed", done);
        Check("subagent.result",
              mgr.getSubAgentResult(id).rfind("FIXED[echo]", 0) == 0);
        mgr.cancelAll();
    }

    // ---- RawrXD::Agentic swarm manager: init + fail-closed task ----
    {
        auto& swarm = RawrXD::Agentic::SubAgentManager::instance();
        RawrXD::Agentic::SwarmTopology topo;
        topo.workerCount = 2;
        Check("swarm.init", swarm.initializeSwarm(topo, "model"));
        Check("swarm.active", swarm.isSwarmActive());
        Check("swarm.task_failclosed", swarm.executeSwarmTask("do work") == 0);
        const std::string shard = dir + "/shard.gguf";
        { std::ofstream(shard, std::ios::binary) << "shard"; }
        Check("swarm.shard", swarm.loadModelShard(shard, 0));
        Check("swarm.shard_count", swarm.getActiveShardCount() == 1);
        swarm.shutdownSwarm();
        Check("swarm.shutdown", !swarm.isSwarmActive());
    }

    std::printf("SUBAGENT_ACCEPTANCE %s (failures=%d)\n",
                g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}