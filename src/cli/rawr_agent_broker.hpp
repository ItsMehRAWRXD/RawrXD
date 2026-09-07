// rawr_agent_broker.hpp — all agent tools must go through broker (no direct FS/proc)
#pragma once
#include "rawr_safety_policy.hpp"
#include "tools/rawr_file_tool.hpp"
#include "tools/rawr_search_tool.hpp"
#include "tools/rawr_patch_tool.hpp"
#include "tools/rawr_build_tool.hpp"
#include "tools/rawr_test_tool.hpp"
#include <atomic>
#include <string>

namespace rawr {

struct AgentBrokerStats {
    std::atomic<int> brokerCalls{0};
    std::atomic<int> unbrokeredFs{0};
    std::atomic<int> unbrokeredProc{0};
    std::atomic<int> modelDecisions{0};
    void reset() {
        brokerCalls.store(0);
        unbrokeredFs.store(0);
        unbrokeredProc.store(0);
        modelDecisions.store(0);
    }
};

inline AgentBrokerStats& BrokerStats() {
    static AgentBrokerStats s;
    return s;
}

struct AgentBroker {
    SafetyPolicy policy;
    explicit AgentBroker(AutonomyLevel lvl) { policy.level = lvl; }

    bool workspaceRead(const std::string& ws, const std::string& path,
                       std::string& out) {
        BrokerStats().brokerCalls.fetch_add(1);
        return ToolReadFile(policy, ws, path, out);
    }

    bool workspaceSearch(const std::string& ws, const std::string& glob,
                         std::string& report) {
        BrokerStats().brokerCalls.fetch_add(1);
        return ToolSearchFiles(policy, ws, glob, report);
    }

    bool workspacePatch(PatchEngine& eng, const std::string& ws,
                        const std::string& path, const std::string& text,
                        PatchRecord& rec) {
        BrokerStats().brokerCalls.fetch_add(1);
        return ToolApplyPatch(policy, eng, ws, path, text, rec);
    }

    int processBuild(const std::string& cmd) {
        BrokerStats().brokerCalls.fetch_add(1);
        return ToolRunBuild(policy, cmd);
    }

    int processTest(const std::string& cmd) {
        BrokerStats().brokerCalls.fetch_add(1);
        return ToolRunTest(policy, cmd);
    }

    void modelDecision(const std::string& /*why*/) {
        BrokerStats().modelDecisions.fetch_add(1);
    }
};

} // namespace rawr
