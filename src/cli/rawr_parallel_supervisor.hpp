// rawr_parallel_supervisor.hpp — parallel lanes → arbitration → merge
// Supervisor: Implement | Test | Review | Investigate (isolated lane roots).
#pragma once
#include "../agents/arbitration_engine.hpp"
#include "../agents/SharedAgentWorkRegistry.hpp"
#include <cstdlib>
#include <filesystem>
#include <future>
#include <string>
#include <vector>

namespace rawr {

struct ParallelSupervisorWitness {
    int lanesSpawned = 0;
    int lanesCompleted = 0;
    int arbitrationUsed = 0;
    int mergeLeaseHeld = 0;
    int mergeApplied = 0;
    std::string mergedRole;
    std::string mergedPayload;
};

inline bool ParallelLanesWanted() {
    const char* e = std::getenv("RAWR_PARALLEL_LANES");
    return e && e[0] == '1';
}

inline std::string LaneRoot(const std::string& workspace, const char* role) {
    namespace fs = std::filesystem;
    fs::path p = fs::path(workspace) / ".rawrxd" / "lanes" / role;
    std::error_code ec;
    fs::create_directories(p, ec);
    return p.string();
}

// Fan-out four role lanes; arbitration executes; Edit lease gates merge record.
inline int RunParallelSupervisor(const std::string& workspace, const std::string& goal,
                                 ParallelSupervisorWitness& wit) {
    using namespace RawrXD::Agents;
    static const char* kRoles[] = {"implement", "test", "review", "investigate"};
    ArbitrationEngine::Config cfg;
    cfg.dispatcher_threads = 4;
    ArbitrationEngine arb(cfg);
    for (const char* role : kRoles) {
        const std::string root = LaneRoot(workspace, role);
        arb.register_agent(std::string("lane_") + role, role,
                           [root, goal, role](const ArbitrationTask&) {
                               return std::string("ROLE=") + role +
                                      "\nLANE=" + root + "\nGOAL=" + goal + "\n";
                           });
    }
    arb.start();
    wit.arbitrationUsed = 1;
    std::vector<std::future<ArbitrationResult>> futs;
    futs.reserve(4);
    for (const char* role : kRoles) {
        ArbitrationTask task;
        task.capability = role;
        task.payload = goal;
        task.resource_key = LaneRoot(workspace, role);
        task.priority = (role[1] == 'm') ? 20 : 10; // implement
        futs.push_back(arb.submit(std::move(task)));
        ++wit.lanesSpawned;
    }
    ArbitrationResult best{};
    std::string bestRole;
    for (size_t i = 0; i < futs.size(); ++i) {
        ArbitrationResult r = futs[i].get();
        if (r.ok && !r.output.empty()) {
            ++wit.lanesCompleted;
            if (bestRole.empty() || kRoles[i][1] == 'm') {
                best = std::move(r);
                bestRole = kRoles[i];
            }
        }
    }
    arb.shutdown();
    if (bestRole.empty()) return 1;
    WorkKey key{AgentWorkLease::Kind::Edit, workspace, "parallel_merge"};
    auto lease = SharedAgentWorkRegistry::instance().acquireOrJoin(key, 1, 1);
    if (lease.status == AcquireResult::ConflictingWrite ||
        lease.status == AcquireResult::StaleRepo)
        return 2;
    wit.mergeLeaseHeld = 1;
    wit.mergedRole = bestRole;
    wit.mergedPayload = best.output;
    wit.mergeApplied = 1;
    SharedAgentWorkRegistry::instance().complete(key);
    return 0;
}

} // namespace rawr
