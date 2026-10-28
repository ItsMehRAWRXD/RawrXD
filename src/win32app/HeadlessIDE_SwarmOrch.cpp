// ============================================================================
// HeadlessIDE_SwarmOrch.cpp — Local-only /api/swarm/orch diagnostic
// Calls production resolveSwarmModelOrchPlan + SubAgentManager::executeSwarm.
// Not a synthetic stub. Fail-closed for non-loopback.
// ============================================================================

#include "HeadlessIDE.h"
#include "Win32IDE_SwarmModelSelector.h"
#include "Win32IDE_AgenticBridge.h"
#include "../subagent_core.h"
#include "../agentic_engine.h"

#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <thread>
#include <windows.h>

namespace {

bool isLoopbackPeer(const std::string& address) {
    return address == "::1" || address == "localhost" ||
        address.compare(0, 4, "127.") == 0 ||
        address.compare(0, 11, "::ffff:127.") == 0;
}

int measureOverlapFromAgents(const std::vector<SubAgent>& agents) {
    struct Ev { long long t; int d; };
    std::vector<Ev> ev;
    ev.reserve(agents.size() * 2);
    for (const auto& a : agents) {
        auto s = std::chrono::duration_cast<std::chrono::milliseconds>(
            a.startTime.time_since_epoch()).count();
        auto e = std::chrono::duration_cast<std::chrono::milliseconds>(
            a.endTime.time_since_epoch()).count();
        if (e < s) e = s;
        ev.push_back({s, +1});
        ev.push_back({e, -1});
    }
    std::sort(ev.begin(), ev.end(), [](const Ev& a, const Ev& b) {
        if (a.t != b.t) return a.t < b.t;
        return a.d < b.d; // ends before starts at same tick
    });
    int cur = 0, peak = 0;
    for (const auto& e : ev) {
        cur += e.d;
        if (cur > peak) peak = cur;
    }
    return peak;
}

} // namespace

void HeadlessIDE::routeSwarmOrchRequest(const HostedHttpRequest& request,
                                        HostedHttpResponse& response) {
    const bool localLoopback =
        m_config.ingressMode == HeadlessIngressMode::Local &&
        isLoopbackPeer(request.peer) &&
        isLoopbackPeer(m_config.bindAddress);
    if (!localLoopback) {
        response.status = 403;
        response.body = "{\"error\":\"swarm_orch_local_only\",\"detail\":\"non_loopback_denied\"}";
        return;
    }

    OutputDebugStringA("[SWARM_ORCH] routeSwarmOrchRequest ENTER\r\n");
    OutputDebugStringA("[SWARM_ORCH] resolveSwarmModelOrchPlan INVOKING\r\n");

    unsigned requestedN = 0;
    std::string inputSnippet;
    bool doCleanup = true;
    int cancelAfterMs = 0;
    bool resolveOnly = false; // tag-fetch+select without executeSwarm (no invent)
    try {
        if (!request.body.empty()) {
            auto j = nlohmann::json::parse(request.body);
            if (j.contains("n") && j["n"].is_number_unsigned())
                requestedN = j["n"].get<unsigned>();
            else if (j.contains("n") && j["n"].is_number_integer())
                requestedN = static_cast<unsigned>(std::max(0, j["n"].get<int>()));
            inputSnippet = j.value("input", j.value("code", std::string()));
            doCleanup = j.value("cleanup", true);
            cancelAfterMs = j.value("cancelAfterMs", 0);
            resolveOnly = j.value("resolveOnly", false);
        }
    } catch (...) {
        response.status = 400;
        response.body = "{\"error\":\"invalid_json\"}";
        return;
    }
    if (inputSnippet.empty())
        inputSnippet = "// headless swarm orch diagnostic snippet\nint main(){return 0;}\n";
    if (inputSnippet.size() > 2000) inputSnippet.resize(2000);

    const RawrXD::Win32App::SwarmModelOrchPlan plan =
        RawrXD::Win32App::resolveSwarmModelOrchPlan(requestedN);
    OutputDebugStringA(("[SWARM_ORCH] resolveSwarmModelOrchPlan DONE taskCount=" +
                        std::to_string(plan.taskCount) + "\r\n").c_str());

    nlohmann::json out = nlohmann::json::object();
    out["path"] = "/api/swarm/orch";
    out["localOnly"] = true;
    out["resolveInvoked"] = true;
    out["taskCount"] = plan.taskCount;
    out["maxParallelPlan"] = plan.maxParallel;
    out["sequential"] = plan.sequential;
    out["emptyFailClosed"] = plan.emptyFailClosed;
    out["models"] = plan.models;

    if (plan.taskCount == 0 || plan.models.empty()) {
        out["executeInvoked"] = false;
        out["disposition"] = "FAIL_CLOSED_EMPTY_INVENTORY";
        out["RUNTIME_PASS"] = false;
        response.status = 503;
        response.body = out.dump();
        return;
    }

    if (resolveOnly) {
        // Product path: HttpTags/GGUF select sealed without executeSwarm.
        out["executeInvoked"] = false;
        out["resolveOnly"] = true;
        out["disposition"] = "RESOLVE_ONLY_SELECTED";
        out["RUNTIME_REACHED"] = true;  // resolve+select reached
        out["RUNTIME_PASS"] = false;    // execute not run — no invent PASS
        out["PROMOTE"] = 0;
        response.status = 200;
        response.body = out.dump();
        return;
    }

    static const char* kLens[] = {
        "security vulnerabilities",
        "performance bottlenecks",
        "code style and best practices",
        "refactoring opportunities",
    };
    constexpr size_t kLensN = sizeof(kLens) / sizeof(kLens[0]);

    std::vector<std::string> prompts;
    prompts.reserve(plan.taskCount);
    for (unsigned i = 0; i < plan.taskCount; ++i) {
        const char* lens = kLens[i % kLensN];
        prompts.push_back(std::string("Model[") + plan.models[i] +
                          "] — Analyze this code for " + lens + ":\n" + inputSnippet);
    }

    SwarmConfig config;
    config.maxParallel = static_cast<int>(plan.maxParallel);
    config.timeoutMs = 60000;
    config.mergeStrategy = "concatenate";
    config.failFast = false;

    // Same production executeSwarm via headless AgenticBridge SubAgentManager.
    AgenticBridge bridge(nullptr);
    bridge.Initialize("", "");
    SubAgentManager* mgr = bridge.GetSubAgentManager();
    if (!mgr) {
        out["executeInvoked"] = false;
        out["disposition"] = "FAIL_CLOSED_NO_SUBAGENT_MANAGER";
        out["RUNTIME_PASS"] = false;
        response.status = 503;
        response.body = out.dump();
        return;
    }

    // Prefer engine-backed manager when possible (honest FAIL if chat unavailable).
    static AgenticEngine engine;
    static bool engineInit = false;
    if (!engineInit) {
        engine.initialize();
        engineInit = true;
    }
    SubAgentManager orchMgr(&engine);
    orchMgr.setLogCallback([](int, const std::string& msg) {
        OutputDebugStringA(("[SWARM_ORCH] " + msg + "\r\n").c_str());
    });

    std::thread cancelThread;
    std::atomic<bool> cancelFired{false};
    if (cancelAfterMs > 0) {
        cancelThread = std::thread([&orchMgr, cancelAfterMs, &cancelFired]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(cancelAfterMs));
            cancelFired.store(true);
            orchMgr.cancelAll();
            OutputDebugStringA("[SWARM_ORCH] cancelAll FIRED\r\n");
        });
    }

    OutputDebugStringA("[SWARM_ORCH] executeSwarm INVOKING\r\n");
    out["executeInvoked"] = true;
    std::string merged = orchMgr.executeSwarm("headless-orch", prompts, config);
    OutputDebugStringA("[SWARM_ORCH] executeSwarm DONE\r\n");

    if (cancelThread.joinable()) cancelThread.join();

    const std::string swarmId = orchMgr.getLastSwarmId();
    const int peakCounter = orchMgr.getSwarmPeakParallel(swarmId);
    auto agents = orchMgr.getSubAgentsForParent("headless-orch");
    const int peakTimestamps = measureOverlapFromAgents(agents);

    nlohmann::json workers = nlohmann::json::array();
    int completed = 0, failed = 0, cancelled = 0;
    for (const auto& a : agents) {
        nlohmann::json w;
        w["id"] = a.id;
        w["state"] = a.stateString();
        w["elapsedMs"] = a.elapsedMs();
        w["tokensGenerated"] = a.tokensGenerated;
        w["resultChars"] = static_cast<int>(a.result.size());
        const bool ok = a.state == SubAgent::State::Completed && !a.result.empty();
        const bool blocked = a.state == SubAgent::State::Failed ||
                             a.state == SubAgent::State::Cancelled ||
                             a.state == SubAgent::State::TimedOut ||
                             (a.state == SubAgent::State::Completed && a.result.empty());
        w["inferenceOrTool"] = ok;
        w["honestFailOrBlocked"] = blocked && !ok;
        if (a.state == SubAgent::State::Completed) ++completed;
        else if (a.state == SubAgent::State::Failed) ++failed;
        else if (a.state == SubAgent::State::Cancelled) ++cancelled;
        // Trim result for receipt (honest, bounded)
        w["resultPreview"] = a.result.substr(0, 240);
        workers.push_back(std::move(w));
    }

    out["swarmId"] = swarmId;
    out["workers"] = workers;
    out["workerCount"] = static_cast<int>(agents.size());
    out["completed"] = completed;
    out["failed"] = failed;
    out["cancelled"] = cancelled;
    out["measuredPeakParallel_counter"] = peakCounter;
    out["measuredPeakParallel_timestamps"] = peakTimestamps;
    out["measuredPeakParallel"] = (std::max)(peakCounter, peakTimestamps);
    out["cancelFired"] = cancelFired.load();
    out["mergedChars"] = static_cast<int>(merged.size());
    out["mergedPreview"] = merged.substr(0, 512);

    if (doCleanup) {
        orchMgr.cancelAll();
        out["cleanupCancelAll"] = true;
        OutputDebugStringA("[SWARM_ORCH] cleanup cancelAll\r\n");
    }

    const bool peakOk = out["measuredPeakParallel"].get<int>() <=
                        static_cast<int>(plan.maxParallel);
    const bool allAccounted = static_cast<unsigned>(agents.size()) == plan.taskCount;
    out["peakWithinCap"] = peakOk;
    out["allWorkersAccounted"] = allAccounted;
    // RUNTIME: orch invoked + workers recorded. Per-worker may be FAIL/BLOCKED.
    out["RUNTIME_REACHED"] = out["executeInvoked"].get<bool>() && allAccounted;
    out["RUNTIME_PASS"] = out["RUNTIME_REACHED"].get<bool>() && peakOk &&
                          (completed + failed + cancelled) == static_cast<int>(plan.taskCount);
    out["disposition"] = out["RUNTIME_PASS"].get<bool>()
        ? "G16_A_RUNTIME_REACHED"
        : "G16_A_INVOKED_PARTIAL_OR_FAIL";
    out["PROMOTE"] = 0;

    (void)mgr; // bridge path retained for link parity; orchMgr is engine-backed
    response.status = 200;
    response.body = out.dump();
}
