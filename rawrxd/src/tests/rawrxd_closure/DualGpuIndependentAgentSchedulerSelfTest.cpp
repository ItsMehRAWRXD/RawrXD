#include "agentic/DualGpuIndependentAgentScheduler.hpp"
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>

using namespace RawrXD::Agentic;

namespace {
struct Ctx { std::uint32_t ordinal{}; std::string model; };
struct Harness { std::unordered_set<void*> live; };
void* createCtx(void* u, const AgentDevice& d, std::string_view model) {
    auto& h = *static_cast<Harness*>(u);
    auto* c = new Ctx{d.ordinal, std::string(model)};
    h.live.insert(c);
    return c;
}
void destroyCtx(void* u, void* p) {
    auto& h = *static_cast<Harness*>(u);
    h.live.erase(p);
    delete static_cast<Ctx*>(p);
}
AgentRunResult runCtx(void*, void* p, std::string_view prompt) {
    auto* c = static_cast<Ctx*>(p);
    return {true, "gpu=" + std::to_string(c->ordinal) + " " + std::string(prompt), {}};
}
}

int main() {
    Harness h;
    int authorityCookie = 7;
    DualGpuSchedulerConfig cfg;
    cfg.preferredPrimaryOrdinal = 0;
    cfg.preferredSecondaryOrdinal = 1;
    cfg.requireSecondary = true;
    cfg.requireDistinctDevices = true;
    cfg.sharedToolAuthority = &authorityCookie;

    AgentContextCallbacks cb{&h, &createCtx, &destroyCtx, &runCtx};
    {
        DualGpuIndependentAgentScheduler scheduler(cfg, cb);
        std::vector<AgentDevice> devices{
            {0, 0x1002, 0x7551, "R9700", true},
            {1, 0x1002, 0x747E, "RX7800XT", true}
        };
        std::string why;
        if (!scheduler.bind(devices, "coder-model", "reviewer-model", &why)) return 1;
        if (!scheduler.runPrimary("write patch").ok) return 2;
        if (!scheduler.runSecondary("review patch").ok) return 3;
        if (!scheduler.send({1,2,"diff","patch-1"})) return 4;
        auto msg = scheduler.receive(2);
        if (!msg || msg->payload != "patch-1") return 5;
        if (!scheduler.receipt().pass(true)) return 6;
        std::cout << scheduler.receipt().text(true);
    }
    if (!h.live.empty()) return 7;
    return 0;
}
