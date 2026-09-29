// AgentAuthority.cpp — RAWRXD_AGENT_AUTHORITY_001
#include "AgentAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace agent {
static std::atomic<int> g_plans{0};
static std::atomic<int> g_acts{0};
static std::atomic<int> g_verifies{0};
static std::atomic<int> g_verifyFails{0};
static std::atomic<int> g_lastState{(int)State::Ask};
static const char* stateName(State s) {
    switch (s) {
        case State::Ask:         return "Ask";
        case State::Plan:        return "Plan";
        case State::Code:        return "Code";
        case State::Debug:       return "Debug";
        case State::Orchestrate: return "Orchestrate";
        case State::Certify:     return "Certify";
    }
    return "Unknown";
}
void plan(const std::string& task) {
    g_plans.fetch_add(1);
    g_lastState.store((int)State::Plan);
}
void act(const std::string& action) {
    g_acts.fetch_add(1);
    g_lastState.store((int)State::Code);
}
bool verify(const std::string& result) {
    g_verifies.fetch_add(1);
    g_lastState.store((int)State::Certify);
    bool ok = !result.empty();
    if (!ok) g_verifyFails.fetch_add(1);
    return ok;
}
void writeAgentReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_AGENT_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "PLANS", g_plans.load());
    rawrxd::receipt::writeKeyValueInt(path, "ACTS", g_acts.load());
    rawrxd::receipt::writeKeyValueInt(path, "VERIFIES", g_verifies.load());
    rawrxd::receipt::writeKeyValueInt(path, "VERIFY_FAILS", g_verifyFails.load());
    rawrxd::receipt::writeKeyValue(path, "LAST_STATE", stateName((State)g_lastState.load()));
    rawrxd::receipt::endGate(path, (g_verifyFails.load() == 0 && g_acts.load() > 0) ? "PASS" : "HOLD");
}
}} // namespace rawrxd::agent