#include "ethics/EthicsLoop.hpp"
#include "ethics/MoralFramework.hpp"
#include "ethics/EthicalConstraint.hpp"
#include "ethics/StakeholderAnalysis.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void EthicsLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    MoralFramework::Init();
    EthicalConstraint::Init();
    StakeholderAnalysis::Init();
    s_initialized = true;
}

void EthicsLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all ethics components
    MoralFramework::OnTick();
    EthicalConstraint::OnTick();
    StakeholderAnalysis::OnTick();
}

bool EthicsLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
