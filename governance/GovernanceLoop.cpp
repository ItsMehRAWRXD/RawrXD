#include "governance/GovernanceLoop.hpp"
#include "governance/PolicyEnforcer.hpp"
#include "governance/AuditLogger.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void GovernanceLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    PolicyEnforcer::Init();
    AuditLogger::Init();
    s_initialized = true;
}

void GovernanceLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all governance components
    PolicyEnforcer::OnTick();
    AuditLogger::OnTick();
}

bool GovernanceLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
