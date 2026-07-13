#include "security/SecurityLoop.hpp"
#include "security/ThreatDetector.hpp"
#include "security/IntrusionPrevention.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void SecurityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ThreatDetector::Init();
    IntrusionPrevention::Init();
    s_initialized = true;
}

void SecurityLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all security components
    ThreatDetector::OnTick();
    IntrusionPrevention::OnTick();
    
    // Auto-detect threats
    auto threats = ThreatDetector::DetectThreats();
    if (!threats.value("system_secure", true)) {
        // In a real implementation, this would trigger alerts
    }
}

bool SecurityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
