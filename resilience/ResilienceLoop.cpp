#include "resilience/ResilienceLoop.hpp"
#include "resilience/FaultDetector.hpp"
#include "resilience/GracefulDegradation.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ResilienceLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    FaultDetector::Init();
    GracefulDegradation::Init();
    s_initialized = true;
}

void ResilienceLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all resilience components
    FaultDetector::OnTick();
    GracefulDegradation::OnTick();
    
    // Auto-detect and handle faults
    auto faults = FaultDetector::DetectFaults();
    if (!faults.value("system_healthy", true)) {
        for (const auto& fault : faults["faults"]) {
            std::string component = fault.value("component", "");
            if (!component.empty()) {
                GracefulDegradation::TriggerDegradation(component, "auto");
            }
        }
    }
}

bool ResilienceLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
