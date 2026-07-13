#include "mastery/MasteryLoop.hpp"
#include "mastery/SystemOrchestrator.hpp"
#include "mastery/CrossLayerIntegrator.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void MasteryLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    SystemOrchestrator::Init();
    CrossLayerIntegrator::Init();
    s_initialized = true;
}

void MasteryLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all mastery components
    SystemOrchestrator::OnTick();
    CrossLayerIntegrator::OnTick();
}

bool MasteryLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
