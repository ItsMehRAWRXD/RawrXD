#include "scalability/ScalabilityLoop.hpp"
#include "scalability/LoadBalancer.hpp"
#include "scalability/AutoScaler.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ScalabilityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    LoadBalancer::Init();
    AutoScaler::Init();
    s_initialized = true;
}

void ScalabilityLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all scalability components
    LoadBalancer::OnTick();
    AutoScaler::OnTick();
}

bool ScalabilityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
