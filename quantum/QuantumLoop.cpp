#include "quantum/QuantumLoop.hpp"
#include "quantum/ProbabilityEngine.hpp"
#include "quantum/UncertaintyQuantifier.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void QuantumLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ProbabilityEngine::Init();
    UncertaintyQuantifier::Init();
    s_initialized = true;
}

void QuantumLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all quantum components
    ProbabilityEngine::OnTick();
    UncertaintyQuantifier::OnTick();
}

bool QuantumLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
