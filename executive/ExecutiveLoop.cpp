#include "executive/ExecutiveLoop.hpp"
#include "executive/ActionSelector.hpp"
#include "executive/ResourceArbiter.hpp"
#include "executive/ConflictResolver.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ExecutiveLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ActionSelector::Init();
    ResourceArbiter::Init();
    ConflictResolver::Init();
    s_initialized = true;
}

void ExecutiveLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Run all executive functions
    ActionSelector::OnTick();
    ResourceArbiter::OnTick();
    ConflictResolver::OnTick();
}

bool ExecutiveLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
