#include "resource/ResourceLoop.hpp"
#include "resource/ResourceAllocator.hpp"
#include "resource/OptimizationEngine.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ResourceLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ResourceAllocator::Init();
    OptimizationEngine::Init();
    s_initialized = true;
}

void ResourceLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all resource components
    ResourceAllocator::OnTick();
    OptimizationEngine::OnTick();
}

bool ResourceLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
