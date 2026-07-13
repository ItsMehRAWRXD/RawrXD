#include "observability/ObservabilityLoop.hpp"
#include "observability/MetricsCollector.hpp"
#include "observability/DistributedTracer.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ObservabilityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    MetricsCollector::Init();
    DistributedTracer::Init();
    s_initialized = true;
}

void ObservabilityLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all observability components
    MetricsCollector::OnTick();
    DistributedTracer::OnTick();
}

bool ObservabilityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
