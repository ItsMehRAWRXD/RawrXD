#include "temporal/TemporalLoop.hpp"
#include "temporal/TemporalMemory.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void TemporalLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    TemporalMemory::Init();
    s_initialized = true;
}

void TemporalLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    TemporalMemory::AddSnapshot(IdentityCore::Get());
}

bool TemporalLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
