#include "identity/ContinuityLoop.hpp"
#include "identity/SelfConsistencyValidator.hpp"
#include "identity/IdentityStabilizer.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ContinuityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    SelfConsistencyValidator::Init();
    IdentityStabilizer::Init();
    s_initialized = true;
}

void ContinuityLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    bool ok = SelfConsistencyValidator::Validate();
    IdentityStabilizer::Stabilize();
    
    if (!ok) {
        IdentityCore::Update({
            {"continuity_score", 0.5}
        });
    }
}

bool ContinuityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
