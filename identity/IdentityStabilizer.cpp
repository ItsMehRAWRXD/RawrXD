#include "identity/IdentityStabilizer.hpp"
#include "identity/IdentityCore.hpp"
#include "identity/ContinuityEngine.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void IdentityStabilizer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

void IdentityStabilizer::Stabilize() {
    std::lock_guard<std::mutex> lock(s_mutex);
    double continuity = ContinuityEngine::ComputeContinuity();
    
    IdentityCore::Update({
        {"continuity_score", continuity}
    });
}
