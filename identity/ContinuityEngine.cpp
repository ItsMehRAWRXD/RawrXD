#include "identity/ContinuityEngine.hpp"
#include "identity/IdentityCore.hpp"
#include "stability/CoherenceModel.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ContinuityEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

double ContinuityEngine::ComputeContinuity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto id = IdentityCore::Get();
    auto coh = CoherenceModel::ComputeCoherence(id);
    
    // Continuity is derived from coherence and identity stability
    double continuity = coh * 0.8 + 0.2; // Base continuity with coherence modulation
    return continuity;
}
