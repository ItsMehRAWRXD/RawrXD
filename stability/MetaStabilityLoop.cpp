#include "stability/MetaStabilityLoop.hpp"
#include "stability/CoherenceModel.hpp"
#include "stability/DriftDetector.hpp"
#include "stability/InvariantEnforcer.hpp"
#include "consciousness/SelfModel.hpp"
#include "emergence/EmergenceLoop.hpp"
#include <chrono>

static float stabilityScore = 1.0f;
static int stabilityTicks = 0;

void MetaStabilityLoop::Init() {
    CoherenceModel::Init();
    DriftDetector::Init();
    InvariantEnforcer::Init();
    stabilityScore = 1.0f;
    stabilityTicks = 0;
}

void MetaStabilityLoop::Tick() {
    // Get current self-model
    auto self = SelfModel::Get();
    
    // Check coherence
    float coherence = CoherenceModel::ComputeCoherence(self);
    
    // Check for drift
    DriftDetector::RecordSnapshot("self_model", self);
    bool hasDrifted = DriftDetector::HasDrifted("self_model", self);
    
    // Validate invariants
    bool invariantsValid = InvariantEnforcer::Validate(self);
    auto violations = InvariantEnforcer::GetViolations(self);
    
    // Compute stability score
    stabilityScore = coherence * (hasDrifted ? 0.5f : 1.0f) * (invariantsValid ? 1.0f : 0.3f);
    
    // Update self-model with stability info
    SelfModel::Update({
        {"stability_score", stabilityScore},
        {"coherence", coherence},
        {"has_drifted", hasDrifted},
        {"invariant_violations", violations}
    });
    
    stabilityTicks++;
    
    // If unstable, trigger emergence loop to re-stabilize
    if (!IsStable()) {
        EmergenceLoop::Tick();
    }
}

void MetaStabilityLoop::Shutdown() {
    // cleanup
}

float MetaStabilityLoop::GetStabilityScore() {
    return stabilityScore;
}

bool MetaStabilityLoop::IsStable() {
    return stabilityScore > 0.6f;
}
