#include "prediction/PredictionLoop.hpp"
#include "prediction/StatePredictor.hpp"
#include "prediction/OutcomeSimulator.hpp"
#include "prediction/RiskAssessor.hpp"
#include "temporal/TemporalMemory.hpp"
#include "identity/IdentityCore.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void PredictionLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    StatePredictor::Init();
    OutcomeSimulator::Init();
    RiskAssessor::Init();
    s_initialized = true;
}

void PredictionLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all prediction components
    StatePredictor::OnTick();
    OutcomeSimulator::OnTick();
    RiskAssessor::OnTick();
    
    // Generate predictions from current state
    auto timeline = TemporalMemory::GetTimeline();
    if (!timeline.empty()) {
        auto current = timeline.back();
        auto prediction = StatePredictor::PredictNextState(current, 1);
        
        // Store prediction for later validation
        // (In a real system, this would be validated against actual outcomes)
    }
}

bool PredictionLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
