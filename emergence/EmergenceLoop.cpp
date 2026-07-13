#include "emergence/EmergenceLoop.hpp"
#include "emergence/ContradictionDetector.hpp"
#include "emergence/UncertaintyModel.hpp"
#include "emergence/EmergentPatternTracker.hpp"
#include "emergence/BehaviorGovernor.hpp"
#include "cognition/CognitiveLoop.hpp"
#include "consciousness/MetacognitiveLoop.hpp"

void EmergenceLoop::Init() {
    ContradictionDetector::Init();
    UncertaintyModel::Init();
    EmergentPatternTracker::Init();
    BehaviorGovernor::Init();
}

void EmergenceLoop::Tick() {
    // run cognitive and metacognitive layers first
    CognitiveLoop::Tick();
    MetacognitiveLoop::Tick();
    
    // detect contradictions in beliefs
    auto contradictions = ContradictionDetector::FindAll();
    if (!contradictions.empty()) {
        UncertaintyModel::SetUncertainty("beliefs", 0.3f);
    }
    
    // record current state for pattern detection
    EmergentPatternTracker::Record({
        {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()},
        {"contradictions", contradictions.size()}
    });
    
    // validate actions against constraints
    // (actions would come from autonomy layer)
}

void EmergenceLoop::Shutdown() {
    // cleanup
}
