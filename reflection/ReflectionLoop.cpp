#include "reflection/ReflectionLoop.hpp"
#include "reflection/BeliefAnalyzer.hpp"
#include "reflection/DecisionTracer.hpp"
#include "reflection/CognitiveAuditor.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ReflectionLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    BeliefAnalyzer::Init();
    DecisionTracer::Init();
    CognitiveAuditor::Init();
    s_initialized = true;
}

void ReflectionLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Run all reflection components
    BeliefAnalyzer::OnTick();
    DecisionTracer::OnTick();
    CognitiveAuditor::OnTick();
    
    // Periodic cognitive audit
    static int tickCount = 0;
    if (++tickCount % 60 == 0) { // Every 60 ticks
        CognitiveAuditor::AuditCognitiveState();
    }
}

bool ReflectionLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
