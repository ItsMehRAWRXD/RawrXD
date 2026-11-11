#include "wisdom/WisdomLoop.hpp"
#include "wisdom/ExperienceSynthesizer.hpp"
#include "wisdom/ContextualJudgment.hpp"
#include "wisdom/IntegrationEngine.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void WisdomLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ExperienceSynthesizer::Init();
    ContextualJudgment::Init();
    IntegrationEngine::Init();
    s_initialized = true;
}

void WisdomLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all wisdom components
    ExperienceSynthesizer::OnTick();
    ContextualJudgment::OnTick();
    IntegrationEngine::OnTick();
}

bool WisdomLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
