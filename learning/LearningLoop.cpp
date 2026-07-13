#include "learning/LearningLoop.hpp"
#include "learning/ExperienceReplay.hpp"
#include "learning/PolicyOptimizer.hpp"
#include "learning/MetaLearner.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void LearningLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ExperienceReplay::Init();
    PolicyOptimizer::Init();
    MetaLearner::Init();
    s_initialized = true;
}

void LearningLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Run all learning components
    ExperienceReplay::OnTick();
    PolicyOptimizer::OnTick();
    MetaLearner::OnTick();
}

bool LearningLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
