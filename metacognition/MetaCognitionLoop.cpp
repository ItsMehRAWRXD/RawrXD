#include "metacognition/MetaCognitionLoop.hpp"
#include "metacognition/ArchitectureAnalyzer.hpp"
#include "metacognition/SelfOptimizer.hpp"
#include "metacognition/LearningScheduler.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void MetaCognitionLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ArchitectureAnalyzer::Init();
    SelfOptimizer::Init();
    LearningScheduler::Init();
    s_initialized = true;
}

void MetaCognitionLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all meta-cognition components
    ArchitectureAnalyzer::OnTick();
    SelfOptimizer::OnTick();
    LearningScheduler::OnTick();
}

bool MetaCognitionLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
