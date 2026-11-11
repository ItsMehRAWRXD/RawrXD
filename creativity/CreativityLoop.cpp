#include "creativity/CreativityLoop.hpp"
#include "creativity/IdeaGenerator.hpp"
#include "creativity/SolutionInnovator.hpp"
#include "creativity/PatternSynthesizer.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void CreativityLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    IdeaGenerator::Init();
    SolutionInnovator::Init();
    PatternSynthesizer::Init();
    s_initialized = true;
}

void CreativityLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all creativity components
    IdeaGenerator::OnTick();
    SolutionInnovator::OnTick();
    PatternSynthesizer::OnTick();
}

bool CreativityLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
