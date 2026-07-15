#include "intent/IntentLoop.hpp"
#include "intent/IntentModel.hpp"
#include "intent/TeleologicalReasoner.hpp"
#include "intent/GoalCausalAlignment.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void IntentLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    IntentModel::Init();
    TeleologicalReasoner::Init();
    GoalCausalAlignment::Init();
    s_initialized = true;
}

void IntentLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update intent progress
    IntentModel::OnTick();
    
    // Run teleological analysis
    TeleologicalReasoner::OnTick();
    
    // Check and maintain alignment
    GoalCausalAlignment::OnTick();
    
    auto alignment = GoalCausalAlignment::CheckAlignment();
    if (!alignment.value("aligned", true)) {
        // Auto-realign if significantly misaligned
        if (GoalCausalAlignment::GetAlignmentScore() < 0.5) {
            GoalCausalAlignment::Realign();
        }
    }
}

bool IntentLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
