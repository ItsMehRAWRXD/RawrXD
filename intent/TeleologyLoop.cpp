#include "intent/TeleologyLoop.hpp"
#include "intent/IntentModel.hpp"
#include "intent/TeleologyEngine.hpp"
#include "intent/GoalCausalAlignment.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void TeleologyLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    IntentModel::Init();
    TeleologyEngine::Init();
    GoalCausalAlignment::Init();
    s_initialized = true;
}

void TeleologyLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all teleology components
    IntentModel::OnTick();
    TeleologyEngine::OnTick();
    GoalCausalAlignment::OnTick();
    
    // Check goal-causal alignment
    bool aligned = GoalCausalAlignment::Check();
    
    // Update intent model with alignment status
    IntentModel::Update({
        {"alignment_ok", aligned},
        {"last_alignment_check", std::chrono::system_clock::now().time_since_epoch().count()}
    });
}

bool TeleologyLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
