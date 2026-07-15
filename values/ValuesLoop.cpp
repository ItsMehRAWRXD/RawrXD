#include "values/ValuesLoop.hpp"
#include "values/ValueLearner.hpp"
#include "values/PreferenceModel.hpp"
#include "values/AlignmentVerifier.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void ValuesLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ValueLearner::Init();
    PreferenceModel::Init();
    AlignmentVerifier::Init();
    s_initialized = true;
}

void ValuesLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    ValueLearner::OnTick();
    PreferenceModel::OnTick();
    AlignmentVerifier::OnTick();
}

bool ValuesLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
