#include "communication/CommunicationLoop.hpp"
#include "communication/IntentTranslator.hpp"
#include "communication/ExplanationGenerator.hpp"
#include "communication/DialogueManager.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void CommunicationLoop::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    IntentTranslator::Init();
    ExplanationGenerator::Init();
    DialogueManager::Init();
    s_initialized = true;
}

void CommunicationLoop::Tick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update all communication components
    IntentTranslator::OnTick();
    ExplanationGenerator::OnTick();
    DialogueManager::OnTick();
}

bool CommunicationLoop::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}
