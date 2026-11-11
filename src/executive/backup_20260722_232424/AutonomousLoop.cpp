// ============================================================================
// AutonomousLoop.cpp - Implementation
// ============================================================================

#include "AutonomousLoop.hpp"
#include "ExecutiveDirector.hpp"
#include <iostream>
#include <thread>

namespace RawrXD {
namespace Executive {

struct AutonomousLoop::Impl {
    ExecutiveDirector* director = nullptr;
    CycleConfig config;
    CycleStats stats;
    
    std::atomic<float> urgency_{1.0f};
    std::chrono::steady_clock::time_point phaseStart;
    
    // Handlers
    std::function<void()> observeHandler;
    std::function<void()> thinkHandler;
    std::function<void()> planHandler;
    std::function<void()> executeHandler;
    std::function<void()> reflectHandler;
    std::function<void()> learnHandler;
    std::function<void()> sleepHandler;
};

AutonomousLoop::AutonomousLoop() : pImpl_(std::make_unique<Impl>()) {}
AutonomousLoop::~AutonomousLoop() = default;

bool AutonomousLoop::Initialize(ExecutiveDirector* director, const CycleConfig& config) {
    pImpl_->director = director;
    pImpl_->config = config;
    pImpl_->stats.startedAt = std::chrono::steady_clock::now();
    return true;
}

void AutonomousLoop::Shutdown() {
    Stop();
}

void AutonomousLoop::Start() {
    if (isRunning_.exchange(true)) return;
    
    std::cout << "[AutonomousLoop] Starting cognitive cycle...\n";
    
    // Start with observation
    TransitionTo(CyclePhase::OBSERVING);
    
    // The actual loop runs in the ExecutiveDirector's thread
    // This just sets up the initial state
}

void AutonomousLoop::Stop() {
    isRunning_ = false;
    shouldShutdown_ = true;
}

void AutonomousLoop::Pause() {
    isPaused_ = true;
}

void AutonomousLoop::Resume() {
    isPaused_ = false;
}

void AutonomousLoop::Interrupt(const std::string& reason) {
    std::cout << "[AutonomousLoop] Interrupted: " << reason << "\n";
    // Handle interrupt logic
}

void AutonomousLoop::SetObserveHandler(std::function<void()> handler) { pImpl_->observeHandler = handler; }
void AutonomousLoop::SetThinkHandler(std::function<void()> handler) { pImpl_->thinkHandler = handler; }
void AutonomousLoop::SetPlanHandler(std::function<void()> handler) { pImpl_->planHandler = handler; }
void AutonomousLoop::SetExecuteHandler(std::function<void()> handler) { pImpl_->executeHandler = handler; }
void AutonomousLoop::SetReflectHandler(std::function<void()> handler) { pImpl_->reflectHandler = handler; }
void AutonomousLoop::SetLearnHandler(std::function<void()> handler) { pImpl_->learnHandler = handler; }
void AutonomousLoop::SetSleepHandler(std::function<void()> handler) { pImpl_->sleepHandler = handler; }

void AutonomousLoop::SetConfig(const CycleConfig& config) { pImpl_->config = config; }
CycleConfig AutonomousLoop::GetConfig() const { return pImpl_->config; }

void AutonomousLoop::SetUrgency(float urgency) {
    pImpl_->urgency_ = std::clamp(urgency, 0.1f, 10.0f);
}

void AutonomousLoop::Loop() {
    // The actual loop is managed by ExecutiveDirector
    // This method would be called if AutonomousLoop had its own thread
}

void AutonomousLoop::ExecutePhase(CyclePhase phase) {
    pImpl_->phaseStart = std::chrono::steady_clock::now();
    
    switch (phase) {
        case CyclePhase::OBSERVING:
            if (pImpl_->observeHandler) pImpl_->observeHandler();
            break;
        case CyclePhase::THINKING:
            if (pImpl_->thinkHandler) pImpl_->thinkHandler();
            break;
        case CyclePhase::PLANNING:
            if (pImpl_->planHandler) pImpl_->planHandler();
            break;
        case CyclePhase::EXECUTING:
            if (pImpl_->executeHandler) pImpl_->executeHandler();
            break;
        case CyclePhase::REFLECTING:
            if (pImpl_->reflectHandler) pImpl_->reflectHandler();
            break;
        case CyclePhase::LEARNING:
            if (pImpl_->learnHandler) pImpl_->learnHandler();
            break;
        case CyclePhase::SLEEPING:
            if (pImpl_->sleepHandler) pImpl_->sleepHandler();
            break;
    }
}

void AutonomousLoop::TransitionTo(CyclePhase newPhase) {
    currentPhase_ = newPhase;
    pImpl_->phaseStart = std::chrono::steady_clock::now();
    
    // Update stats
    pImpl_->stats.totalCycles++;
    pImpl_->stats.cyclesByPhase[static_cast<int>(newPhase)]++;
}

CycleStats AutonomousLoop::GetStats() const {
    return pImpl_->stats;
}

void AutonomousLoop::ResetStats() {
    pImpl_->stats = CycleStats{};
    pImpl_->stats.startedAt = std::chrono::steady_clock::now();
}

std::string AutonomousLoop::GetPhaseName(CyclePhase phase) const {
    switch (phase) {
        case CyclePhase::OBSERVING: return "OBSERVING";
        case CyclePhase::THINKING: return "THINKING";
        case CyclePhase::PLANNING: return "PLANNING";
        case CyclePhase::EXECUTING: return "EXECUTING";
        case CyclePhase::REFLECTING: return "REFLECTING";
        case CyclePhase::LEARNING: return "LEARNING";
        case CyclePhase::SLEEPING: return "SLEEPING";
        default: return "UNKNOWN";
    }
}

double AutonomousLoop::GetCurrentPhaseElapsedMs() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now - pImpl_->phaseStart).count();
}

double AutonomousLoop::GetEstimatedCycleCompletionMs() const {
    // Calculate based on current phase and config
    return 0.0;
}

} // namespace Executive
} // namespace RawrXD
