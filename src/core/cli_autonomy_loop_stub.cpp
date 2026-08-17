// cli_autonomy_loop_stub.cpp — Stub implementation for CLIAutonomyLoop
// Provides minimal definitions for RawrEngine linker closure.

#include "../cli/cli_autonomy_loop.h"

CLIAutonomyLoop& CLIAutonomyLoop::instance() {
    static CLIAutonomyLoop inst;
    return inst;
}

CLIAutonomyLoop::CLIAutonomyLoop()
    : m_state(AutonomyLoopState::Idle)
    , m_stopRequested(false)
    , m_engine(nullptr)
    , m_subAgentMgr(nullptr)
    , m_hasLastFailure(false)
    , m_actionsThisMinute(0)
    , m_consecutiveFailures(0)
{
    m_minuteWindowStart = std::chrono::steady_clock::now();
}

CLIAutonomyLoop::~CLIAutonomyLoop() {
    stop();
}

void CLIAutonomyLoop::setAgenticEngine(AgenticEngine* engine) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_engine = engine;
}

void CLIAutonomyLoop::setSubAgentManager(SubAgentManager* mgr) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_subAgentMgr = mgr;
}

void CLIAutonomyLoop::start() {
    m_state.store(AutonomyLoopState::Running);
}

void CLIAutonomyLoop::stop() {
    m_state.store(AutonomyLoopState::Idle);
}

void CLIAutonomyLoop::pause() {
    m_state.store(AutonomyLoopState::Paused);
}

void CLIAutonomyLoop::resume() {
    m_state.store(AutonomyLoopState::Running);
}

AutonomyLoopState CLIAutonomyLoop::getState() const {
    return m_state.load();
}

std::string CLIAutonomyLoop::getStatusString() const {
    return "[STUB] CLIAutonomyLoop idle";
}

std::string CLIAutonomyLoop::getDetailedStatus() const {
    return "[STUB] CLIAutonomyLoop detailed status";
}
