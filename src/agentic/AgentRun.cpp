// ============================================================================
// AgentRun.cpp — AgentRun Implementation
// ============================================================================

#include "AgentRun.hpp"
#include <random>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Helpers
// ============================================================================
static std::string GenerateRunId() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    uint64_t val = dis(gen);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << val;
    return "run_" + oss.str();
}

// ============================================================================
// ToolCall
// ============================================================================
ToolCall::ToolCall(const std::string& n, const nlohmann::json& a,
                   const std::string& run, uint32_t turn, uint32_t seq)
    : id(GenerateRunId()), name(n), arguments(a), runId(run),
      turnId(turn), sequence(seq), createdAt(std::chrono::steady_clock::now()) {}

// ============================================================================
// ToolResult
// ============================================================================
ToolResult::ToolResult(const ToolCallResult& tcr, const std::string& cid)
    : callId(cid), success(tcr.isSuccess()), output(tcr.output),
      error(tcr.error), durationMs(tcr.durationMs), exitCode(0),
      completedAt(std::chrono::steady_clock::now()) {
    if (!tcr.metadata.empty()) metadata = tcr.metadata;
}

// ============================================================================
// AgentRun
// ============================================================================
AgentRun::AgentRun() {
    m_runId = GenerateRunId();
}

AgentRun::AgentRun(const AgentRunConfig& config) : m_config(config) {
    m_runId = GenerateRunId();
    Configure(config);
}

AgentRun::~AgentRun() = default;

void AgentRun::Configure(const AgentRunConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;

    // Initialize budgets from config
    m_toolBudget = ToolBudget(
        config.maxToolCalls,
        config.toolExtensionSize,
        config.maxToolExtensions,
        config.toolHardCap
    );
    m_turnBudget = TurnBudget(config.maxTurns, config.turnHardCap);

    // Apply adaptive sizing if complexity is set
    if (config.complexity != TaskComplexity::Normal) {
        ApplyAdaptiveBudget(config.complexity, m_toolBudget, m_turnBudget);
    }
}

void AgentRun::Start(const std::string& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_task = task;
    m_startTime = std::chrono::steady_clock::now();
    m_toolCallCount.store(0);
    m_turnCount.store(0);
    m_transcript.Reset();
    m_transcript.SetInitialPrompt(task);
    m_transcript.SetModel(m_config.model);
    m_transcript.SetWorkingDirectory(m_config.workingDirectory);
    SetState(AgentRunState::Running);
}

void AgentRun::Complete(AgentTerminationReason reason, const std::string& finalAnswer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_termReason = reason;
    m_finalAnswer = finalAnswer;
    m_endTime = std::chrono::steady_clock::now();

    AgentRunState target = AgentRunState::Complete;
    switch (reason) {
        case AgentTerminationReason::Cancelled:      target = AgentRunState::Cancelled; break;
        case AgentTerminationReason::Timeout:        target = AgentRunState::Timeout; break;
        case AgentTerminationReason::BudgetExhausted: target = AgentRunState::BudgetExhausted; break;
        case AgentTerminationReason::Failure:
        case AgentTerminationReason::ContextExhausted:
        case AgentTerminationReason::StepLimitReached: target = AgentRunState::Error; break;
        default: target = AgentRunState::Complete; break;
    }
    SetState(target);

    if (!m_config.transcriptPath.empty()) {
        m_transcript.SaveToFile(m_config.transcriptPath);
    }
}

void AgentRun::Cancel() {
    SetState(AgentRunState::Cancelled);
    m_termReason = AgentTerminationReason::Cancelled;
    m_endTime = std::chrono::steady_clock::now();
}

void AgentRun::Fail(const std::string& error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_error = error;
    m_termReason = AgentTerminationReason::Failure;
    m_endTime = std::chrono::steady_clock::now();
    SetState(AgentRunState::Error);
}

// ---- Budget ----
bool AgentRun::CanCallTool(uint32_t count) const {
    return m_toolBudget.canCall() && m_toolBudget.getRemaining() >= count;
}

bool AgentRun::CanTakeTurn() const {
    return m_turnBudget.canTurn();
}

bool AgentRun::RequestToolExtension(uint32_t requested, uint32_t& grantedOut) {
    auto result = m_toolBudget.extend(requested, grantedOut);
    if (result == BudgetExtensionResult::Denied ||
        result == BudgetExtensionResult::HardCapReached ||
        result == BudgetExtensionResult::MaxExtensionsReached) {
        return false;
    }
    return true;
}

bool AgentRun::ConsumeToolCalls(uint32_t count) {
    if (!m_toolBudget.consume(count)) {
        FireBudgetExhausted(true);
        return false;
    }
    m_toolCallCount.fetch_add(count);
    return true;
}

bool AgentRun::ConsumeTurn() {
    if (!m_turnBudget.consume(1)) {
        FireBudgetExhausted(false);
        return false;
    }
    m_turnCount.fetch_add(1);
    return true;
}

void AgentRun::RecordToolCall(const ToolCall& call) {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Record in transcript if transcript supports it
    // For now, just track count
    (void)call;
}

void AgentRun::RecordToolResult(const ToolResult& result) {
    std::lock_guard<std::mutex> lock(m_mutex);
    (void)result;
}

// ---- Time ----
bool AgentRun::IsTimedOut() const {
    if (m_config.totalTimeoutSec == 0) return false;
    return GetElapsedSec() >= m_config.totalTimeoutSec;
}

uint32_t AgentRun::GetElapsedSec() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_startTime).count();
    return static_cast<uint32_t>(elapsed);
}

uint32_t AgentRun::GetRemainingSec() const {
    if (m_config.totalTimeoutSec == 0) return 0; // No timeout
    uint32_t elapsed = GetElapsedSec();
    return (elapsed >= m_config.totalTimeoutSec) ? 0 : (m_config.totalTimeoutSec - elapsed);
}

// ---- Trace ----
std::string AgentRun::GetTraceSummary() const {
    std::ostringstream oss;
    oss << "AgentRun[" << m_runId << "]\n";
    oss << "  State: " << static_cast<int>(m_state.load()) << "\n";
    oss << "  Task: " << m_task.substr(0, 80) << "\n";
    oss << "  " << m_toolBudget.toString() << "\n";
    oss << "  " << m_turnBudget.toString() << "\n";
    oss << "  Tool calls: " << m_toolCallCount.load() << "\n";
    oss << "  Turns: " << m_turnCount.load() << "\n";
    oss << "  Elapsed: " << GetElapsedSec() << "s\n";
    return oss.str();
}

void AgentRun::SaveTranscript() const {
    if (!m_config.transcriptPath.empty()) {
        m_transcript.SaveToFile(m_config.transcriptPath);
    }
}

// ---- Callbacks ----
void AgentRun::SetStateChangeCallback(StateChangeCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stateCallback = std::move(cb);
}

void AgentRun::SetBudgetExhaustedCallback(BudgetExhaustedCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_budgetCallback = std::move(cb);
}

// ---- Internal ----
void AgentRun::SetState(AgentRunState newState) {
    AgentRunState old = m_state.exchange(newState);
    if (old != newState && m_stateCallback) {
        m_stateCallback(old, newState);
    }
}

void AgentRun::FireBudgetExhausted(bool isToolBudget) {
    if (m_budgetCallback) {
        m_budgetCallback(*this, isToolBudget);
    }
}

} // namespace Agent
} // namespace RawrXD
