#pragma once

#include <string>
#include <cstdint>

namespace rawrxd {
namespace agent {

enum class AgentState {
    Idle,
    Observing,
    Planning,
    Executing,
    Reviewing,
    Testing,
    Recovering,
    Completed,
    Failed
};

enum class AgentEvent {
    UserRequest,
    PlanReady,
    CodeGenerated,
    ToolCompleted,
    TestPassed,
    TestFailed,
    ErrorDetected,
    Timeout,
    Cancelled
};

inline const char* AgentStateToString(AgentState s) {
    switch (s) {
        case AgentState::Idle:       return "Idle";
        case AgentState::Observing:  return "Observing";
        case AgentState::Planning:   return "Planning";
        case AgentState::Executing:  return "Executing";
        case AgentState::Reviewing:  return "Reviewing";
        case AgentState::Testing:    return "Testing";
        case AgentState::Recovering: return "Recovering";
        case AgentState::Completed:  return "Completed";
        case AgentState::Failed:     return "Failed";
        default: return "Unknown";
    }
}

inline const char* AgentEventToString(AgentEvent e) {
    switch (e) {
        case AgentEvent::UserRequest:    return "UserRequest";
        case AgentEvent::PlanReady:      return "PlanReady";
        case AgentEvent::CodeGenerated:  return "CodeGenerated";
        case AgentEvent::ToolCompleted:  return "ToolCompleted";
        case AgentEvent::TestPassed:     return "TestPassed";
        case AgentEvent::TestFailed:     return "TestFailed";
        case AgentEvent::ErrorDetected:  return "ErrorDetected";
        case AgentEvent::Timeout:        return "Timeout";
        case AgentEvent::Cancelled:      return "Cancelled";
        default: return "Unknown";
    }
}

} // namespace agent
} // namespace rawrxd
