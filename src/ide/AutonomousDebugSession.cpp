/*===========================================================================
 * AutonomousDebugSession.cpp
 * RawrXD IDE - Autonomous Debug Session Implementation
 *===========================================================================*/

#include "DebugAgentBridge.h"
#include <windows.h>
#include <process.h>

namespace RawrXD {

/*===========================================================================
 * AUTONOMOUS DEBUG SESSION
 *===========================================================================*/

AutonomousDebugSession::AutonomousDebugSession(DebugAgentBridge* bridge)
    : m_bridge(bridge)
    , m_state(AutonomousDebugState::Idle)
    , m_autoApplyThreshold(0.90f)
    , m_maxAttempts(3)
    , m_humanApproval(true)
    , m_currentAttempt(0) {
}

AutonomousDebugSession::~AutonomousDebugSession() {
    StopSession();
}

void AutonomousDebugSession::StartSession(const std::string& targetExecutable) {
    if (m_state != AutonomousDebugState::Idle) {
        return; // Already running
    }
    
    m_currentAttempt = 0;
    m_attemptHistory.clear();
    TransitionTo(AutonomousDebugState::Observing);
    
    // Launch debugger
    auto& svc = DebuggerService::GetInstance();
    if (!svc.LaunchProcess(targetExecutable)) {
        TransitionTo(AutonomousDebugState::Failed);
        return;
    }
    
    // Set up bridge callback
    m_bridge->SetFixCallback([this](const AgentFixProposal& proposal) {
        OnFixReceived(proposal);
    });
    
    // Set up bridge progress
    m_bridge->SetProgressCallback([this](const std::string& status) {
        // Could update UI here
        (void)status;
    });
}

void AutonomousDebugSession::StopSession() {
    if (m_state == AutonomousDebugState::Idle) {
        return;
    }
    
    // Stop debugger
    auto& svc = DebuggerService::GetInstance();
    svc.StopDebugging();
    
    TransitionTo(AutonomousDebugState::Idle);
}

std::string AutonomousDebugSession::GetStateDescription() const {
    switch (m_state) {
        case AutonomousDebugState::Idle:        return "Idle";
        case AutonomousDebugState::Observing:   return "Observing execution";
        case AutonomousDebugState::Analyzing:   return "AI analyzing exception";
        case AutonomousDebugState::Proposing:   return "Fix proposed - awaiting approval";
        case AutonomousDebugState::Applying:    return "Applying fix";
        case AutonomousDebugState::Rebuilding:  return "Rebuilding project";
        case AutonomousDebugState::Validating:  return "Validating fix";
        case AutonomousDebugState::Complete:    return "Fix successful";
        case AutonomousDebugState::Failed:      return "Could not fix";
        default: return "Unknown";
    }
}

void AutonomousDebugSession::ApproveCurrentFix() {
    if (m_state != AutonomousDebugState::Proposing) {
        return;
    }
    
    TransitionTo(AutonomousDebugState::Applying);
    
    // Apply the fix
    if (m_bridge->ApplyFixes(m_currentProposal.patches)) {
        TransitionTo(AutonomousDebugState::Rebuilding);
        
        // Trigger rebuild (async)
        // TODO: Integrate with IDE build system
        // For now, simulate
        Sleep(1000);
        OnBuildComplete(true);
    } else {
        TransitionTo(AutonomousDebugState::Failed);
    }
}

void AutonomousDebugSession::RejectCurrentFix() {
    if (m_state != AutonomousDebugState::Proposing) {
        return;
    }
    
    // Update stats
    auto stats = m_bridge->GetStats();
    (void)stats; // Could log rejection
    
    // Try again or fail
    if (m_currentAttempt < m_maxAttempts) {
        TransitionTo(AutonomousDebugState::Observing);
        
        // Continue debugging
        auto& svc = DebuggerService::GetInstance();
        svc.ContinueExecution();
    } else {
        TransitionTo(AutonomousDebugState::Failed);
    }
}

void AutonomousDebugSession::RetryAnalysis() {
    if (m_state != AutonomousDebugState::Proposing && 
        m_state != AutonomousDebugState::Failed) {
        return;
    }
    
    // Re-run analysis with different parameters
    // TODO: Implement retry with different prompt strategies
}

void AutonomousDebugSession::OnExceptionReceived(const AgentDebugContext& context) {
    (void)context;
    
    if (m_state != AutonomousDebugState::Observing) {
        return;
    }
    
    TransitionTo(AutonomousDebugState::Analyzing);
    
    // Bridge will call OnFixReceived when analysis complete
}

void AutonomousDebugSession::OnFixReceived(const AgentFixProposal& proposal) {
    if (m_state != AutonomousDebugState::Analyzing) {
        return;
    }
    
    m_currentAttempt++;
    m_currentProposal = proposal;
    m_attemptHistory.push_back(proposal);
    
    TransitionTo(AutonomousDebugState::Proposing);
    
    // Auto-apply if confidence is high enough and human approval not required
    if (!m_humanApproval && proposal.confidence >= m_autoApplyThreshold) {
        ApproveCurrentFix();
    }
    // Otherwise, wait for human approval
}

void AutonomousDebugSession::OnBuildComplete(bool success) {
    if (m_state != AutonomousDebugState::Rebuilding) {
        return;
    }
    
    if (success) {
        TransitionTo(AutonomousDebugState::Validating);
        
        // Re-launch debugger to validate
        // TODO: Implement validation run
        Sleep(500);
        OnValidationComplete(true);
    } else {
        TransitionTo(AutonomousDebugState::Failed);
    }
}

void AutonomousDebugSession::OnValidationComplete(bool passed) {
    if (m_state != AutonomousDebugState::Validating) {
        return;
    }
    
    if (passed) {
        TransitionTo(AutonomousDebugState::Complete);
    } else {
        // Fix didn't work, try again
        if (m_currentAttempt < m_maxAttempts) {
            TransitionTo(AutonomousDebugState::Observing);
            
            // Continue debugging
            auto& svc = DebuggerService::GetInstance();
            svc.ContinueExecution();
        } else {
            TransitionTo(AutonomousDebugState::Failed);
        }
    }
}

void AutonomousDebugSession::TransitionTo(AutonomousDebugState newState) {
    m_state = newState;
    ExecuteCurrentState();
}

void AutonomousDebugSession::ExecuteCurrentState() {
    switch (m_state) {
        case AutonomousDebugState::Observing:
            // Continue execution
            {
                auto& svc = DebuggerService::GetInstance();
                svc.ContinueExecution();
            }
            break;
            
        case AutonomousDebugState::Analyzing:
            // Waiting for agent analysis
            break;
            
        case AutonomousDebugState::Proposing:
            // Waiting for human approval or auto-apply
            break;
            
        case AutonomousDebugState::Applying:
            // Applying fix in progress
            break;
            
        case AutonomousDebugState::Rebuilding:
            // Build in progress
            break;
            
        case AutonomousDebugState::Validating:
            // Validation in progress
            break;
            
        case AutonomousDebugState::Complete:
            // Success - could notify UI
            break;
            
        case AutonomousDebugState::Failed:
            // Failed - could notify UI
            break;
            
        case AutonomousDebugState::Idle:
        default:
            break;
    }
}

} // namespace RawrXD
