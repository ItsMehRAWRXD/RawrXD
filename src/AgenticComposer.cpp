#include "AgenticComposer.h"
#include <iostream>
#include <thread>

namespace RawrXD {
namespace IDE {

AgenticComposer::AgenticComposer() {
    m_rewriteEngine = std::make_unique<MultiFileRewriteEngine>();
}

void AgenticComposer::startGoal(const std::string& userGoal, const std::vector<std::string>& files) {
    m_state = ComposerState::Planning;
    m_steps.clear();
    
    // Add planning step
    m_steps.push_back({"Goal Analysis", "Analyze cross-file dependencies for: " + userGoal, false, false});

    // Launch async planning task using thread pool
    std::thread([&](std::string goal, std::vector<std::string> targetFiles) {
        try {
            // Step 1: Analyze dependencies
            auto dependencies = m_rewriteEngine->analyzeDependencies(targetFiles);
            
            // Step 2: Generate coordinated edit plan
            m_activePlan = m_rewriteEngine->planCoordinatedEdits(goal, targetFiles, dependencies);
            
            // Update UI on main thread
            m_steps[0].completed = true;
            m_steps.push_back({
                "Review Plan", 
                "Coordinated edits generated for " + std::to_string(targetFiles.size()) + " files.", 
                false, 
                false
            });
            
            // Calculate complexity score
            int complexity = 0;
            for (const auto& edit : m_activePlan.edits) {
                complexity += edit.complexity;
            }
            
            // Add complexity warning if needed
            if (complexity > 50) {
                m_steps.push_back({
                    "Complexity Warning",
                    "High complexity detected (" + std::to_string(complexity) + "). Review carefully.",
                    false,
                    false
                });
            }
            
            m_state = ComposerState::ReviewingChange;
            
            // Notify UI of state change
            if (m_onStateChanged) {
                m_onStateChanged(m_state);
            }
        } catch (const std::exception& e) {
            m_steps[0].failed = true;
            m_steps.push_back({"Planning Failed", std::string("Error: ") + e.what(), true, true});
            m_state = ComposerState::Failed;
            
            if (m_onStateChanged) {
                m_onStateChanged(m_state);
            }
        }
    }, userGoal, files).detach();
}

void AgenticComposer::approveStep() {
    if (m_state != ComposerState::ReviewingChange) return;

    m_state = ComposerState::Applying;
    m_steps.back().completed = true;
    m_steps.push_back({"Applying Edits", "Committing atomic changes to disk...", false, false});

    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (m_rewriteEngine->applyPlan(m_activePlan)) {
            m_steps.back().completed = true;
            m_state = ComposerState::Success;
        } else {
            m_steps.back().failed = true;
            m_state = ComposerState::Failed;
            m_rewriteEngine->rollback(m_activePlan);
        }
    }).detach();
}

void AgenticComposer::rejectStep() {
    m_state = ComposerState::Idle;
    m_steps.back().failed = true;
    m_steps.push_back({"Rejected", "User rejected the plan.", true, true});
}

void AgenticComposer::rollbackAll() {
    m_rewriteEngine->rollback(m_activePlan);
}

} // namespace IDE
} // namespace RawrXD
