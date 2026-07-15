#include "ide/EthicsPanel.hpp"
#include "ide/PanelState.hpp"
#include "ethics/MoralFramework.hpp"
#include "ethics/EthicalConstraint.hpp"
#include "ethics/StakeholderAnalysis.hpp"
#include <imgui.h>
#include <cstring>

static char actionBuffer[256] = "";

const char* EthicsPanel::Id() { return "EthicsPanel"; }
void EthicsPanel::Toggle() { PanelState::Toggle(Id()); }
bool EthicsPanel::IsWired() { return true; }
void EthicsPanel::Init() {}

void EthicsPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Ethics & Moral Reasoning");

    // Moral Framework
    if (ImGui::CollapsingHeader("Moral Framework", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = MoralFramework::GetFrameworkMetrics();
        ImGui::Text("Active Principles: %zu", metrics.value("active_principles", 0).get<size_t>());
        ImGui::Text("Evaluations: %zu", metrics.value("evaluations", 0).get<size_t>());
        
        auto principles = MoralFramework::GetActivePrinciples();
        ImGui::Text("Principles:");
        ImGui::BeginChild("principles", ImVec2(0, 80), true);
        for (const auto& p : principles) {
            ImGui::Text("- ID: %d (Weight: %.2f)", 
                p.value("id", 0), p.value("weight", 0.0));
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Ethical Constraints
    if (ImGui::CollapsingHeader("Ethical Constraints")) {
        auto metrics = EthicalConstraint::GetConstraintMetrics();
        ImGui::Text("Total Constraints: %zu", metrics.value("total_constraints", 0).get<size_t>());
        ImGui::Text("Hard: %zu | Soft: %zu | Contextual: %zu",
            metrics.value("hard_constraints", 0).get<size_t>(),
            metrics.value("soft_constraints", 0).get<size_t>(),
            metrics.value("contextual_constraints", 0).get<size_t>());
        ImGui::Text("Total Violations: %zu", metrics.value("total_violations", 0).get<size_t>());
        
        if (ImGui::Button("Clear Violations")) {
            EthicalConstraint::ClearViolations();
        }
    }
    
    ImGui::Separator();
    
    // Stakeholder Analysis
    if (ImGui::CollapsingHeader("Stakeholder Analysis")) {
        auto metrics = StakeholderAnalysis::GetStakeholderMetrics();
        ImGui::Text("Registered Stakeholders: %zu", metrics.value("registered_stakeholders", 0).get<size_t>());
        ImGui::Text("Analyses Performed: %zu", metrics.value("analyses_performed", 0).get<size_t>());
        
        auto stakeholders = StakeholderAnalysis::GetStakeholders();
        ImGui::Text("Stakeholders:");
        ImGui::BeginChild("stakeholders", ImVec2(0, 80), true);
        for (const auto& s : stakeholders) {
            ImGui::Text("- %s [%s]", 
                s.value("id", "unknown").c_str(),
                s.value("priority", "medium").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Action Evaluation
    if (ImGui::CollapsingHeader("Evaluate Action")) {
        ImGui::InputText("Action JSON", actionBuffer, sizeof(actionBuffer));
        if (ImGui::Button("Evaluate")) {
            if (strlen(actionBuffer) > 0) {
                try {
                    auto action = nlohmann::json::parse(actionBuffer);
                    auto evaluation = MoralFramework::EvaluateAction(action);
                    auto constraints = EthicalConstraint::CheckAllConstraints(action);
                    auto impact = StakeholderAnalysis::AnalyzeImpact(action);
                    
                    ImGui::Text("Moral Score: %.2f", evaluation.value("weighted_score", 0.0));
                    ImGui::Text("Permissible: %s", evaluation.value("is_permissible", false) ? "Yes" : "No");
                    ImGui::Text("Constraints Passed: %s", constraints.value("all_passed", false) ? "Yes" : "No");
                    ImGui::Text("Requires Review: %s", impact.value("requires_review", false) ? "Yes" : "No");
                } catch (...) {
                    ImGui::TextColored(ImVec4(1, 0, 0, 1), "Invalid JSON");
                }
            }
        }
    }
    
    ImGui::End();
}
