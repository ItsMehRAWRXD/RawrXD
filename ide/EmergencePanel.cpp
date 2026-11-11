#include "ide/EmergencePanel.hpp"
#include "ide/PanelState.hpp"
#include "emergence/ContradictionDetector.hpp"
#include "emergence/UncertaintyModel.hpp"
#include "emergence/EmergentPatternTracker.hpp"
#include "emergence/BehaviorGovernor.hpp"

const char* EmergencePanel::Id() { return "EmergencePanel"; }
void EmergencePanel::Toggle() { PanelState::Toggle(Id()); }
bool EmergencePanel::IsWired() { return true; }
void EmergencePanel::Init() {}

void EmergencePanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Emergent Behavior");

    // Contradictions
    ImGui::Text("Contradictions:");
    auto contradictions = ContradictionDetector::FindAll();
    ImGui::Text("Active: %zu", contradictions.size());
    
    // Uncertainty
    ImGui::Separator();
    ImGui::Text("Uncertainty Model:");
    auto uncertainties = UncertaintyModel::GetAll();
    for (auto& [key, val] : uncertainties.items()) {
        ImGui::Text("%s: %.2f", key.c_str(), val.get<float>());
    }
    
    // Patterns
    ImGui::Separator();
    ImGui::Text("Emergent Patterns:");
    auto patterns = EmergentPatternTracker::DetectPatterns();
    for (auto& p : patterns) {
        ImGui::BulletText("%s", p.dump().c_str());
    }
    
    // Constraints
    ImGui::Separator();
    ImGui::Text("Behavior Constraints:");
    auto constraints = BehaviorGovernor::GetConstraints();
    for (auto& c : constraints) {
        ImGui::BulletText("%s", c.get<std::string>().c_str());
    }

    ImGui::End();
}
