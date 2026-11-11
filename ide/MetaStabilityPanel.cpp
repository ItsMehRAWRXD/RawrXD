#include "ide/MetaStabilityPanel.hpp"
#include "ide/PanelState.hpp"
#include "stability/MetaStabilityLoop.hpp"
#include "stability/CoherenceModel.hpp"
#include "stability/DriftDetector.hpp"
#include "stability/InvariantEnforcer.hpp"
#include "consciousness/SelfModel.hpp"

const char* MetaStabilityPanel::Id() { return "MetaStabilityPanel"; }
void MetaStabilityPanel::Toggle() { PanelState::Toggle(Id()); }
bool MetaStabilityPanel::IsWired() { return true; }
void MetaStabilityPanel::Init() {}

void MetaStabilityPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Meta-Stability Monitor");

    // Stability Score
    float score = MetaStabilityLoop::GetStabilityScore();
    ImGui::Text("Stability Score: %.2f", score);
    ImGui::ProgressBar(score, ImVec2(-1, 0), score > 0.6f ? "STABLE" : "UNSTABLE");
    
    // Coherence
    ImGui::Separator();
    auto self = SelfModel::Get();
    float coherence = CoherenceModel::ComputeCoherence(self);
    ImGui::Text("Coherence: %.2f", coherence);
    ImGui::ProgressBar(coherence);
    
    // Drift Detection
    ImGui::Separator();
    ImGui::Text("Drift Detection:");
    auto driftReport = DriftDetector::GetDriftReport();
    for (auto& [key, data] : driftReport.items()) {
        ImGui::BulletText("%s: threshold=%.2f", key.c_str(), 
            data["threshold"].get<float>());
    }
    
    // Invariants
    ImGui::Separator();
    ImGui::Text("Invariant Violations:");
    auto violations = InvariantEnforcer::GetViolations(self);
    if (violations.empty()) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "All invariants satisfied");
    } else {
        for (auto& v : violations) {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "VIOLATION: %s", v.c_str());
        }
    }
    
    // Stability Status
    ImGui::Separator();
    if (MetaStabilityLoop::IsStable()) {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "SYSTEM STABLE");
    } else {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "SYSTEM UNSTABLE - EMERGENCE LOOP ACTIVE");
    }

    ImGui::End();
}
