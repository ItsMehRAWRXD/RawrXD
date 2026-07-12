#include "ide/TemporalPanel.hpp"
#include "ide/PanelState.hpp"
#include "temporal/TemporalMemory.hpp"
#include "temporal/CausalInference.hpp"
#include "temporal/TimelineReasoner.hpp"
#include <imgui.h>

const char* TemporalPanel::Id() { return "TemporalPanel"; }
void TemporalPanel::Toggle() { PanelState::Toggle(Id()); }
bool TemporalPanel::IsWired() { return true; }
void TemporalPanel::Init() {}

void TemporalPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Temporal Reasoning");

    size_t snapshots = TemporalMemory::GetSize();
    ImGui::Text("Timeline Snapshots: %zu", snapshots);
    ImGui::ProgressBar(snapshots / 1000.0f, ImVec2(-1, 0), "memory");
    
    ImGui::Separator();
    
    auto ci = CausalInference::Infer();
    ImGui::Text("Change Detected: %s", ci.value("change_detected", false) ? "YES" : "NO");
    
    auto changes = CausalInference::DetectChanges();
    ImGui::Text("Total Changes: %zu", changes.value("total_changes", 0).get<size_t>());
    ImGui::Text("Change Rate: %.3f", changes.value("change_rate", 0.0));
    
    ImGui::Separator();
    
    auto analysis = TimelineReasoner::Analyze();
    ImGui::Text("Timeline Length: %zu", analysis.value("length", 0).get<size_t>());
    
    if (ImGui::Button("Clear Timeline")) {
        TemporalMemory::Clear();
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Analyze Trends")) {
        auto trends = TimelineReasoner::GetTrends();
        // Could display in a popup or separate window
    }
    
    ImGui::End();
}
