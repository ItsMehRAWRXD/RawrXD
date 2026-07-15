#include "ide/CausalPanel.hpp"
#include "ide/PanelState.hpp"
#include "causal/CausalGraph.hpp"
#include "causal/InterventionModel.hpp"
#include "causal/Counterfactual.hpp"
#include <imgui.h>

const char* CausalPanel::Id() { return "CausalPanel"; }
void CausalPanel::Toggle() { PanelState::Toggle(Id()); }
bool CausalPanel::IsWired() { return true; }
void CausalPanel::Init() {}

void CausalPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Causal Dynamics");

    auto edges = CausalGraph::GetEdges();
    size_t edgeCount = CausalGraph::GetEdgeCount();
    
    ImGui::Text("Causal Edges: %zu", edgeCount);
    ImGui::ProgressBar(edgeCount / 1000.0f, ImVec2(-1, 0), "edges");
    
    ImGui::Separator();
    
    if (ImGui::CollapsingHeader("Edge List")) {
        ImGui::BeginChild("edges", ImVec2(0, 150), true);
        for (auto& e : edges) {
            ImGui::BulletText("%s -> %s", e.first.c_str(), e.second.c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    auto last = InterventionModel::GetLast();
    ImGui::Text("Last Intervention:");
    if (!last.empty()) {
        ImGui::TextWrapped("%s", last.dump(2).c_str());
    } else {
        ImGui::TextDisabled("No interventions recorded");
    }
    
    ImGui::Separator();
    
    if (ImGui::Button("Clear Graph")) {
        CausalGraph::Clear();
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Clear Interventions")) {
        InterventionModel::Clear();
    }
    
    ImGui::End();
}
