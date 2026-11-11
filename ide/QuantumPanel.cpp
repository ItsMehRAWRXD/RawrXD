#include "ide/QuantumPanel.hpp"
#include "ide/PanelState.hpp"
#include "quantum/ProbabilityEngine.hpp"
#include "quantum/UncertaintyQuantifier.hpp"
#include <imgui.h>
#include <cstring>

static char eventBuffer[256] = "";

const char* QuantumPanel::Id() { return "QuantumPanel"; }
void QuantumPanel::Toggle() { PanelState::Toggle(Id()); }
bool QuantumPanel::IsWired() { return true; }
void QuantumPanel::Init() {}

void QuantumPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Quantum & Uncertainty");

    // Probability Engine
    if (ImGui::CollapsingHeader("Probability Engine", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = ProbabilityEngine::GetProbabilityMetrics();
        ImGui::Text("Calculations: %zu", metrics.value("calculations_performed", 0).get<size_t>());
        ImGui::Text("Status: %s", metrics.value("engine_status", "unknown").c_str());
        
        ImGui::Separator();
        
        ImGui::InputText("Event JSON", eventBuffer, sizeof(eventBuffer));
        if (ImGui::Button("Calculate Probability")) {
            if (strlen(eventBuffer) > 0) {
                try {
                    auto event = nlohmann::json::parse(eventBuffer);
                    double prob = ProbabilityEngine::CalculateProbability(event);
                    ImGui::Text("Probability: %.4f", prob);
                } catch (...) {
                    ImGui::TextColored(ImVec4(1, 0, 0, 1), "Invalid JSON");
                }
            }
        }
    }
    
    ImGui::Separator();
    
    // Uncertainty Quantifier
    if (ImGui::CollapsingHeader("Uncertainty Quantifier")) {
        auto metrics = UncertaintyQuantifier::GetUncertaintyMetrics();
        ImGui::Text("Quantifications: %zu", metrics.value("quantifications_performed", 0).get<size_t>());
        ImGui::Text("History: %zu entries", metrics.value("history_entries", 0).get<size_t>());
        ImGui::Text("Avg Uncertainty: %.4f", metrics.value("avg_uncertainty", 0.0));
    }
    
    ImGui::End();
}
