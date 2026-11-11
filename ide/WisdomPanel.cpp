#include "ide/WisdomPanel.hpp"
#include "ide/PanelState.hpp"
#include "wisdom/ExperienceSynthesizer.hpp"
#include "wisdom/ContextualJudgment.hpp"
#include "wisdom/IntegrationEngine.hpp"
#include <imgui.h>
#include <cstring>

static char situationBuffer[256] = "";

const char* WisdomPanel::Id() { return "WisdomPanel"; }
void WisdomPanel::Toggle() { PanelState::Toggle(Id()); }
bool WisdomPanel::IsWired() { return true; }
void WisdomPanel::Init() {}

void WisdomPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Wisdom & Integration");

    // Experience Synthesis
    if (ImGui::CollapsingHeader("Experience Synthesis", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = ExperienceSynthesizer::GetWisdomMetrics();
        ImGui::Text("Wisdom Entries: %zu", metrics.value("wisdom_entries", 0).get<size_t>());
        ImGui::Text("Syntheses Performed: %zu", metrics.value("syntheses_performed", 0).get<size_t>());
        
        if (ImGui::Button("Query Wisdom")) {
            auto wisdom = ExperienceSynthesizer::QueryWisdom("general");
            // Would display in expanded view
        }
    }
    
    ImGui::Separator();
    
    // Contextual Judgment
    if (ImGui::CollapsingHeader("Contextual Judgment")) {
        auto metrics = ContextualJudgment::GetJudgmentMetrics();
        ImGui::Text("Total Judgments: %zu", metrics.value("total_judgments", 0).get<size_t>());
        ImGui::Text("History Size: %zu", metrics.value("history_size", 0).get<size_t>());
        
        ImGui::InputText("Situation JSON", situationBuffer, sizeof(situationBuffer));
        if (ImGui::Button("Apply Judgment")) {
            if (strlen(situationBuffer) > 0) {
                try {
                    auto situation = nlohmann::json::parse(situationBuffer);
                    auto judgment = ContextualJudgment::ApplyJudgment(situation);
                    ImGui::Text("Recommendation: %s", judgment.value("recommendation", "N/A").c_str());
                    ImGui::Text("Priority: %s", judgment.value("priority", "N/A").c_str());
                    ImGui::Text("Confidence: %.2f", judgment.value("confidence", 0.0));
                } catch (...) {
                    ImGui::TextColored(ImVec4(1, 0, 0, 1), "Invalid JSON");
                }
            }
        }
    }
    
    ImGui::Separator();
    
    // Integration Engine
    if (ImGui::CollapsingHeader("Integration Engine")) {
        auto metrics = IntegrationEngine::GetIntegrationMetrics();
        ImGui::Text("Integrations: %zu", metrics.value("integrations_performed", 0).get<size_t>());
        ImGui::Text("Conflicts Resolved: %zu", metrics.value("conflicts_resolved", 0).get<size_t>());
    }
    
    ImGui::End();
}
