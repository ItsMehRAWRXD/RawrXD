#include "ide/TeleologyPanel.hpp"
#include "ide/PanelState.hpp"
#include "intent/IntentModel.hpp"
#include "intent/TeleologyEngine.hpp"
#include "intent/GoalCausalAlignment.hpp"
#include <imgui.h>
#include <cstring>

static char intentBuffer[128] = "";

const char* TeleologyPanel::Id() { return "TeleologyPanel"; }
void TeleologyPanel::Toggle() { PanelState::Toggle(Id()); }
bool TeleologyPanel::IsWired() { return true; }
void TeleologyPanel::Init() {}

void TeleologyPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Intent & Teleology");

    // Intent Model Section
    if (ImGui::CollapsingHeader("Intent Model", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto intent = IntentModel::Get();
        ImGui::Text("Active Intent: %s", intent.value("active_intent", "unknown").get<std::string>().c_str());
        
        auto long_term = intent.value("long_term_intents", nlohmann::json::array());
        ImGui::Text("Long-term Intents (%zu):", long_term.size());
        ImGui::BeginChild("intents", ImVec2(0, 60), true);
        for (const auto& i : long_term) {
            ImGui::BulletText("%s", i.get<std::string>().c_str());
        }
        ImGui::EndChild();
        
        ImGui::InputText("New Intent", intentBuffer, sizeof(intentBuffer));
        if (ImGui::Button("Set Active")) {
            if (strlen(intentBuffer) > 0) {
                IntentModel::SetActiveIntent(intentBuffer);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Add Long-term")) {
            if (strlen(intentBuffer) > 0) {
                IntentModel::AddLongTermIntent(intentBuffer);
            }
        }
    }
    
    ImGui::Separator();
    
    // Teleology Analysis
    if (ImGui::CollapsingHeader("Teleology Analysis")) {
        auto analysis = TeleologyEngine::Analyze();
        ImGui::Text("Derived Purpose: %s", analysis.value("derived_purpose", "unknown").get<std::string>().c_str());
        ImGui::Text("Coherence: %.2f", analysis.value("teleological_coherence", 0.0));
        
        auto hierarchy = TeleologyEngine::GetGoalHierarchy();
        ImGui::Text("Root Purpose: %s", hierarchy.value("root", "unknown").get<std::string>().c_str());
        
        if (ImGui::Button("Analyze")) {
            auto result = TeleologyEngine::Analyze();
            ImGui::Text("Analysis complete");
        }
    }
    
    ImGui::Separator();
    
    // Goal-Causal Alignment
    if (ImGui::CollapsingHeader("Goal-Causal Alignment")) {
        auto status = GoalCausalAlignment::GetAlignmentStatus();
        bool aligned = status.value("aligned", false);
        
        ImVec4 color = aligned ? ImVec4(0, 1, 0, 1) : ImVec4(1, 0, 0, 1);
        ImGui::TextColored(color, "Alignment: %s", aligned ? "OK" : "MISALIGNED");
        
        auto metrics = GoalCausalAlignment::GetAlignmentMetrics();
        ImGui::Text("Goals with requirements: %zu", metrics.value("total_goals_with_requirements", 0).get<size_t>());
        ImGui::Text("Aligned goals: %zu", metrics.value("aligned_goals", 0).get<size_t>());
        ImGui::Text("Alignment rate: %.1f%%", metrics.value("alignment_rate", 0.0).get<double>() * 100);
        
        if (ImGui::Button("Check Alignment")) {
            bool result = GoalCausalAlignment::Check();
            ImGui::Text("Result: %s", result ? "aligned" : "misaligned");
        }
    }
    
    ImGui::End();
}
