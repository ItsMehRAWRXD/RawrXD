#include "ide/IntentPanel.hpp"
#include "ide/PanelState.hpp"
#include "intent/IntentModel.hpp"
#include "intent/TeleologicalReasoner.hpp"
#include "intent/GoalCausalAlignment.hpp"
#include <imgui.h>

const char* IntentPanel::Id() { return "IntentPanel"; }
void IntentPanel::Toggle() { PanelState::Toggle(Id()); }
bool IntentPanel::IsWired() { return true; }
void IntentPanel::Init() {}

void IntentPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Intent & Teleology");

    // Current Intent Section
    auto intent = IntentModel::GetCurrentIntent();
    std::string goal = intent.value("goal", "");
    std::string status = intent.value("status", "idle");
    double progress = intent.value("progress", 0.0);
    
    ImGui::Text("Current Intent:");
    if (goal.empty()) {
        ImGui::TextDisabled("No active intent");
    } else {
        ImGui::Text("Goal: %s", goal.c_str());
        ImGui::Text("Status: %s", status.c_str());
        ImGui::ProgressBar((float)progress, ImVec2(-1, 0), status.c_str());
    }
    
    ImGui::Separator();
    
    // Alignment Section
    auto alignment = GoalCausalAlignment::CheckAlignment();
    double alignmentScore = alignment.value("alignment_score", 0.0);
    bool aligned = alignment.value("aligned", false);
    
    ImGui::Text("Goal-Causal Alignment:");
    ImGui::Text("Score: %.2f", alignmentScore);
    ImGui::ProgressBar((float)alignmentScore, ImVec2(-1, 0), aligned ? "aligned" : "misaligned");
    
    if (!aligned) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Misalignment detected!");
        if (ImGui::Button("Realign")) {
            GoalCausalAlignment::Realign();
        }
    }
    
    ImGui::Separator();
    
    // Teleological Analysis
    if (ImGui::CollapsingHeader("Suggested Actions")) {
        auto suggestions = TeleologicalReasoner::SuggestAlignedActions();
        for (const auto& suggestion : suggestions) {
            ImGui::BulletText("%s", suggestion.get<std::string>().c_str());
        }
    }
    
    // Intent History
    if (ImGui::CollapsingHeader("Intent History")) {
        auto history = IntentModel::GetIntentHistory();
        ImGui::BeginChild("history", ImVec2(0, 100), true);
        for (const auto& pastIntent : history) {
            std::string pastGoal = pastIntent.value("goal", "");
            std::string pastStatus = pastIntent.value("status", "");
            ImGui::Text("%s [%s]", pastGoal.c_str(), pastStatus.c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Controls
    if (ImGui::Button("Clear Intent")) {
        IntentModel::ClearIntent();
    }
    
    ImGui::End();
}
