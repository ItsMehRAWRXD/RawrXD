#include "ide/ValuesPanel.hpp"
#include "ide/PanelState.hpp"
#include "values/ValueLearner.hpp"
#include "values/PreferenceModel.hpp"
#include "values/AlignmentVerifier.hpp"
#include <imgui.h>

const char* ValuesPanel::Id() { return "ValuesPanel"; }
void ValuesPanel::Toggle() { PanelState::Toggle(Id()); }
bool ValuesPanel::IsWired() { return true; }
void ValuesPanel::Init() {}

void ValuesPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Value Alignment");

    // Learned Values
    auto values = ValueLearner::GetLearnedValues();
    ImGui::Text("Learned Values:");
    for (auto& [key, val] : values.items()) {
        float v = val.get<double>();
        ImGui::Text("%s:", key.c_str());
        ImGui::SameLine();
        ImGui::ProgressBar(v, ImVec2(150, 0));
    }
    
    ImGui::Separator();
    
    // Alignment Report
    auto report = AlignmentVerifier::GetAlignmentReport();
    double threshold = report.value("threshold", 0.7);
    size_t violations = report.value("total_violations", 0);
    
    ImGui::Text("Alignment Threshold: %.2f", threshold);
    ImGui::Text("Total Violations: %zu", violations);
    
    if (violations > 0) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Alignment violations detected!");
    } else {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "All actions aligned");
    }
    
    ImGui::Separator();
    
    // Preferences
    if (ImGui::CollapsingHeader("Preferences")) {
        auto prefs = PreferenceModel::GetAllPreferences();
        for (auto& [key, val] : prefs.items()) {
            ImGui::Text("%s: %s", key.c_str(), val.dump().c_str());
        }
    }
    
    ImGui::End();
}
