#include "ide/PredictionPanel.hpp"
#include "ide/PanelState.hpp"
#include "prediction/StatePredictor.hpp"
#include "prediction/OutcomeSimulator.hpp"
#include "prediction/RiskAssessor.hpp"
#include "temporal/TemporalMemory.hpp"
#include <imgui.h>

const char* PredictionPanel::Id() { return "PredictionPanel"; }
void PredictionPanel::Toggle() { PanelState::Toggle(Id()); }
bool PredictionPanel::IsWired() { return true; }
void PredictionPanel::Init() {}

void PredictionPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Predictive Modeling");

    // Prediction Metrics Section
    auto metrics = StatePredictor::GetModelMetrics();
    ImGui::Text("Prediction Accuracy: %.2f", metrics.value("accuracy", 0.0));
    ImGui::ProgressBar((float)metrics.value("accuracy", 0.0), ImVec2(-1, 0));
    
    ImGui::Text("Total Predictions: %d", metrics.value("total_predictions", 0));
    ImGui::Text("Correct: %d", metrics.value("correct_predictions", 0));
    
    ImGui::Separator();
    
    // Risk Assessment Section
    auto riskBreakdown = RiskAssessor::GetRiskBreakdown();
    double overallRisk = riskBreakdown.value("overall_risk", 0.0);
    
    ImGui::Text("Overall Risk Level: %.2f", overallRisk);
    ImVec4 riskColor = overallRisk < 0.3 ? ImVec4(0, 1, 0, 1) : 
                       (overallRisk < 0.7 ? ImVec4(1, 1, 0, 1) : ImVec4(1, 0, 0, 1));
    ImGui::TextColored(riskColor, "%s", overallRisk < 0.3 ? "LOW" : (overallRisk < 0.7 ? "MEDIUM" : "HIGH"));
    ImGui::ProgressBar((float)overallRisk, ImVec2(-1, 0));
    
    ImGui::Separator();
    
    // Mitigation Suggestions
    if (ImGui::CollapsingHeader("Mitigation Suggestions")) {
        auto suggestions = RiskAssessor::GetMitigationSuggestions();
        for (const auto& suggestion : suggestions) {
            ImGui::BulletText("%s", suggestion.get<std::string>().c_str());
        }
    }
    
    // Simulation History
    if (ImGui::CollapsingHeader("Simulation History")) {
        auto history = OutcomeSimulator::GetSimulationHistory();
        ImGui::BeginChild("sim_history", ImVec2(0, 100), true);
        int count = 0;
        for (const auto& sim : history) {
            if (count++ > 10) break; // Show last 10
            std::string action = sim.value("action", "scenario");
            ImGui::Text("%s", action.c_str());
        }
        ImGui::EndChild();
        
        if (ImGui::Button("Clear Simulations")) {
            OutcomeSimulator::ClearSimulations();
        }
    }
    
    // Current Trajectory
    if (ImGui::Button("Predict Trajectory")) {
        auto timeline = TemporalMemory::GetTimeline();
        if (!timeline.empty()) {
            auto trajectory = StatePredictor::PredictTrajectory(timeline.back(), 5);
            // Could display in a popup or separate view
        }
    }
    
    ImGui::End();
}
