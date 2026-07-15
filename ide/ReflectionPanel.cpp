#include "ide/ReflectionPanel.hpp"
#include "ide/PanelState.hpp"
#include "reflection/BeliefAnalyzer.hpp"
#include "reflection/DecisionTracer.hpp"
#include "reflection/CognitiveAuditor.hpp"
#include <imgui.h>

const char* ReflectionPanel::Id() { return "ReflectionPanel"; }
void ReflectionPanel::Toggle() { PanelState::Toggle(Id()); }
bool ReflectionPanel::IsWired() { return true; }
void ReflectionPanel::Init() {}

void ReflectionPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Reflection & Introspection");

    // Cognitive Health
    auto health = CognitiveAuditor::GetCognitiveHealth();
    std::string status = health.value("status", "unknown");
    double healthScore = health.value("health_score", 0.0);
    
    ImGui::Text("Cognitive Health:");
    ImVec4 statusColor = (status == "healthy") ? ImVec4(0, 1, 0, 1) :
                         (status == "degraded") ? ImVec4(1, 1, 0, 1) :
                         ImVec4(1, 0, 0, 1);
    ImGui::TextColored(statusColor, "%s", status.c_str());
    ImGui::ProgressBar((float)healthScore, ImVec2(-1, 0));
    
    ImGui::Separator();
    
    // Belief Analysis
    auto beliefMetrics = BeliefAnalyzer::GetBeliefMetrics();
    ImGui::Text("Beliefs: %zu total", beliefMetrics.value("total_beliefs", 0).get<size_t>());
    ImGui::Text("High confidence: %zu", beliefMetrics.value("high_confidence_beliefs", 0).get<size_t>());
    ImGui::Text("Low confidence: %zu", beliefMetrics.value("low_confidence_beliefs", 0).get<size_t>());
    
    if (ImGui::CollapsingHeader("Belief Analysis")) {
        auto analysis = BeliefAnalyzer::AnalyzeBeliefs();
        ImGui::Text("Average confidence: %.2f", analysis.value("average_confidence", 0.0));
    }
    
    ImGui::Separator();
    
    // Decision Metrics
    auto decisionMetrics = DecisionTracer::GetDecisionMetrics();
    ImGui::Text("Total Decisions: %d", decisionMetrics.value("total_decisions", 0));
    
    if (ImGui::CollapsingHeader("Decision Patterns")) {
        auto patterns = DecisionTracer::AnalyzeDecisionPatterns();
        ImGui::TextWrapped("%s", patterns.dump(2).c_str());
    }
    
    ImGui::Separator();
    
    // Anomalies
    if (ImGui::CollapsingHeader("Anomalies")) {
        auto anomalies = CognitiveAuditor::FindAnomalies();
        if (anomalies.empty()) {
            ImGui::TextDisabled("No anomalies detected");
        } else {
            for (const auto& anomaly : anomalies) {
                ImGui::TextColored(ImVec4(1, 0.5, 0, 1), "%s", 
                    anomaly.value("type", "unknown").c_str());
            }
        }
    }
    
    if (ImGui::Button("Run Audit")) {
        CognitiveAuditor::AuditCognitiveState();
    }
    
    ImGui::End();
}
