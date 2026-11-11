#include "ide/MasteryPanel.hpp"
#include "ide/PanelState.hpp"
#include "mastery/SystemOrchestrator.hpp"
#include "mastery/CrossLayerIntegrator.hpp"
#include <imgui.h>
#include <cstring>

const char* MasteryPanel::Id() { return "MasteryPanel"; }
void MasteryPanel::Toggle() { PanelState::Toggle(Id()); }
bool MasteryPanel::IsWired() { return true; }
void MasteryPanel::Init() {}

void MasteryPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("System Mastery");

    // System State
    if (ImGui::CollapsingHeader("System State", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto state = SystemOrchestrator::GetSystemState();
        ImGui::Text("Total Layers: %d", state.value("total_layers", 0).get<int>());
        ImGui::Text("Healthy Layers: %d", state.value("healthy_layers", 0).get<int>());
        ImGui::Text("System Health: %.1f%%", state.value("system_health", 0.0).get<double>() * 100);
        ImGui::Text("Status: %s", state.value("status", "unknown").c_str());
        
        if (ImGui::Button("Refresh State")) {
            // State will be refreshed on next frame
        }
    }
    
    ImGui::Separator();
    
    // System Health
    if (ImGui::CollapsingHeader("System Health")) {
        auto health = SystemOrchestrator::GetSystemHealth();
        ImGui::Text("Overall Health: %.1f%%", health.value("overall_health", 0.0).get<double>() * 100);
        ImGui::Text("Healthy: %d", health.value("healthy_layers", 0).get<int>());
        ImGui::Text("Warning: %d", health.value("warning_layers", 0).get<int>());
        ImGui::Text("Critical: %d", health.value("critical_layers", 0).get<int>());
        ImGui::Text("Status: %s", health.value("status", "unknown").c_str());
    }
    
    ImGui::Separator();
    
    // System Metrics
    if (ImGui::CollapsingHeader("System Metrics")) {
        auto metrics = SystemOrchestrator::GetSystemMetrics();
        ImGui::Text("Layers Active: %zu", metrics.value("layers_active", 0).get<size_t>());
        ImGui::Text("Coordinations: %zu", metrics.value("coordinations_performed", 0).get<size_t>());
    }
    
    ImGui::Separator();
    
    // Cross-Layer Integration
    if (ImGui::CollapsingHeader("Cross-Layer Integration")) {
        auto intMetrics = CrossLayerIntegrator::GetIntegrationMetrics();
        ImGui::Text("Total Integrations: %zu", intMetrics.value("total_integrations", 0).get<size_t>());
        ImGui::Text("Conflicts Resolved: %zu", intMetrics.value("conflicts_resolved", 0).get<size_t>());
        ImGui::Text("Success Rate: %.1f%%", intMetrics.value("integration_success_rate", 0.0).get<double>() * 100);
        
        if (ImGui::Button("Integrate All Layers")) {
            std::vector<std::string> allLayers = {
                "fabric", "distributed", "adaptive", "cognition", "consciousness",
                "autonomy", "emergence", "metastability", "identity", "temporal",
                "causal", "intent", "prediction", "learning", "executive",
                "values", "reflection", "communication", "social", "creativity",
                "ethics", "wisdom", "metacognition"
            };
            CrossLayerIntegrator::IntegrateLayerOutputs(allLayers);
        }
    }
    
    ImGui::End();
}
