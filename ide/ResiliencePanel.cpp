#include "ide/ResiliencePanel.hpp"
#include "ide/PanelState.hpp"
#include "resilience/FaultDetector.hpp"
#include "resilience/GracefulDegradation.hpp"
#include <imgui.h>
#include <cstring>

static char componentBuffer[64] = "";

const char* ResiliencePanel::Id() { return "ResiliencePanel"; }
void ResiliencePanel::Toggle() { PanelState::Toggle(Id()); }
bool ResiliencePanel::IsWired() { return true; }
void ResiliencePanel::Init() {}

void ResiliencePanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Resilience & Fault Tolerance");

    // Fault Detection
    if (ImGui::CollapsingHeader("Fault Detection", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = FaultDetector::GetFaultMetrics();
        ImGui::Text("Total Components: %zu", metrics.value("total_components", 0).get<size_t>());
        ImGui::Text("Healthy: %zu", metrics.value("healthy", 0).get<size_t>());
        ImGui::Text("Degraded: %zu", metrics.value("degraded", 0).get<size_t>());
        ImGui::Text("Critical: %zu", metrics.value("critical", 0).get<size_t>());
        ImGui::Text("Detections: %zu", metrics.value("detections_performed", 0).get<size_t>());
        
        if (ImGui::Button("Detect Faults")) {
            auto faults = FaultDetector::DetectFaults();
            ImGui::Text("Faults Found: %d", faults.value("faults_detected", 0).get<int>());
        }
    }
    
    ImGui::Separator();
    
    // Graceful Degradation
    if (ImGui::CollapsingHeader("Graceful Degradation")) {
        auto metrics = GracefulDegradation::GetDegradationMetrics();
        ImGui::Text("Total Degradations: %zu", metrics.value("total_degradations", 0).get<size_t>());
        ImGui::Text("Currently Degraded: %zu", metrics.value("currently_degraded", 0).get<size_t>());
        ImGui::Text("Fallbacks Executed: %zu", metrics.value("fallbacks_executed", 0).get<size_t>());
        
        ImGui::InputText("Component", componentBuffer, sizeof(componentBuffer));
        
        if (ImGui::Button("Trigger Degradation")) {
            if (strlen(componentBuffer) > 0) {
                GracefulDegradation::TriggerDegradation(componentBuffer, "manual");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Restore")) {
            if (strlen(componentBuffer) > 0) {
                GracefulDegradation::RestoreComponent(componentBuffer);
            }
        }
        
        auto status = GracefulDegradation::GetDegradationStatus();
        ImGui::Text("Degraded Components:");
        ImGui::BeginChild("degraded", ImVec2(0, 80), true);
        for (const auto& [comp, compStatus] : status.items()) {
            if (compStatus.value("status", "") == "degraded") {
                ImGui::Text("- %s [%s]", comp.c_str(), 
                    compStatus.value("degradation_level", "unknown").c_str());
            }
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
