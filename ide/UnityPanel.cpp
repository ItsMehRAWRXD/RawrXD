#include "ide/UnityPanel.hpp"
#include "imgui.h"
#include "unity/SynthesisEngine.hpp"
#include "unity/UnityLoop.hpp"
#include "ide/PanelState.hpp"

namespace RawrXD {
namespace IDE {

bool UnityPanel::s_visible = false;
int UnityPanel::s_selectedIntegration = -1;
int UnityPanel::s_selectedProperty = -1;

void UnityPanel::Init() {
    s_visible = false;
    s_selectedIntegration = -1;
    s_selectedProperty = -1;
}

void UnityPanel::Render() {
    if (!s_visible) return;

    if (ImGui::Begin("Unity & Synthesis", &s_visible)) {
        // Unity metrics
        ImGui::Text("Unity Metrics");
        auto metrics = Sovereign::Unity::SynthesisEngine::GetSynthesisMetrics();
        
        ImGui::Text("Integrations: %d", metrics.value("totalIntegrations", 0));
        ImGui::Text("Active: %d", metrics.value("activeIntegrations", 0));
        ImGui::Text("Avg Strength: %.2f%%", metrics.value("averageIntegrationStrength", 0.0f) * 100);
        ImGui::Text("Emergent Properties: %d", metrics.value("totalEmergentProperties", 0));
        ImGui::Text("Stable: %d", metrics.value("stableEmergentProperties", 0));
        
        ImGui::Separator();
        
        // Coherence report
        auto coherence = Sovereign::Unity::SynthesisEngine::GetCoherenceReport();
        ImGui::Text("System Coherence: %.2f%%", coherence.value("overallCoherence", 0.0f) * 100);
        ImGui::Text("Layer Alignment: %.2f%%", coherence.value("layerAlignment", 0.0f) * 100);
        ImGui::Text("Cross-Layer Harmony: %.2f%%", coherence.value("crossLayerHarmony", 0.0f) * 100);
        ImGui::Text("Emergent Stability: %.2f%%", coherence.value("emergentStability", 0.0f) * 100);
        
        ImGui::Separator();
        
        // Integrations section
        if (ImGui::CollapsingHeader("Layer Integrations")) {
            auto integrations = Sovereign::Unity::SynthesisEngine::GetIntegrations();
            if (integrations.is_array() && !integrations.empty()) {
                for (size_t i = 0; i < integrations.size(); i++) {
                    const auto& integration = integrations[i];
                    std::string label = integration.value("sourceLayer", "Unknown");
                    label += " <-> ";
                    label += integration.value("targetLayer", "Unknown");
                    label += " (" + std::to_string((int)(integration.value("strength", 0.0f) * 100)) + "%)";
                    if (ImGui::Selectable(label.c_str(), s_selectedIntegration == (int)i)) {
                        s_selectedIntegration = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No integrations");
            }
            
            if (ImGui::Button("Create Integration")) {
                // TODO: Open create integration dialog
            }
        }
        
        // Emergent properties section
        if (ImGui::CollapsingHeader("Emergent Properties")) {
            auto properties = Sovereign::Unity::SynthesisEngine::GetEmergentProperties();
            if (properties.is_array() && !properties.empty()) {
                for (size_t i = 0; i < properties.size(); i++) {
                    const auto& property = properties[i];
                    std::string label = property.value("name", "Unknown");
                    label += " (" + std::to_string((int)(property.value("emergenceLevel", 0.0f) * 100)) + "%)";
                    if (property.value("isStable", false)) {
                        label += " [Stable]";
                    }
                    if (ImGui::Selectable(label.c_str(), s_selectedProperty == (int)i)) {
                        s_selectedProperty = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No emergent properties");
            }
            
            if (ImGui::Button("Identify Property")) {
                // TODO: Open identify property dialog
            }
        }
        
        // Unity report
        if (ImGui::CollapsingHeader("Unity Report")) {
            auto report = Sovereign::Unity::SynthesisEngine::GenerateUnityReport();
            ImGui::Text("Status: %s", report.value("status", "unknown").c_str());
            ImGui::Text("Timestamp: %lld", report.value("timestamp", 0));
        }
        
        ImGui::Separator();
        
        // Tick control
        if (ImGui::Button("Tick Unity")) {
            Sovereign::Unity::UnityLoop::OnTick();
        }
        ImGui::SameLine();
        ImGui::Text("Alive: %s", Sovereign::Unity::UnityLoop::IsAlive() ? "Yes" : "No");
    }
    ImGui::End();
}

void UnityPanel::Toggle() {
    s_visible = !s_visible;
    PanelState::SetVisible(Id(), s_visible);
}

bool UnityPanel::IsVisible() {
    return s_visible;
}

const char* UnityPanel::Id() {
    return "UnityPanel";
}

} // namespace IDE
} // namespace RawrXD
