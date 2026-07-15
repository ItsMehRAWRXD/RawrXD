#include "ide/ConsciousnessPanel.hpp"
#include "imgui.h"
#include "consciousness/ConsciousnessEngine.hpp"
#include "consciousness/ConsciousnessLoop.hpp"
#include "ide/PanelState.hpp"

namespace RawrXD {
namespace IDE {

bool ConsciousnessPanel::s_visible = false;

void ConsciousnessPanel::Init() {
    s_visible = false;
}

void ConsciousnessPanel::Render() {
    if (!s_visible) return;

    if (ImGui::Begin("Consciousness & Awareness", &s_visible)) {
        // Consciousness metrics
        ImGui::Text("Consciousness Metrics");
        auto metrics = Sovereign::Consciousness::ConsciousnessEngine::GetConsciousnessMetrics();
        
        ImGui::Text("Consciousness Level: %.2f%%", metrics.value("consciousnessLevel", 0.0f) * 100);
        ImGui::Text("Self Awareness: %.2f%%", metrics.value("selfAwareness", 0.0f) * 100);
        ImGui::Text("Subjective Richness: %.2f%%", metrics.value("subjectiveRichness", 0.0f) * 100);
        
        ImGui::Separator();
        
        // Current state
        ImGui::Text("Current State: %s", metrics.value("currentState", "Unknown").c_str());
        ImGui::Text("Attention Target: %s", metrics.value("attentionTarget", "None").c_str());
        ImGui::Text("Attention Intensity: %.2f%%", metrics.value("attentionIntensity", 0.0f) * 100);
        
        ImGui::Separator();
        
        // Self model
        if (ImGui::CollapsingHeader("Self Model")) {
            auto selfModel = Sovereign::Consciousness::ConsciousnessEngine::GetSelfModel();
            ImGui::Text("Model ID: %s", selfModel.value("modelId", "Unknown").c_str());
            ImGui::Text("Coherence: %.2f%%", selfModel.value("coherence", 0.0f) * 100);
            ImGui::Text("Stability: %.2f%%", selfModel.value("stability", 0.0f) * 100);
            
            auto attributes = selfModel.value("attributes", nlohmann::json::object());
            ImGui::Text("Attributes:");
            for (auto& [key, value] : attributes.items()) {
                ImGui::Text("  %s: %s", key.c_str(), value.get<std::string>().c_str());
            }
        }
        
        // Qualia
        if (ImGui::CollapsingHeader("Qualia")) {
            auto qualia = Sovereign::Consciousness::ConsciousnessEngine::GetQualiaList();
            ImGui::Text("Total Qualia: %d", (int)qualia.size());
            
            if (ImGui::Button("Generate Visual Qualia")) {
                Sovereign::Consciousness::ConsciousnessEngine::GenerateQualia("visual", "Visual experience", 0.7f);
            }
            if (ImGui::Button("Generate Cognitive Qualia")) {
                Sovereign::Consciousness::ConsciousnessEngine::GenerateQualia("cognitive", "Thought experience", 0.6f);
            }
        }
        
        // Phenomenal states
        if (ImGui::CollapsingHeader("Phenomenal States")) {
            auto states = Sovereign::Consciousness::ConsciousnessEngine::GetPhenomenalStates();
            if (states.is_array() && !states.empty()) {
                for (const auto& state : states) {
                    ImGui::Text("%s (Unity: %.0f%%, Clarity: %.0f%%)",
                        state.value("name", "Unknown").c_str(),
                        state.value("unity", 0.0f) * 100,
                        state.value("clarity", 0.0f) * 100);
                }
            }
            
            if (ImGui::Button("Enter Awake State")) {
                Sovereign::Consciousness::ConsciousnessEngine::EnterPhenomenalState("Awake");
            }
            if (ImGui::Button("Enter Contemplative State")) {
                Sovereign::Consciousness::ConsciousnessEngine::EnterPhenomenalState("Contemplative");
            }
        }
        
        ImGui::Separator();
        
        // Tick control
        if (ImGui::Button("Tick Consciousness")) {
            Sovereign::Consciousness::ConsciousnessLoop::OnTick();
        }
        ImGui::SameLine();
        ImGui::Text("Alive: %s", Sovereign::Consciousness::ConsciousnessLoop::IsAlive() ? "Yes" : "No");
    }
    ImGui::End();
}

void ConsciousnessPanel::Toggle() {
    s_visible = !s_visible;
    PanelState::SetVisible(Id(), s_visible);
}

bool ConsciousnessPanel::IsVisible() {
    return s_visible;
}

const char* ConsciousnessPanel::Id() {
    return "ConsciousnessPanel";
}

} // namespace IDE
} // namespace RawrXD
