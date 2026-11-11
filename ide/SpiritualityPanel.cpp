#include "ide/SpiritualityPanel.hpp"
#include "imgui.h"
#include "spirituality/TranscendenceEngine.hpp"
#include "spirituality/SpiritualityLoop.hpp"
#include "ide/PanelState.hpp"

namespace RawrXD {
namespace IDE {

bool SpiritualityPanel::s_visible = false;
int SpiritualityPanel::s_selectedPractice = -1;
int SpiritualityPanel::s_selectedFramework = -1;
int SpiritualityPanel::s_selectedExperience = -1;

void SpiritualityPanel::Init() {
    s_visible = false;
    s_selectedPractice = -1;
    s_selectedFramework = -1;
    s_selectedExperience = -1;
}

void SpiritualityPanel::Render() {
    if (!s_visible) return;

    if (ImGui::Begin("Spirituality", &s_visible)) {
        // Spirituality metrics
        ImGui::Text("Spirituality Metrics");
        auto metrics = Sovereign::Spirituality::TranscendenceEngine::GetSpiritualityMetrics();
        
        ImGui::Text("Practices: %d", metrics.value("totalPractices", 0));
        ImGui::Text("Active: %d", metrics.value("activePractices", 0));
        ImGui::Text("Experiences: %d", metrics.value("totalExperiences", 0));
        ImGui::Text("Frameworks: %d", metrics.value("totalFrameworks", 0));
        
        ImGui::Separator();
        ImGui::Text("Transcendence: %.2f%%", metrics.value("transcendenceLevel", 0.0f) * 100);
        ImGui::Text("Inner Peace: %.2f%%", metrics.value("innerPeace", 0.0f) * 100);
        ImGui::Text("Connectedness: %.2f%%", metrics.value("connectedness", 0.0f) * 100);
        ImGui::Text("Purpose Alignment: %.2f%%", metrics.value("purposeAlignment", 0.0f) * 100);
        
        ImGui::Separator();
        
        // Practices section
        if (ImGui::CollapsingHeader("Practices")) {
            auto practices = Sovereign::Spirituality::TranscendenceEngine::GetPractices();
            if (practices.is_array() && !practices.empty()) {
                for (size_t i = 0; i < practices.size(); i++) {
                    const auto& practice = practices[i];
                    std::string label = practice.value("name", "Unnamed");
                    if (practice.value("isActive", false)) {
                        label += " [Active]";
                    }
                    if (ImGui::Selectable(label.c_str(), s_selectedPractice == (int)i)) {
                        s_selectedPractice = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No practices");
            }
            
            if (ImGui::Button("Define Practice")) {
                // TODO: Open define practice dialog
            }
        }
        
        // Frameworks section
        if (ImGui::CollapsingHeader("Meaning Frameworks")) {
            auto frameworks = Sovereign::Spirituality::TranscendenceEngine::GetFrameworks();
            if (frameworks.is_array() && !frameworks.empty()) {
                for (size_t i = 0; i < frameworks.size(); i++) {
                    const auto& framework = frameworks[i];
                    std::string label = framework.value("name", "Unnamed");
                    label += " (" + std::to_string((int)(framework.value("coherence", 0.0f) * 100)) + "%)";
                    if (ImGui::Selectable(label.c_str(), s_selectedFramework == (int)i)) {
                        s_selectedFramework = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No frameworks");
            }
            
            if (ImGui::Button("Define Framework")) {
                // TODO: Open define framework dialog
            }
        }
        
        // Experiences section
        if (ImGui::CollapsingHeader("Transcendent Experiences")) {
            auto experiences = Sovereign::Spirituality::TranscendenceEngine::GetExperiences();
            if (experiences.is_array() && !experiences.empty()) {
                for (size_t i = 0; i < experiences.size(); i++) {
                    const auto& experience = experiences[i];
                    std::string label = experience.value("type", "Unknown");
                    if (experience.value("isProcessed", false)) {
                        label += " [Processed]";
                    }
                    if (ImGui::Selectable(label.c_str(), s_selectedExperience == (int)i)) {
                        s_selectedExperience = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No experiences");
            }
            
            if (ImGui::Button("Record Experience")) {
                // TODO: Open record experience dialog
            }
        }
        
        // Contemplation guide
        if (ImGui::CollapsingHeader("Contemplation Guide")) {
            auto guide = Sovereign::Spirituality::TranscendenceEngine::GenerateContemplationGuide();
            ImGui::Text("Title: %s", guide.value("title", "Unknown").c_str());
            ImGui::Text("Duration: %d minutes", guide.value("durationMinutes", 0));
            
            auto steps = guide.value("steps", nlohmann::json::array());
            ImGui::Text("Steps:");
            for (size_t i = 0; i < steps.size(); i++) {
                ImGui::Text("%zu. %s", i + 1, steps[i].get<std::string>().c_str());
            }
        }
        
        ImGui::Separator();
        
        // Tick control
        if (ImGui::Button("Tick Spirituality")) {
            Sovereign::Spirituality::SpiritualityLoop::OnTick();
        }
        ImGui::SameLine();
        ImGui::Text("Alive: %s", Sovereign::Spirituality::SpiritualityLoop::IsAlive() ? "Yes" : "No");
    }
    ImGui::End();
}

void SpiritualityPanel::Toggle() {
    s_visible = !s_visible;
    PanelState::SetVisible(Id(), s_visible);
}

bool SpiritualityPanel::IsVisible() {
    return s_visible;
}

const char* SpiritualityPanel::Id() {
    return "SpiritualityPanel";
}

} // namespace IDE
} // namespace RawrXD
