#include "ide/KnowledgePanel.hpp"
#include "imgui.h"
#include "knowledge/OntologyEngine.hpp"
#include "knowledge/EpistemologyEngine.hpp"
#include "knowledge/KnowledgeLoop.hpp"
#include "ide/PanelState.hpp"

namespace RawrXD {
namespace IDE {

bool KnowledgePanel::s_visible = false;
int KnowledgePanel::s_selectedConcept = -1;
int KnowledgePanel::s_selectedBelief = -1;
char KnowledgePanel::s_queryBuffer[256] = {};

void KnowledgePanel::Init() {
    s_visible = false;
    s_selectedConcept = -1;
    s_selectedBelief = -1;
    s_queryBuffer[0] = '\0';
}

void KnowledgePanel::Render() {
    if (!s_visible) return;

    if (ImGui::Begin("Knowledge", &s_visible)) {
        // Knowledge metrics
        ImGui::Text("Knowledge Metrics");
        auto metrics = Sovereign::Knowledge::KnowledgeLoop::GetKnowledgeMetrics();
        
        if (metrics.contains("ontology")) {
            auto ontMetrics = metrics["ontology"];
            ImGui::Text("Concepts: %d", ontMetrics.value("totalConcepts", 0));
            ImGui::Text("Relationships: %d", ontMetrics.value("totalRelationships", 0));
        }
        
        if (metrics.contains("epistemology")) {
            auto epiMetrics = metrics["epistemology"];
            ImGui::Text("Beliefs: %d", epiMetrics.value("totalBeliefs", 0));
            ImGui::Text("Evidence: %d", epiMetrics.value("totalEvidence", 0));
        }
        
        ImGui::Separator();
        
        // Ontology section
        if (ImGui::CollapsingHeader("Ontology")) {
            auto concepts = Sovereign::Knowledge::OntologyEngine::GetConcepts();
            if (concepts.is_array() && !concepts.empty()) {
                for (size_t i = 0; i < concepts.size(); i++) {
                    const auto& concept = concepts[i];
                    std::string label = concept.value("name", "Unnamed");
                    if (ImGui::Selectable(label.c_str(), s_selectedConcept == (int)i)) {
                        s_selectedConcept = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No concepts");
            }
            
            if (ImGui::Button("Define Concept")) {
                // TODO: Open define concept dialog
            }
        }
        
        // Epistemology section
        if (ImGui::CollapsingHeader("Epistemology")) {
            auto beliefs = Sovereign::Knowledge::EpistemologyEngine::GetBeliefs();
            if (beliefs.is_array() && !beliefs.empty()) {
                for (size_t i = 0; i < beliefs.size(); i++) {
                    const auto& belief = beliefs[i];
                    std::string label = belief.value("proposition", "Unknown");
                    float confidence = belief.value("confidence", 0.0f);
                    label += " (" + std::to_string((int)(confidence * 100)) + "%)";
                    if (ImGui::Selectable(label.c_str(), s_selectedBelief == (int)i)) {
                        s_selectedBelief = (int)i;
                    }
                }
            } else {
                ImGui::TextDisabled("No beliefs");
            }
            
            if (ImGui::Button("Form Belief")) {
                // TODO: Open form belief dialog
            }
        }
        
        // Query section
        if (ImGui::CollapsingHeader("Query")) {
            ImGui::InputText("Search", s_queryBuffer, sizeof(s_queryBuffer));
            if (ImGui::Button("Query Ontology")) {
                // TODO: Execute query
            }
            if (ImGui::Button("Query Beliefs")) {
                // TODO: Execute query
            }
        }
        
        ImGui::Separator();
        
        // Tick control
        if (ImGui::Button("Tick Knowledge")) {
            Sovereign::Knowledge::KnowledgeLoop::OnTick();
        }
        ImGui::SameLine();
        ImGui::Text("Alive: %s", Sovereign::Knowledge::KnowledgeLoop::IsAlive() ? "Yes" : "No");
    }
    ImGui::End();
}

void KnowledgePanel::Toggle() {
    s_visible = !s_visible;
    PanelState::SetVisible(Id(), s_visible);
}

bool KnowledgePanel::IsVisible() {
    return s_visible;
}

const char* KnowledgePanel::Id() {
    return "KnowledgePanel";
}

} // namespace IDE
} // namespace RawrXD
