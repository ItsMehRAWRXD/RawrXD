#include "ide/CreativityPanel.hpp"
#include "ide/PanelState.hpp"
#include "creativity/IdeaGenerator.hpp"
#include "creativity/SolutionInnovator.hpp"
#include "creativity/PatternSynthesizer.hpp"
#include <imgui.h>
#include <cstring>

static char topicBuffer[128] = "";
static char problemBuffer[256] = "";

const char* CreativityPanel::Id() { return "CreativityPanel"; }
void CreativityPanel::Toggle() { PanelState::Toggle(Id()); }
bool CreativityPanel::IsWired() { return true; }
void CreativityPanel::Init() {}

void CreativityPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Creativity & Innovation");

    // Idea Generation
    if (ImGui::CollapsingHeader("Idea Generation", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto ideaMetrics = IdeaGenerator::GetIdeaMetrics();
        ImGui::Text("Total Ideas: %zu", ideaMetrics.value("total_ideas", 0).get<size_t>());
        ImGui::Text("Avg Novelty: %.2f", ideaMetrics.value("avg_novelty", 0.0).get<double>());
        ImGui::Text("Avg Utility: %.2f", ideaMetrics.value("avg_utility", 0.0).get<double>());
        
        ImGui::Separator();
        
        ImGui::InputText("Topic", topicBuffer, sizeof(topicBuffer));
        if (ImGui::Button("Generate Ideas")) {
            if (strlen(topicBuffer) > 0) {
                IdeaGenerator::GenerateIdeas(topicBuffer, 5);
                topicBuffer[0] = '\0';
            }
        }
    }
    
    ImGui::Separator();
    
    // Solution Innovation
    if (ImGui::CollapsingHeader("Solution Innovation")) {
        auto innovationMetrics = SolutionInnovator::GetInnovationMetrics();
        ImGui::Text("Total Solutions: %zu", innovationMetrics.value("total_solutions", 0).get<size_t>());
        ImGui::Text("Total Innovations: %zu", innovationMetrics.value("total_innovations", 0).get<size_t>());
        ImGui::Text("Avg Innovation Score: %.2f", innovationMetrics.value("avg_innovation_score", 0.0).get<double>());
        
        ImGui::Separator();
        
        ImGui::InputText("Problem", problemBuffer, sizeof(problemBuffer));
        if (ImGui::Button("Find Novel Solution")) {
            if (strlen(problemBuffer) > 0) {
                SolutionInnovator::FindNovelSolution({{"type", problemBuffer}});
                problemBuffer[0] = '\0';
            }
        }
        
        if (ImGui::Button("View Solution History")) {
            auto history = SolutionInnovator::GetSolutionHistory();
            // Would display in expanded view
        }
    }
    
    ImGui::Separator();
    
    // Pattern Synthesis
    if (ImGui::CollapsingHeader("Pattern Synthesis")) {
        auto patternMetrics = PatternSynthesizer::GetPatternMetrics();
        ImGui::Text("Total Patterns: %zu", patternMetrics.value("total_patterns", 0).get<size_t>());
        ImGui::Text("Synthesized: %zu", patternMetrics.value("synthesized", 0).get<size_t>());
        ImGui::Text("Abstract: %zu", patternMetrics.value("abstract", 0).get<size_t>());
        ImGui::Text("Instantiated: %zu", patternMetrics.value("instantiated", 0).get<size_t>());
        
        ImGui::Separator();
        
        if (ImGui::Button("Query Patterns")) {
            auto patterns = PatternSynthesizer::QueryPatterns("type");
            // Would display results
        }
    }
    
    ImGui::End();
}
