#include "ide/MetaCognitionPanel.hpp"
#include "ide/PanelState.hpp"
#include "metacognition/ArchitectureAnalyzer.hpp"
#include "metacognition/SelfOptimizer.hpp"
#include "metacognition/LearningScheduler.hpp"
#include <imgui.h>
#include <cstring>

static char topicBuffer[128] = "";

const char* MetaCognitionPanel::Id() { return "MetaCognitionPanel"; }
void MetaCognitionPanel::Toggle() { PanelState::Toggle(Id()); }
bool MetaCognitionPanel::IsWired() { return true; }
void MetaCognitionPanel::Init() {}

void MetaCognitionPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Meta-Cognition & Self-Improvement");

    // Architecture Analysis
    if (ImGui::CollapsingHeader("Architecture Analysis", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = ArchitectureAnalyzer::GetArchitectureMetrics();
        ImGui::Text("Layers Monitored: %zu", metrics.value("layers_monitored", 0).get<size_t>());
        ImGui::Text("Analyses Performed: %zu", metrics.value("analyses_performed", 0).get<size_t>());
        
        if (ImGui::Button("Identify Bottlenecks")) {
            auto bottlenecks = ArchitectureAnalyzer::IdentifyBottlenecks();
            ImGui::Text("Bottlenecks Found: %zu", bottlenecks.value("bottlenecks_found", 0).get<size_t>());
        }
        
        if (ImGui::Button("Suggest Optimizations")) {
            auto suggestions = ArchitectureAnalyzer::SuggestOptimizations();
            ImGui::Text("Suggestions: %zu", suggestions.value("total_suggestions", 0).get<size_t>());
        }
        
        if (ImGui::Button("Measure Inter-Layer Latency")) {
            auto latency = ArchitectureAnalyzer::MeasureInterLayerLatency();
            ImGui::Text("Total Pipeline: %.3f ms", latency.value("total_pipeline_ms", 0.0));
        }
    }
    
    ImGui::Separator();
    
    // Self Optimization
    if (ImGui::CollapsingHeader("Self Optimization")) {
        auto metrics = SelfOptimizer::GetOptimizationMetrics();
        ImGui::Text("Total Optimizations: %zu", metrics.value("total_optimizations", 0).get<size_t>());
        ImGui::Text("Active Optimizations: %zu", metrics.value("active_optimizations", 0).get<size_t>());
        
        auto active = SelfOptimizer::GetActiveOptimizations();
        ImGui::Text("Active:");
        ImGui::BeginChild("optimizations", ImVec2(0, 60), true);
        for (const auto& opt : active) {
            ImGui::Text("- %s", opt.value("id", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Learning Scheduler
    if (ImGui::CollapsingHeader("Learning Scheduler")) {
        auto metrics = LearningScheduler::GetScheduleMetrics();
        ImGui::Text("Scheduled: %zu", metrics.value("total_scheduled", 0).get<size_t>());
        ImGui::Text("Pending: %zu", metrics.value("pending", 0).get<size_t>());
        ImGui::Text("In Progress: %zu", metrics.value("in_progress", 0).get<size_t>());
        ImGui::Text("Completed: %zu", metrics.value("completed", 0).get<size_t>());
        ImGui::Text("Completion Rate: %.1f%%", metrics.value("completion_rate", 0.0).get<double>() * 100);
        
        ImGui::InputText("Topic", topicBuffer, sizeof(topicBuffer));
        ImGui::SameLine();
        if (ImGui::Button("Schedule")) {
            if (strlen(topicBuffer) > 0) {
                LearningScheduler::ScheduleLearning(topicBuffer, 5);
                topicBuffer[0] = '\0';
            }
        }
    }
    
    ImGui::End();
}
