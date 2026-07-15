#include "ide/LearningPanel.hpp"
#include "ide/PanelState.hpp"
#include "learning/ExperienceReplay.hpp"
#include "learning/PolicyOptimizer.hpp"
#include "learning/MetaLearner.hpp"
#include <imgui.h>

const char* LearningPanel::Id() { return "LearningPanel"; }
void LearningPanel::Toggle() { PanelState::Toggle(Id()); }
bool LearningPanel::IsWired() { return true; }
void LearningPanel::Init() {}

void LearningPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Learning & Adaptation");

    // Experience Replay Stats
    auto expStats = ExperienceReplay::GetExperienceStats();
    ImGui::Text("Experience Buffer:");
    ImGui::Text("Size: %zu / %zu", 
        expStats.value("buffer_size", 0).get<size_t>(),
        expStats.value("max_size", 0).get<size_t>());
    ImGui::ProgressBar((float)expStats.value("utilization", 0.0), ImVec2(-1, 0));
    
    ImGui::Separator();
    
    // Policy Optimizer Metrics
    auto policyMetrics = PolicyOptimizer::GetOptimizationMetrics();
    ImGui::Text("Policy Optimization:");
    ImGui::Text("Steps: %d", policyMetrics.value("optimization_steps", 0));
    ImGui::Text("Average Reward: %.3f", policyMetrics.value("average_reward", 0.0));
    ImGui::Text("Policy Rules: %zu", policyMetrics.value("policy_rules", 0).get<size_t>());
    
    ImGui::Separator();
    
    // Meta-Learning
    auto metaMetrics = MetaLearner::GetMetaMetrics();
    ImGui::Text("Meta-Learning:");
    ImGui::Text("Tasks Learned: %d", metaMetrics.value("tasks_learned", 0));
    
    if (ImGui::CollapsingHeader("Learning Strategy")) {
        auto strategy = MetaLearner::GetLearningStrategy();
        ImGui::Text("Learning Rate: %.4f", strategy.value("learning_rate", 0.0));
        ImGui::Text("Exploration Rate: %.3f", strategy.value("exploration_rate", 0.0));
        ImGui::Text("Batch Size: %d", strategy.value("batch_size", 0));
    }
    
    ImGui::Separator();
    
    // Controls
    if (ImGui::Button("Clear Experiences")) {
        ExperienceReplay::ClearExperiences();
    }
    
    ImGui::End();
}
