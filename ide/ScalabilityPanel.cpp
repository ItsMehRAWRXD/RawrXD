#include "ide/ScalabilityPanel.hpp"
#include "ide/PanelState.hpp"
#include "scalability/LoadBalancer.hpp"
#include "scalability/AutoScaler.hpp"
#include <imgui.h>
#include <cstring>

static char nodeIdBuffer[64] = "";
static char strategyBuffer[64] = "";

const char* ScalabilityPanel::Id() { return "ScalabilityPanel"; }
void ScalabilityPanel::Toggle() { PanelState::Toggle(Id()); }
bool ScalabilityPanel::IsWired() { return true; }
void ScalabilityPanel::Init() {}

void ScalabilityPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Scalability & Load Balancing");

    // Load Balancer Status
    if (ImGui::CollapsingHeader("Load Balancer", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = LoadBalancer::GetLoadBalancerMetrics();
        ImGui::Text("Total Nodes: %zu", metrics.value("total_nodes", 0).get<size_t>());
        ImGui::Text("Healthy: %zu", metrics.value("healthy_nodes", 0).get<size_t>());
        ImGui::Text("Unhealthy: %zu", metrics.value("unhealthy_nodes", 0).get<size_t>());
        ImGui::Text("Total Requests: %zu", metrics.value("total_requests", 0).get<size_t>());
        ImGui::Text("Failed: %zu", metrics.value("failed_requests", 0).get<size_t>());
        ImGui::Text("Average Load: %.2f", metrics.value("average_load", 0.0));
        ImGui::Text("Strategy: %s", metrics.value("current_strategy", "unknown").get<std::string>().c_str());
        
        ImGui::Separator();
        
        ImGui::InputText("Node ID", nodeIdBuffer, sizeof(nodeIdBuffer));
        
        if (ImGui::Button("Register Node")) {
            if (strlen(nodeIdBuffer) > 0) {
                LoadBalancer::RegisterNode(nodeIdBuffer, {{"weight", 1.0}});
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Unregister")) {
            if (strlen(nodeIdBuffer) > 0) {
                LoadBalancer::UnregisterNode(nodeIdBuffer);
            }
        }
        
        ImGui::InputText("Strategy", strategyBuffer, sizeof(strategyBuffer));
        if (ImGui::Button("Set Strategy")) {
            if (strlen(strategyBuffer) > 0) {
                LoadBalancer::SetStrategy(strategyBuffer);
            }
        }
        
        // Show node loads
        auto nodeLoads = LoadBalancer::GetAllNodeLoads();
        ImGui::Text("Node Loads:");
        ImGui::BeginChild("nodes", ImVec2(0, 80), true);
        for (const auto& [id, data] : nodeLoads.items()) {
            bool healthy = data.value("healthy", false);
            double load = data.value("current_load", 0.0);
            ImGui::Text("%s: %.2f [%s]", id.get<std::string>().c_str(), load, healthy ? "OK" : "DOWN");
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Auto Scaler
    if (ImGui::CollapsingHeader("Auto Scaler")) {
        auto metrics = AutoScaler::GetAutoScalerMetrics();
        auto limits = AutoScaler::GetLimits();
        auto thresholds = AutoScaler::GetThresholds();
        
        ImGui::Text("Current Nodes: %zu", metrics.value("current_nodes", 0).get<size_t>());
        ImGui::Text("Min: %zu, Max: %zu", 
            limits.value("min_nodes", 0).get<size_t>(),
            limits.value("max_nodes", 0).get<size_t>());
        ImGui::Text("Scale Ups: %zu", metrics.value("scale_up_count", 0).get<size_t>());
        ImGui::Text("Scale Downs: %zu", metrics.value("scale_down_count", 0).get<size_t>());
        
        ImGui::Text("Thresholds:");
        ImGui::Text("  Scale Up: %.0f%%", thresholds.value("scale_up_threshold", 0.0).get<double>() * 100);
        ImGui::Text("  Scale Down: %.0f%%", thresholds.value("scale_down_threshold", 0.0).get<double>() * 100);
        
        if (ImGui::Button("Evaluate Scaling")) {
            auto eval = AutoScaler::EvaluateScalingNeeds();
            ImGui::Text("Recommendation: %s", eval.value("recommendation", "unknown").get<std::string>().c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("Scale Up")) {
            AutoScaler::ScaleUp("manual");
        }
        ImGui::SameLine();
        if (ImGui::Button("Scale Down")) {
            AutoScaler::ScaleDown("manual");
        }
    }
    
    ImGui::End();
}
