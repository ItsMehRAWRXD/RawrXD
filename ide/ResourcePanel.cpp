#include "ide/ResourcePanel.hpp"
#include "ide/PanelState.hpp"
#include "resource/ResourceAllocator.hpp"
#include "resource/OptimizationEngine.hpp"
#include <imgui.h>
#include <cstring>

static char resourceTypeBuffer[64] = "";
static char requesterBuffer[64] = "";

const char* ResourcePanel::Id() { return "ResourcePanel"; }
void ResourcePanel::Toggle() { PanelState::Toggle(Id()); }
bool ResourcePanel::IsWired() { return true; }
void ResourcePanel::Init() {}

void ResourcePanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Resource Management");

    // Resource Utilization
    if (ImGui::CollapsingHeader("Resource Utilization", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto utilization = ResourceAllocator::GetResourceUtilization();
        for (const auto& [type, data] : utilization.items()) {
            double used = data.value("used", 0.0);
            double limit = data.value("limit", 1.0);
            double util = data.value("utilization", 0.0);
            
            ImGui::Text("%s: %.1f / %.1f (%.1f%%)", 
                type.get<std::string>().c_str(), used, limit, util * 100);
            ImGui::ProgressBar((float)util, ImVec2(-1, 0));
        }
    }
    
    ImGui::Separator();
    
    // Resource Allocation
    if (ImGui::CollapsingHeader("Resource Allocation")) {
        auto available = ResourceAllocator::GetAvailableResources();
        auto allocated = ResourceAllocator::GetAllocatedResources();
        
        ImGui::Text("Active Allocations: %zu", allocated.size());
        
        ImGui::InputText("Resource Type", resourceTypeBuffer, sizeof(resourceTypeBuffer));
        ImGui::InputText("Requester", requesterBuffer, sizeof(requesterBuffer));
        
        if (ImGui::Button("Allocate")) {
            if (strlen(resourceTypeBuffer) > 0 && strlen(requesterBuffer) > 0) {
                ResourceAllocator::Allocate(resourceTypeBuffer, 100.0, requesterBuffer);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Show Allocated")) {
            auto allocs = ResourceAllocator::GetAllocatedResources();
            ImGui::Text("Found %zu allocations", allocs.size());
        }
    }
    
    ImGui::Separator();
    
    // Optimization
    if (ImGui::CollapsingHeader("Optimization")) {
        auto metrics = OptimizationEngine::GetOptimizationMetrics();
        ImGui::Text("Total Optimizations: %zu", metrics.value("total_optimizations", 0).get<size_t>());
        ImGui::Text("Applied: %zu", metrics.value("applied", 0).get<size_t>());
        ImGui::Text("Pending: %zu", metrics.value("pending", 0).get<size_t>());
        
        if (ImGui::Button("Find Bottlenecks")) {
            auto bottlenecks = OptimizationEngine::FindBottlenecks();
            ImGui::Text("Found %zu bottlenecks", bottlenecks.value("bottlenecks_found", 0).get<size_t>());
        }
        ImGui::SameLine();
        if (ImGui::Button("Recommendations")) {
            auto recs = OptimizationEngine::RecommendOptimizations();
            ImGui::Text("Found %zu recommendations", recs.size());
        }
        
        auto activeOpts = OptimizationEngine::GetActiveOptimizations();
        ImGui::Text("Active Optimizations:");
        ImGui::BeginChild("opts", ImVec2(0, 60), true);
        for (const auto& opt : activeOpts) {
            ImGui::Text("- %s", opt.value("description", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
