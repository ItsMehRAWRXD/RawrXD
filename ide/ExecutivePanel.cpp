#include "ide/ExecutivePanel.hpp"
#include "ide/PanelState.hpp"
#include "executive/ActionSelector.hpp"
#include "executive/ResourceArbiter.hpp"
#include "executive/ConflictResolver.hpp"
#include <imgui.h>

const char* ExecutivePanel::Id() { return "ExecutivePanel"; }
void ExecutivePanel::Toggle() { PanelState::Toggle(Id()); }
bool ExecutivePanel::IsWired() { return true; }
void ExecutivePanel::Init() {}

void ExecutivePanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Executive Control");

    // Current Selection
    auto current = ActionSelector::GetCurrentSelection();
    ImGui::Text("Current Selection:");
    if (!current.empty()) {
        ImGui::TextWrapped("%s", current.dump(2).c_str());
    } else {
        ImGui::TextDisabled("No selection");
    }
    
    ImGui::Separator();
    
    // Resource Status
    auto resources = ResourceArbiter::GetResourceStatus();
    ImGui::Text("Resources:");
    
    if (ImGui::CollapsingHeader("Allocated")) {
        auto allocated = resources.value("allocated", nlohmann::json::object());
        for (auto& [res, req] : allocated.items()) {
            ImGui::BulletText("%s -> %s", res.c_str(), req.get<std::string>().c_str());
        }
    }
    
    if (ImGui::CollapsingHeader("Available")) {
        auto available = resources.value("available", nlohmann::json::array());
        for (const auto& res : available) {
            ImGui::BulletText("%s", res.get<std::string>().c_str());
        }
    }
    
    ImGui::Separator();
    
    // Conflict History
    if (ImGui::CollapsingHeader("Conflict History")) {
        auto history = ConflictResolver::GetConflictHistory();
        ImGui::BeginChild("conflicts", ImVec2(0, 100), true);
        int count = 0;
        for (const auto& entry : history) {
            if (count++ > 5) break;
            auto conflict = entry.value("conflict", nlohmann::json{});
            ImGui::Text("%s", conflict.value("type", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
