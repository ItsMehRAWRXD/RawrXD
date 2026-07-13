#include "ide/InfiniteHorizonPanel.hpp"
#include "infinite/InfiniteHorizonEngine.hpp"
#include "infinite/InfiniteHorizonLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool InfiniteHorizonPanel::s_visible = false;
bool InfiniteHorizonPanel::s_initialized = false;
char InfiniteHorizonPanel::s_nameBuffer[256] = {};
char InfiniteHorizonPanel::s_typeBuffer[64] = {};
char InfiniteHorizonPanel::s_classBuffer[64] = {};
char InfiniteHorizonPanel::s_categoryBuffer[64] = {};
char InfiniteHorizonPanel::s_parentBuffer[128] = {};
char InfiniteHorizonPanel::s_frontierBuffer[128] = {};
std::vector<char> InfiniteHorizonPanel::s_jsonBuffer(4096, '\0');
int InfiniteHorizonPanel::s_selectedTab = 0;

void InfiniteHorizonPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Infinite::InfiniteHorizonLoop::Init();
    Infinite::InfiniteHorizonLoop::Start();
}

void InfiniteHorizonPanel::Shutdown() {
    if (!s_initialized) return;
    Infinite::InfiniteHorizonLoop::Shutdown();
    s_initialized = false;
}

void InfiniteHorizonPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Infinite Horizon (Layer 63)", &s_visible);
    
    const char* tabs[] = {"Frontiers", "Boundaries", "Thresholds", "Limits", "Discoveries", "Metrics", "Report"};
    ImGui::TabBar("HorizonTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderFrontierManager(); break;
        case 1: RenderBoundaryManager(); break;
        case 2: RenderThresholdManager(); break;
        case 3: RenderLimitManager(); break;
        case 4: RenderDiscoveryManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void InfiniteHorizonPanel::RenderFrontierManager() {
    ImGui::Text("Universal Frontier Management");
    ImGui::Separator();
    
    ImGui::InputText("Frontier Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Frontier Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputText("Parent Universe", s_parentBuffer, sizeof(s_parentBuffer));
    
    if (ImGui::Button("Establish Frontier")) {
        Infinite::InfiniteHorizonEngine::EstablishUniversalFrontier(s_nameBuffer, s_typeBuffer, s_parentBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
        memset(s_parentBuffer, 0, sizeof(s_parentBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Frontiers:");
    auto frontiers = Infinite::InfiniteHorizonEngine::GetAllFrontiers();
    for (const auto& frontier : frontiers) {
        ImGui::Text("%s - %s [%s] (Rate: %.2f, Regions: %zu)", frontier.frontierId.c_str(), frontier.name.c_str(), 
                    frontier.frontierType.c_str(), frontier.expansionRate, frontier.discoveredRegions.size());
    }
}

void InfiniteHorizonPanel::RenderBoundaryManager() {
    ImGui::Text("Cosmic Boundary Management");
    ImGui::Separator();
    
    ImGui::InputText("Boundary Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Boundary Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float strength = 1.0f;
    ImGui::SliderFloat("Strength", &strength, 0.0f, 1.0f);
    
    if (ImGui::Button("Detect Boundary")) {
        Infinite::InfiniteHorizonEngine::DetectCosmicBoundary(s_nameBuffer, s_typeBuffer, strength);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Detected Boundaries:");
    auto boundaries = Infinite::InfiniteHorizonEngine::GetAllBoundaries();
    for (const auto& boundary : boundaries) {
        ImGui::Text("%s - %s [%s] (Str: %.2f, Perm: %.2f)", boundary.boundaryId.c_str(), boundary.name.c_str(), 
                    boundary.boundaryType.c_str(), boundary.boundaryStrength, boundary.permeability);
    }
}

void InfiniteHorizonPanel::RenderThresholdManager() {
    ImGui::Text("Multiversal Threshold Management");
    ImGui::Separator();
    
    ImGui::InputText("Threshold Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Threshold Class", s_classBuffer, sizeof(s_classBuffer));
    
    if (ImGui::Button("Identify Threshold")) {
        std::vector<std::string> universes = {"universe_1", "universe_2"};
        Infinite::InfiniteHorizonEngine::IdentifyMultiversalThreshold(s_nameBuffer, s_classBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_classBuffer, 0, sizeof(s_classBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Identified Thresholds:");
    auto thresholds = Infinite::InfiniteHorizonEngine::GetAllThresholds();
    for (const auto& threshold : thresholds) {
        ImGui::Text("%s - %s [%s] (Energy: %.2f)", threshold.thresholdId.c_str(), threshold.name.c_str(), 
                    threshold.thresholdClass.c_str(), threshold.transitionEnergy);
    }
}

void InfiniteHorizonPanel::RenderLimitManager() {
    ImGui::Text("Transcendent Limit Management");
    ImGui::Separator();
    
    ImGui::InputText("Limit Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Limit Category", s_categoryBuffer, sizeof(s_categoryBuffer));
    static float maximum = 1000.0f;
    ImGui::SliderFloat("Maximum Value", &maximum, 0.0f, 10000.0f);
    
    if (ImGui::Button("Discover Limit")) {
        Infinite::InfiniteHorizonEngine::DiscoverTranscendentLimit(s_nameBuffer, s_categoryBuffer, maximum);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_categoryBuffer, 0, sizeof(s_categoryBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Limits:");
    auto limits = Infinite::InfiniteHorizonEngine::GetAllLimits();
    for (const auto& limit : limits) {
        ImGui::Text("%s - %s [%s] (%.2f/%.2f, Progress: %.2f%%)", limit.limitId.c_str(), limit.name.c_str(), 
                    limit.limitCategory.c_str(), limit.currentValue, limit.maximumValue, limit.expansionProgress * 100.0f);
    }
}

void InfiniteHorizonPanel::RenderDiscoveryManager() {
    ImGui::Text("Horizon Discovery Management");
    ImGui::Separator();
    
    ImGui::InputText("Discovery Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Discovery Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputText("Frontier ID", s_frontierBuffer, sizeof(s_frontierBuffer));
    ImGui::InputTextMultiline("Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    static float significance = 0.5f;
    ImGui::SliderFloat("Significance", &significance, 0.0f, 1.0f);
    
    if (ImGui::Button("Record Discovery")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            Infinite::InfiniteHorizonEngine::RecordHorizonDiscovery(s_nameBuffer, s_typeBuffer, s_frontierBuffer, data, significance);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            memset(s_frontierBuffer, 0, sizeof(s_frontierBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Recorded Discoveries:");
    auto discoveries = Infinite::InfiniteHorizonEngine::GetAllDiscoveries();
    for (const auto& discovery : discoveries) {
        ImGui::Text("%s - %s [%s] (Sig: %.2f)", discovery.discoveryId.c_str(), discovery.name.c_str(), 
                    discovery.discoveryType.c_str(), discovery.significance);
    }
}

void InfiniteHorizonPanel::RenderMetrics() {
    ImGui::Text("Horizon Metrics");
    ImGui::Separator();
    
    auto metrics = Infinite::InfiniteHorizonEngine::GetHorizonMetrics();
    
    ImGui::Text("Frontiers: %d", metrics["frontierCount"].get<int>());
    ImGui::Text("Boundaries: %d", metrics["boundaryCount"].get<int>());
    ImGui::Text("Thresholds: %d", metrics["thresholdCount"].get<int>());
    ImGui::Text("Limits: %d", metrics["limitCount"].get<int>());
    ImGui::Text("Discoveries: %d", metrics["discoveryCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Expansion: %.4f", metrics["totalExpansion"].get<float>());
    ImGui::Text("Boundary Integrity: %.4f", metrics["boundaryIntegrity"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void InfiniteHorizonPanel::RenderReport() {
    ImGui::Text("Horizon Report");
    ImGui::Separator();
    
    auto report = Infinite::InfiniteHorizonEngine::GenerateHorizonReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool InfiniteHorizonPanel::IsVisible() {
    return s_visible;
}

void InfiniteHorizonPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void InfiniteHorizonPanel::Toggle() {
    s_visible = !s_visible;
}

const char* InfiniteHorizonPanel::GetPanelName() {
    return "Infinite Horizon";
}

const char* InfiniteHorizonPanel::GetShortcut() {
    return "Ctrl+Shift+F35";
}

} // namespace IDE
