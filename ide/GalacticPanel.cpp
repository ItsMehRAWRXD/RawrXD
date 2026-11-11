#include "ide/GalacticPanel.hpp"
#include "ide/PanelState.hpp"
#include "galaxy/GalacticCoreEngine.hpp"
#include "galaxy/GalacticLoop.hpp"
#include <imgui.h>
#include <nlohmann/json.hpp>

bool GalacticPanel::s_visible = false;
bool GalacticPanel::s_initialized = false;
int GalacticPanel::s_selectedTab = 0;

void GalacticPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_visible = false;
    s_selectedTab = 0;
    PanelState::Register("galactic_panel", &s_visible);
}

void GalacticPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

void GalacticPanel::Render() {
    if (!s_visible || !s_initialized) return;
    
    ImGui::Begin("Galactic Systems", &s_visible);
    
    const char* tabs[] = { "Overview", "Star Clusters", "Spiral Arms", "Trade Routes", "Councils" };
    ImGui::TabBar("GalacticTabs");
    for (int i = 0; i < 5; i++) {
        if (ImGui::TabItem(tabs[i])) {
            s_selectedTab = i;
        }
    }
    ImGui::EndTabBar();
    
    switch (s_selectedTab) {
        case 0: {
            auto metrics = Galaxy::GalacticCoreEngine::GetGalacticMetrics();
            ImGui::Text("Galactic Metrics");
            ImGui::Separator();
            ImGui::Text("Star Clusters: %d", metrics["starClusterCount"].get<int>());
            ImGui::Text("Spiral Arms: %d", metrics["spiralArmCount"].get<int>());
            ImGui::Text("Trade Routes: %d", metrics["tradeRouteCount"].get<int>());
            ImGui::Text("Councils: %d", metrics["councilCount"].get<int>());
            ImGui::Separator();
            ImGui::Text("Galactic Coherence: %.2f%%", metrics["galacticCoherence"].get<float>() * 100.0f);
            ImGui::Text("Galactic Stability: %.2f%%", metrics["galacticStability"].get<float>() * 100.0f);
            break;
        }
        case 1: {
            auto clusters = Galaxy::GalacticCoreEngine::GetAllStarClusters();
            ImGui::Text("Star Clusters (%zu)", clusters.size());
            ImGui::Separator();
            for (const auto& cluster : clusters) {
                ImGui::Text("%s (%s)", cluster.name.c_str(), cluster.clusterId.c_str());
                ImGui::Text("  Systems: %zu | Coherence: %.2f | Stability: %.2f",
                    cluster.starSystems.size(), cluster.coherence, cluster.stability);
            }
            break;
        }
        case 2: {
            auto arms = Galaxy::GalacticCoreEngine::GetAllSpiralArms();
            ImGui::Text("Spiral Arms (%zu)", arms.size());
            ImGui::Separator();
            for (const auto& arm : arms) {
                ImGui::Text("%s (%s)", arm.name.c_str(), arm.armId.c_str());
                ImGui::Text("  Clusters: %zu | Density: %.2f | Velocity: %.2f",
                    arm.starClusters.size(), arm.density, arm.rotationVelocity);
            }
            break;
        }
        case 3: {
            auto routes = Galaxy::GalacticCoreEngine::GetTradeRoutes();
            ImGui::Text("Trade Routes (%zu)", routes.size());
            ImGui::Separator();
            for (const auto& route : routes) {
                const char* status = route.active ? "Active" : "Inactive";
                ImGui::Text("%s: %s -> %s [%s]", 
                    route.routeId.c_str(), 
                    route.sourceCluster.c_str(), 
                    route.targetCluster.c_str(),
                    status);
                ImGui::Text("  Volume: %.2f | Efficiency: %.2f", route.tradeVolume, route.efficiency);
            }
            break;
        }
        case 4: {
            ImGui::Text("Galactic Councils");
            ImGui::Separator();
            ImGui::Text("Councils facilitate inter-cluster diplomacy");
            ImGui::Text("and galactic-scale policy decisions.");
            break;
        }
    }
    
    ImGui::End();
}

void GalacticPanel::Toggle() {
    s_visible = !s_visible;
}

bool GalacticPanel::IsVisible() {
    return s_visible;
}

std::string GalacticPanel::Id() {
    return "galactic_panel";
}
