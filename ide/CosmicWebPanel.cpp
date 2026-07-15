#include "ide/CosmicWebPanel.hpp"
#include "ide/PanelState.hpp"
#include "cosmic/CosmicWebEngine.hpp"
#include "cosmic/CosmicWebLoop.hpp"
#include <imgui.h>
#include <nlohmann/json.hpp>

bool CosmicWebPanel::s_visible = false;
bool CosmicWebPanel::s_initialized = false;
int CosmicWebPanel::s_selectedTab = 0;

void CosmicWebPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_visible = false;
    s_selectedTab = 0;
    PanelState::Register("cosmic_web_panel", &s_visible);
}

void CosmicWebPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

void CosmicWebPanel::Render() {
    if (!s_visible || !s_initialized) return;
    
    ImGui::Begin("Cosmic Web", &s_visible);
    
    const char* tabs[] = { "Overview", "Galaxy Clusters", "Filaments", "Superclusters", "Councils" };
    ImGui::TabBar("CosmicWebTabs");
    for (int i = 0; i < 5; i++) {
        if (ImGui::TabItem(tabs[i])) {
            s_selectedTab = i;
        }
    }
    ImGui::EndTabBar();
    
    switch (s_selectedTab) {
        case 0: {
            auto metrics = Cosmic::CosmicWebEngine::GetCosmicMetrics();
            ImGui::Text("Cosmic Web Metrics");
            ImGui::Separator();
            ImGui::Text("Galaxy Clusters: %d", metrics["galaxyClusterCount"].get<int>());
            ImGui::Text("Filaments: %d", metrics["filamentCount"].get<int>());
            ImGui::Text("Superclusters: %d", metrics["superclusterCount"].get<int>());
            ImGui::Text("Cosmic Nodes: %d", metrics["cosmicNodeCount"].get<int>());
            ImGui::Separator();
            ImGui::Text("Cosmic Coherence: %.2f%%", metrics["cosmicCoherence"].get<float>() * 100.0f);
            ImGui::Text("Cosmic Expansion: %.4f", metrics["cosmicExpansionRate"].get<float>());
            break;
        }
        case 1: {
            auto clusters = Cosmic::CosmicWebEngine::GetAllGalaxyClusters();
            ImGui::Text("Galaxy Clusters (%zu)", clusters.size());
            ImGui::Separator();
            for (const auto& cluster : clusters) {
                ImGui::Text("%s (%s)", cluster.name.c_str(), cluster.clusterId.c_str());
                ImGui::Text("  Galaxies: %zu | Mass: %.2e | Coherence: %.2f",
                    cluster.galaxies.size(), cluster.mass, cluster.coherence);
            }
            break;
        }
        case 2: {
            auto filaments = Cosmic::CosmicWebEngine::GetAllFilaments();
            ImGui::Text("Cosmic Filaments (%zu)", filaments.size());
            ImGui::Separator();
            for (const auto& filament : filaments) {
                ImGui::Text("%s (%s)", filament.name.c_str(), filament.filamentId.c_str());
                ImGui::Text("  Clusters: %zu | Length: %.2f | Energy: %.2e",
                    filament.galaxyClusters.size(), filament.length, 
                    Cosmic::CosmicWebEngine::CalculateFilamentEnergy(filament.filamentId));
            }
            break;
        }
        case 3: {
            auto superclusters = Cosmic::CosmicWebEngine::GetAllSuperclusters();
            ImGui::Text("Superclusters (%zu)", superclusters.size());
            ImGui::Separator();
            for (const auto& supercluster : superclusters) {
                ImGui::Text("%s (%s)", supercluster.name.c_str(), supercluster.superclusterId.c_str());
                ImGui::Text("  Filaments: %zu | Volume: %.2e | Mass: %.2e",
                    supercluster.filaments.size(), supercluster.volume, supercluster.mass);
            }
            break;
        }
        case 4: {
            ImGui::Text("Universal Councils");
            ImGui::Separator();
            ImGui::Text("Councils facilitate inter-supercluster diplomacy");
            ImGui::Text("and cosmic-scale policy decisions.");
            break;
        }
    }
    
    ImGui::End();
}

void CosmicWebPanel::Toggle() {
    s_visible = !s_visible;
}

bool CosmicWebPanel::IsVisible() {
    return s_visible;
}

std::string CosmicWebPanel::Id() {
    return "cosmic_web_panel";
}
