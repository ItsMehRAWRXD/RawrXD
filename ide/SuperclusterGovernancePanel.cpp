#include "ide/SuperclusterGovernancePanel.hpp"
#include "ide/PanelState.hpp"
#include "supercluster/SuperclusterGovernanceEngine.hpp"
#include "supercluster/SuperclusterGovernanceLoop.hpp"
#include <imgui.h>
#include <nlohmann/json.hpp>

bool SuperclusterGovernancePanel::s_visible = false;
bool SuperclusterGovernancePanel::s_initialized = false;
int SuperclusterGovernancePanel::s_selectedTab = 0;

void SuperclusterGovernancePanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    s_visible = false;
    s_selectedTab = 0;
    PanelState::Register("supercluster_governance_panel", &s_visible);
}

void SuperclusterGovernancePanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

void SuperclusterGovernancePanel::Render() {
    if (!s_visible || !s_initialized) return;
    
    ImGui::Begin("Supercluster Governance", &s_visible);
    
    const char* tabs[] = { "Overview", "Regions", "Protocols", "Alliances", "Policies", "Councils" };
    if (ImGui::BeginTabBar("SuperclusterTabs")) {
        for (int i = 0; i < 6; i++) {
            if (ImGui::TabItem(tabs[i])) {
                s_selectedTab = i;
            }
        }
        ImGui::EndTabBar();
    }
    
    switch (s_selectedTab) {
        case 0: {
            auto metrics = Supercluster::SuperclusterGovernanceEngine::GetGovernanceMetrics();
            ImGui::Text("Supercluster Governance Metrics");
            ImGui::Separator();
            ImGui::Text("Regions: %d", metrics["regionCount"].get<int>());
            ImGui::Text("Protocols: %d", metrics["protocolCount"].get<int>());
            ImGui::Text("Alliances: %d", metrics["allianceCount"].get<int>());
            ImGui::Text("Policies: %d", metrics["policyCount"].get<int>());
            ImGui::Text("Councils: %d", metrics["councilCount"].get<int>());
            ImGui::Separator();
            ImGui::Text("Governance Coherence: %.2f%%", metrics["governanceCoherence"].get<float>() * 100.0f);
            ImGui::Text("Inter-Regional Stability: %.2f%%", metrics["interRegionalStability"].get<float>() * 100.0f);
            break;
        }
        case 1: {
            auto regions = Supercluster::SuperclusterGovernanceEngine::GetAllSuperclusterRegions();
            ImGui::Text("Supercluster Regions (%zu)", regions.size());
            ImGui::Separator();
            for (const auto& region : regions) {
                ImGui::Text("%s (%s)", region.name.c_str(), region.regionId.c_str());
                ImGui::Text("  Superclusters: %zu | Coherence: %.2f | Governance: %.2f",
                    region.memberSuperclusters.size(), region.coherence, region.governanceStrength);
            }
            break;
        }
        case 2: {
            auto protocols = Supercluster::SuperclusterGovernanceEngine::GetAllProtocols();
            ImGui::Text("Governance Protocols (%zu)", protocols.size());
            ImGui::Separator();
            for (const auto& protocol : protocols) {
                const char* status = protocol.active ? "Active" : "Inactive";
                ImGui::Text("%s (%s) [%s]", protocol.name.c_str(), protocol.protocolId.c_str(), status);
                ImGui::Text("  Enforcement: %.2f%%", protocol.enforcementLevel * 100.0f);
            }
            break;
        }
        case 3: {
            auto alliances = Supercluster::SuperclusterGovernanceEngine::GetAllAlliances();
            ImGui::Text("Inter-Supercluster Alliances (%zu)", alliances.size());
            ImGui::Separator();
            for (const auto& alliance : alliances) {
                ImGui::Text("%s (%s)", alliance.name.c_str(), alliance.allianceId.c_str());
                ImGui::Text("  Regions: %zu | Solidarity: %.2f",
                    alliance.memberRegions.size(), alliance.solidarityIndex);
            }
            break;
        }
        case 4: {
            auto policies = Supercluster::SuperclusterGovernanceEngine::GetAllPolicies();
            ImGui::Text("Cosmic Policies (%zu)", policies.size());
            ImGui::Separator();
            for (const auto& policy : policies) {
                ImGui::Text("%s (%s) [%s]", policy.name.c_str(), policy.policyId.c_str(), policy.scope.c_str());
                ImGui::Text("  Compliance: %.2f%%", policy.complianceRate * 100.0f);
            }
            break;
        }
        case 5: {
            ImGui::Text("Supercluster Councils");
            ImGui::Separator();
            ImGui::Text("Councils facilitate inter-regional governance");
            ImGui::Text("and cosmic-scale policy coordination.");
            break;
        }
    }
    
    ImGui::End();
}

void SuperclusterGovernancePanel::Toggle() {
    s_visible = !s_visible;
}

bool SuperclusterGovernancePanel::IsVisible() {
    return s_visible;
}

std::string SuperclusterGovernancePanel::Id() {
    return "supercluster_governance_panel";
}
