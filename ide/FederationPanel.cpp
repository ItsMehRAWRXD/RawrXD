#include "ide/FederationPanel.hpp"
#include "ide/PanelState.hpp"
#include "federation/FederationGraph.hpp"
#include "federation/FederatedIdentity.hpp"
#include "federation/GlobalResourceEconomy.hpp"
#include "federation/NegotiationProtocol.hpp"
#include <imgui.h>
#include <cstring>

static char nodeIdBuffer[64] = "";
static char clusterIdBuffer[64] = "";

const char* FederationPanel::Id() { return "FederationPanel"; }
void FederationPanel::Toggle() { PanelState::Toggle(Id()); }
bool FederationPanel::IsWired() { return true; }
void FederationPanel::Init() {}

void FederationPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Federation & Coordination");

    // Federated Identity
    if (ImGui::CollapsingHeader("Federated Identity", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto identity = FederatedIdentity::GetFederatedIdentity();
        ImGui::Text("Global ID: %s", identity.value("global_id", "unknown").get<std::string>().c_str());
        ImGui::Text("Active Clusters: %zu", identity.value("cluster_count", 0).get<size_t>());
        
        auto clusters = identity.value("clusters", nlohmann::json::array());
        ImGui::Text("Clusters:");
        ImGui::BeginChild("clusters", ImVec2(0, 60), true);
        for (const auto& cluster : clusters) {
            ImGui::BulletText("%s", cluster.get<std::string>().c_str());
        }
        ImGui::EndChild();
        
        ImGui::InputText("Cluster ID", clusterIdBuffer, sizeof(clusterIdBuffer));
        if (ImGui::Button("Join Cluster")) {
            if (strlen(clusterIdBuffer) > 0) {
                FederatedIdentity::JoinCluster(clusterIdBuffer, {{"role", "member"}});
            }
        }
    }
    
    ImGui::Separator();
    
    // Federation Graph
    if (ImGui::CollapsingHeader("Federation Graph")) {
        auto metrics = FederationGraph::GetGraphMetrics();
        ImGui::Text("Nodes: %zu", metrics.value("node_count", 0).get<size_t>());
        ImGui::Text("Links: %zu", metrics.value("link_count", 0).get<size_t>());
        ImGui::Text("Density: %.3f", metrics.value("density", 0.0).get<double>());
        
        ImGui::InputText("Node ID", nodeIdBuffer, sizeof(nodeIdBuffer));
        if (ImGui::Button("Register Node")) {
            if (strlen(nodeIdBuffer) > 0) {
                FederationGraph::RegisterNode(nodeIdBuffer, {{"type", "cluster"}});
            }
        }
        
        auto links = FederationGraph::GetLinks();
        ImGui::Text("Links:");
        ImGui::BeginChild("links", ImVec2(0, 60), true);
        for (const auto& link : links) {
            ImGui::Text("%s -> %s [%.1f]", 
                link.value("from", "?").get<std::string>().c_str(),
                link.value("to", "?").get<std::string>().c_str(),
                link.value("weight", 0.0).get<double>());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Global Resource Economy
    if (ImGui::CollapsingHeader("Global Resource Economy")) {
        auto economy = GlobalResourceEconomy::GetEconomyMetrics();
        ImGui::Text("Cluster Count: %zu", economy.value("cluster_count", 0).get<size_t>());
        ImGui::Text("Total Requests: %zu", economy.value("total_requests", 0).get<size_t>());
        ImGui::Text("Total Offers: %zu", economy.value("total_offers", 0).get<size_t>());
        
        auto local = GlobalResourceEconomy::GetLocalResources();
        ImGui::Text("Local Resources:");
        ImGui::Text("  CPU: %.1f%%", local.value("cpu", 0.0).get<double>());
        ImGui::Text("  Memory: %.1f MB", local.value("memory", 0.0).get<double>());
    }
    
    ImGui::Separator();
    
    // Negotiations
    if (ImGui::CollapsingHeader("Negotiations")) {
        auto metrics = NegotiationProtocol::GetNegotiationMetrics();
        ImGui::Text("Total: %zu", metrics.value("total_negotiations", 0).get<size_t>());
        ImGui::Text("Pending: %zu", metrics.value("pending", 0).get<size_t>());
        ImGui::Text("Accepted: %zu", metrics.value("accepted", 0).get<size_t>());
        ImGui::Text("Rejected: %zu", metrics.value("rejected", 0).get<size_t>());
        
        auto active = NegotiationProtocol::GetActiveNegotiations();
        ImGui::Text("Active Negotiations:");
        ImGui::BeginChild("negotiations", ImVec2(0, 60), true);
        for (const auto& neg : active) {
            ImGui::Text("%s: %s -> %s", 
                neg.value("id", "?").get<std::string>().c_str(),
                neg.value("from", "?").get<std::string>().c_str(),
                neg.value("to", "?").get<std::string>().c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
