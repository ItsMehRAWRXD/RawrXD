#include "ide/AstralNexusPanel.hpp"
#include "astral/AstralNexusEngine.hpp"
#include "astral/AstralNexusLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool AstralNexusPanel::s_visible = false;
bool AstralNexusPanel::s_initialized = false;
char AstralNexusPanel::s_nameBuffer[256] = {};
char AstralNexusPanel::s_typeBuffer[64] = {};
char AstralNexusPanel::s_classBuffer[64] = {};
char AstralNexusPanel::s_sourceBuffer[128] = {};
char AstralNexusPanel::s_destinationBuffer[128] = {};
std::vector<char> AstralNexusPanel::s_jsonBuffer(4096, '\0');
int AstralNexusPanel::s_selectedTab = 0;

void AstralNexusPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Astral::AstralNexusLoop::Init();
    Astral::AstralNexusLoop::Start();
}

void AstralNexusPanel::Shutdown() {
    if (!s_initialized) return;
    Astral::AstralNexusLoop::Shutdown();
    s_initialized = false;
}

void AstralNexusPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Astral Nexus (Layer 61)", &s_visible);
    
    const char* tabs[] = {"Portals", "Gateways", "Bridges", "Conduits", "Connections", "Metrics", "Report"};
    ImGui::TabBar("NexusTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderPortalManager(); break;
        case 1: RenderGatewayManager(); break;
        case 2: RenderBridgeManager(); break;
        case 3: RenderConduitManager(); break;
        case 4: RenderConnectionManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void AstralNexusPanel::RenderPortalManager() {
    ImGui::Text("Universal Portal Management");
    ImGui::Separator();
    
    ImGui::InputText("Portal Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Source Universe", s_sourceBuffer, sizeof(s_sourceBuffer));
    ImGui::InputText("Destination Universe", s_destinationBuffer, sizeof(s_destinationBuffer));
    
    if (ImGui::Button("Establish Portal")) {
        Astral::AstralNexusEngine::EstablishUniversalPortal(s_nameBuffer, s_sourceBuffer, s_destinationBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_sourceBuffer, 0, sizeof(s_sourceBuffer));
        memset(s_destinationBuffer, 0, sizeof(s_destinationBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Portals:");
    auto portals = Astral::AstralNexusEngine::GetAllPortals();
    for (const auto& portal : portals) {
        ImGui::Text("%s - %s [%s] (Stab: %.2f)", portal.portalId.c_str(), portal.name.c_str(), 
                    portal.active ? "ACTIVE" : "INACTIVE", portal.stability);
    }
}

void AstralNexusPanel::RenderGatewayManager() {
    ImGui::Text("Cosmic Gateway Management");
    ImGui::Separator();
    
    ImGui::InputText("Gateway Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Gateway Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Commission Gateway")) {
        Astral::AstralNexusEngine::CommissionCosmicGateway(s_nameBuffer, s_typeBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Commissioned Gateways:");
    auto gateways = Astral::AstralNexusEngine::GetAllGateways();
    for (const auto& gateway : gateways) {
        ImGui::Text("%s - %s [%s] (BW: %.2f)", gateway.gatewayId.c_str(), gateway.name.c_str(), 
                    gateway.gatewayType.c_str(), gateway.bandwidth);
    }
}

void AstralNexusPanel::RenderBridgeManager() {
    ImGui::Text("Multiversal Bridge Management");
    ImGui::Separator();
    
    ImGui::InputText("Bridge Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Bridge Class", s_classBuffer, sizeof(s_classBuffer));
    
    if (ImGui::Button("Construct Bridge")) {
        std::vector<std::string> universes = {"universe_1", "universe_2"};
        Astral::AstralNexusEngine::ConstructMultiversalBridge(s_nameBuffer, s_classBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_classBuffer, 0, sizeof(s_classBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Constructed Bridges:");
    auto bridges = Astral::AstralNexusEngine::GetAllBridges();
    for (const auto& bridge : bridges) {
        ImGui::Text("%s - %s [%s] (Integ: %.2f)", bridge.bridgeId.c_str(), bridge.name.c_str(), 
                    bridge.bridgeClass.c_str(), bridge.structuralIntegrity);
    }
}

void AstralNexusPanel::RenderConduitManager() {
    ImGui::Text("Transcendent Conduit Management");
    ImGui::Separator();
    
    ImGui::InputText("Conduit Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Conduit Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float capacity = 1000.0f;
    ImGui::SliderFloat("Flow Capacity", &capacity, 0.0f, 10000.0f);
    
    if (ImGui::Button("Activate Conduit")) {
        Astral::AstralNexusEngine::ActivateTranscendentConduit(s_nameBuffer, s_typeBuffer, capacity);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Conduits:");
    auto conduits = Astral::AstralNexusEngine::GetAllConduits();
    for (const auto& conduit : conduits) {
        ImGui::Text("%s - %s [%s] (Eff: %.2f)", conduit.conduitId.c_str(), conduit.name.c_str(), 
                    conduit.conduitType.c_str(), conduit.efficiency);
    }
}

void AstralNexusPanel::RenderConnectionManager() {
    ImGui::Text("Nexus Connection Management");
    ImGui::Separator();
    
    ImGui::InputText("Source ID", s_sourceBuffer, sizeof(s_sourceBuffer));
    ImGui::InputText("Destination ID", s_destinationBuffer, sizeof(s_destinationBuffer));
    ImGui::InputText("Connection Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Create Connection")) {
        Astral::AstralNexusEngine::CreateNexusConnection(s_sourceBuffer, s_destinationBuffer, s_typeBuffer);
        memset(s_sourceBuffer, 0, sizeof(s_sourceBuffer));
        memset(s_destinationBuffer, 0, sizeof(s_destinationBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Nexus Connections:");
    auto connections = Astral::AstralNexusEngine::GetAllConnections();
    for (const auto& connection : connections) {
        ImGui::Text("%s - %s (Str: %.2f, Rel: %.2f)", connection.connectionId.c_str(), 
                    connection.connectionType.c_str(), connection.strength, connection.reliability);
    }
}

void AstralNexusPanel::RenderMetrics() {
    ImGui::Text("Nexus Metrics");
    ImGui::Separator();
    
    auto metrics = Astral::AstralNexusEngine::GetNexusMetrics();
    
    ImGui::Text("Portals: %d (%d active)", metrics["portalCount"].get<int>(), metrics["activePortalCount"].get<int>());
    ImGui::Text("Gateways: %d", metrics["gatewayCount"].get<int>());
    ImGui::Text("Bridges: %d", metrics["bridgeCount"].get<int>());
    ImGui::Text("Conduits: %d", metrics["conduitCount"].get<int>());
    ImGui::Text("Connections: %d", metrics["connectionCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Nexus Connectivity: %.4f", metrics["nexusConnectivity"].get<float>());
    ImGui::Text("Average Throughput: %.4f", metrics["averageThroughput"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void AstralNexusPanel::RenderReport() {
    ImGui::Text("Nexus Report");
    ImGui::Separator();
    
    auto report = Astral::AstralNexusEngine::GenerateNexusReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool AstralNexusPanel::IsVisible() {
    return s_visible;
}

void AstralNexusPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void AstralNexusPanel::Toggle() {
    s_visible = !s_visible;
}

const char* AstralNexusPanel::GetPanelName() {
    return "Astral Nexus";
}

const char* AstralNexusPanel::GetShortcut() {
    return "Ctrl+Shift+F33";
}

} // namespace IDE
