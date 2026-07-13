#include "ide/SovereignIntegrationPanel.hpp"
#include "integration/SovereignIntegrationEngine.hpp"
#include "integration/SovereignIntegrationLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SovereignIntegrationPanel::s_visible = false;
bool SovereignIntegrationPanel::s_initialized = false;
char SovereignIntegrationPanel::s_nameBuffer[256] = {};
char SovereignIntegrationPanel::s_typeBuffer[64] = {};
int SovereignIntegrationPanel::s_selectedTab = 0;
int SovereignIntegrationPanel::s_selectedLayer = 1;

void SovereignIntegrationPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Integration::SovereignIntegrationLoop::Init();
    Integration::SovereignIntegrationLoop::Start();
}

void SovereignIntegrationPanel::Shutdown() {
    if (!s_initialized) return;
    Integration::SovereignIntegrationLoop::Shutdown();
    s_initialized = false;
}

void SovereignIntegrationPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sovereign Integration (Layer 65)", &s_visible);
    
    const char* tabs[] = {"Layer Overview", "Orchestrations", "Bridges", "System Health", "Controls", "Events", "Report"};
    ImGui::TabBar("IntegrationTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderLayerOverview(); break;
        case 1: RenderOrchestrationManager(); break;
        case 2: RenderBridgeManager(); break;
        case 3: RenderSystemHealth(); break;
        case 4: RenderSystemControls(); break;
        case 5: RenderEventMonitor(); break;
        case 6: RenderSystemReport(); break;
    }
    
    ImGui::End();
}

void SovereignIntegrationPanel::RenderLayerOverview() {
    ImGui::Text("64-Layer Architecture Overview");
    ImGui::Separator();
    
    auto statuses = Integration::SovereignIntegrationEngine::GetAllLayerStatuses();
    
    int initialized = 0, active = 0;
    for (const auto& status : statuses) {
        if (status.initialized) initialized++;
        if (status.active) active++;
    }
    
    ImGui::Text("Total Layers: 64");
    ImGui::Text("Initialized: %d/64", initialized);
    ImGui::Text("Active: %d/64", active);
    
    ImGui::Separator();
    ImGui::Text("Layer Status Grid:");
    
    ImGui::SliderInt("Select Layer", &s_selectedLayer, 1, 64);
    
    auto status = Integration::SovereignIntegrationEngine::GetLayerStatus(s_selectedLayer);
    ImGui::Text("Layer %d: %s", status.layerId, status.layerName.c_str());
    ImGui::Text("  Initialized: %s", status.initialized ? "YES" : "NO");
    ImGui::Text("  Active: %s", status.active ? "YES" : "NO");
    ImGui::Text("  Health: %.2f%%", status.health * 100.0f);
    
    if (ImGui::Button("Initialize")) {
        Integration::SovereignIntegrationEngine::InitializeLayer(s_selectedLayer);
    }
    ImGui::SameLine();
    if (ImGui::Button("Activate")) {
        Integration::SovereignIntegrationEngine::ActivateLayer(s_selectedLayer);
    }
    ImGui::SameLine();
    if (ImGui::Button("Deactivate")) {
        Integration::SovereignIntegrationEngine::DeactivateLayer(s_selectedLayer);
    }
}

void SovereignIntegrationPanel::RenderOrchestrationManager() {
    ImGui::Text("Cross-Layer Orchestration");
    ImGui::Separator();
    
    ImGui::InputText("Orchestration Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Orchestration Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Create Orchestration")) {
        std::vector<int> layers = {1, 2, 3, 4, 5};
        nlohmann::json params;
        params["priority"] = "high";
        Integration::SovereignIntegrationEngine::CreateOrchestration(s_nameBuffer, layers, s_typeBuffer, params);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Orchestrations:");
    auto orchestrations = Integration::SovereignIntegrationEngine::GetAllOrchestrations();
    for (const auto& orch : orchestrations) {
        ImGui::Text("%s - %s [%s] (%s)", orch.orchestrationId.c_str(), orch.name.c_str(), 
                    orch.orchestrationType.c_str(), orch.executing ? "RUNNING" : "PAUSED");
    }
}

void SovereignIntegrationPanel::RenderBridgeManager() {
    ImGui::Text("Cross-Layer Bridges");
    ImGui::Separator();
    
    static int sourceLayer = 1;
    static int destLayer = 2;
    ImGui::SliderInt("Source Layer", &sourceLayer, 1, 64);
    ImGui::SliderInt("Destination Layer", &destLayer, 1, 64);
    ImGui::InputText("Bridge Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Establish Bridge")) {
        Integration::SovereignIntegrationEngine::EstablishBridge(sourceLayer, destLayer, s_typeBuffer);
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Bridges:");
    auto bridges = Integration::SovereignIntegrationEngine::GetAllBridges();
    for (const auto& bridge : bridges) {
        ImGui::Text("%s: Layer %d <-> Layer %d [%s] (BW: %.0f)", bridge.bridgeId.c_str(), 
                    bridge.sourceLayer, bridge.destinationLayer, bridge.bridgeType.c_str(), bridge.bandwidth);
    }
}

void SovereignIntegrationPanel::RenderSystemHealth() {
    ImGui::Text("System Health Monitor");
    ImGui::Separator();
    
    auto health = Integration::SovereignIntegrationEngine::CalculateSystemHealth();
    
    ImGui::Text("Overall Health: %.2f%%", health.overallHealth * 100.0f);
    ImGui::ProgressBar(health.overallHealth);
    
    ImGui::Text("Layer Synchronization: %.2f%%", health.layerSynchronization * 100.0f);
    ImGui::ProgressBar(health.layerSynchronization);
    
    ImGui::Text("Data Flow Efficiency: %.2f%%", health.dataFlowEfficiency * 100.0f);
    ImGui::ProgressBar(health.dataFlowEfficiency);
    
    ImGui::Text("Orchestration Capability: %.2f%%", health.orchestrationCapability * 100.0f);
    ImGui::ProgressBar(health.orchestrationCapability);
    
    ImGui::Separator();
    ImGui::Text("Active Layers: %d/64", health.activeLayers);
    ImGui::Text("Active Bridges: %d", health.activeBridges);
}

void SovereignIntegrationPanel::RenderSystemControls() {
    ImGui::Text("System Control Panel");
    ImGui::Separator();
    
    if (ImGui::Button("Initialize All Layers", ImVec2(200, 40))) {
        Integration::SovereignIntegrationEngine::InitializeAllLayers();
    }
    
    if (ImGui::Button("Activate All Layers", ImVec2(200, 40))) {
        Integration::SovereignIntegrationEngine::ActivateAllLayers();
    }
    
    if (ImGui::Button("Deactivate All Layers", ImVec2(200, 40))) {
        Integration::SovereignIntegrationEngine::DeactivateAllLayers();
    }
    
    ImGui::Separator();
    
    if (ImGui::Button("Emergency Shutdown", ImVec2(200, 40))) {
        Integration::SovereignIntegrationEngine::EmergencyShutdown();
    }
    
    if (ImGui::Button("System Reboot", ImVec2(200, 40))) {
        Integration::SovereignIntegrationEngine::SystemReboot();
    }
}

void SovereignIntegrationPanel::RenderEventMonitor() {
    ImGui::Text("System Event Monitor");
    ImGui::Separator();
    
    ImGui::Text("Event Log:");
    ImGui::BeginChild("EventLog", ImVec2(0, 200), true);
    ImGui::Text("[System] Integration Layer initialized");
    ImGui::Text("[System] Monitoring 64 layers");
    ImGui::Text("[System] Event system active");
    ImGui::EndChild();
    
    if (ImGui::Button("Broadcast Test Event")) {
        nlohmann::json eventData;
        eventData["message"] = "Test event from Integration Panel";
        Integration::SovereignIntegrationEngine::BroadcastEvent("test", eventData);
    }
}

void SovereignIntegrationPanel::RenderSystemReport() {
    ImGui::Text("System Integration Report");
    ImGui::Separator();
    
    auto report = Integration::SovereignIntegrationEngine::GenerateSystemReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool SovereignIntegrationPanel::IsVisible() {
    return s_visible;
}

void SovereignIntegrationPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void SovereignIntegrationPanel::Toggle() {
    s_visible = !s_visible;
}

const char* SovereignIntegrationPanel::GetPanelName() {
    return "Sovereign Integration";
}

const char* SovereignIntegrationPanel::GetShortcut() {
    return "Ctrl+Shift+F37";
}

} // namespace IDE
