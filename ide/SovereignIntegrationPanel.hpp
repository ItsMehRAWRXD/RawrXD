#pragma once
#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SovereignIntegrationPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void Toggle();
    static const char* GetPanelName();
    static const char* GetShortcut();

private:
    static void RenderLayerOverview();
    static void RenderOrchestrationManager();
    static void RenderBridgeManager();
    static void RenderSystemHealth();
    static void RenderSystemControls();
    static void RenderEventMonitor();
    static void RenderSystemReport();
    
    static bool s_visible;
    static bool s_initialized;
    static char s_nameBuffer[256];
    static char s_typeBuffer[64];
    static int s_selectedTab;
    static int s_selectedLayer;
};

} // namespace IDE
