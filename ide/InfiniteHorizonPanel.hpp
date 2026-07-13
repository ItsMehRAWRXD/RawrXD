#pragma once
#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class InfiniteHorizonPanel {
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
    static void RenderFrontierManager();
    static void RenderBoundaryManager();
    static void RenderThresholdManager();
    static void RenderLimitManager();
    static void RenderDiscoveryManager();
    static void RenderMetrics();
    static void RenderReport();
    
    static bool s_visible;
    static bool s_initialized;
    static char s_nameBuffer[256];
    static char s_typeBuffer[64];
    static char s_classBuffer[64];
    static char s_categoryBuffer[64];
    static char s_parentBuffer[128];
    static char s_frontierBuffer[128];
    static std::vector<char> s_jsonBuffer;
    static int s_selectedTab;
};

} // namespace IDE
