#pragma once
#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class CelestialForgePanel {
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
    static void RenderConstructorManager();
    static void RenderFabricatorManager();
    static void RenderSynthesizerManager();
    static void RenderCreationEngineManager();
    static void RenderArtifactManager();
    static void RenderMetrics();
    static void RenderReport();
    
    static bool s_visible;
    static bool s_initialized;
    static char s_nameBuffer[256];
    static char s_typeBuffer[64];
    static char s_methodBuffer[64];
    static char s_domainBuffer[64];
    static char s_creatorBuffer[128];
    static std::vector<char> s_jsonBuffer;
    static int s_selectedTab;
};

} // namespace IDE
