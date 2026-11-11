#pragma once
#include <imgui.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class OmniversalTribunalPanel {
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
    static void RenderCourtManager();
    static void RenderCaseManager();
    static void RenderLawManager();
    static void RenderArbitratorManager();
    static void RenderVerdictManager();
    static void RenderMetrics();
    static void RenderReport();
    
    static bool s_visible;
    static bool s_initialized;
    static char s_nameBuffer[256];
    static char s_descriptionBuffer[512];
    static char s_jurisdictionBuffer[128];
    static char s_scopeBuffer[128];
    static char s_specializationBuffer[128];
    static char s_statusBuffer[64];
    static char s_rulingBuffer[64];
    static std::vector<char> s_jsonBuffer;
    static int s_selectedTab;
};

} // namespace IDE
