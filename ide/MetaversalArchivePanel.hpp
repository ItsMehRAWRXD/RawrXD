#pragma once
#include <imgui.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class MetaversalArchivePanel {
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
    static void RenderHistoryManager();
    static void RenderRecordManager();
    static void RenderLibraryManager();
    static void RenderDocumentManager();
    static void RenderIndexManager();
    static void RenderMetrics();
    static void RenderReport();
    
    static bool s_visible;
    static bool s_initialized;
    static char s_nameBuffer[256];
    static char s_descriptionBuffer[512];
    static char s_universeBuffer[128];
    static char s_typeBuffer[64];
    static char s_authorBuffer[128];
    static char s_classificationBuffer[64];
    static std::vector<char> s_jsonBuffer;
    static int s_selectedTab;
};

} // namespace IDE
