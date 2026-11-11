#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SupremeInfinityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnInfinityEstablished(const std::string& infinityId);
    static void OnSupremacyManifested(const std::string& supremacyId);
    static void OnInfiniteRealized(const std::string& infiniteId);
    static void OnEternalDiscovered(const std::string& eternalId);

private:
    static void RenderSupremeStructureTab();
    static void RenderUltimateInfinityTab();
    static void RenderEternalSupremacyTab();
    static void RenderInfiniteSupremeTab();
    static void RenderSupremeEternalTab();
    static void RenderSupremeMetricsTab();
    static void RenderSupremeVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_supremacyInput;
    static float s_infinityInput;
    static float s_eternalityInput;
    static float s_ultimacyInput;
    static float s_boundlessnessInput;
    static float s_transcendenceInput;
    static float s_eternalitySupremacyInput;
    static float s_infinitySupremacyInput;
    static float s_divinityInput;
    static float s_infiniteSupremeInput;
    static float s_supremacyInfiniteInput;
    static float s_perpetuityInput;
    static float s_eternalitySupremeInput;
    static float s_supremacyEternalInput;
    static float s_infinityEternalInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedInfinityId;
    static std::string s_selectedSupremacyId;
    static std::string s_selectedInfiniteId;
    static std::string s_selectedEternalId;
    static std::vector<nlohmann::json> s_supremeEvents;
};

} // namespace IDE
