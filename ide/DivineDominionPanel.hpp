#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class DivineDominionPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnSovereignEstablished(const std::string& sovereignId);
    static void OnEternalManifested(const std::string& eternalId);
    static void OnSacredRealized(const std::string& sacredId);
    static void OnHolyDiscovered(const std::string& holyId);

private:
    static void RenderDivineStructureTab();
    static void RenderSovereignDivineTab();
    static void RenderEternalDivineTab();
    static void RenderSacredDivineTab();
    static void RenderHolyDivineTab();
    static void RenderDivineMetricsTab();
    static void RenderDivineVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_divinityInput;
    static float s_dominionInput;
    static float s_sovereigntyInput;
    static float s_authorityInput;
    static float s_majestyInput;
    static float s_sovereigntySovereignInput;
    static float s_divinitySovereignInput;
    static float s_supremacyInput;
    static float s_eternalityInput;
    static float s_divinityEternalInput;
    static float s_perpetuityInput;
    static float s_gloryInput;
    static float s_sacrednessInput;
    static float s_divinitySacredInput;
    static float s_reverenceInput;
    static float s_holinessInput;
    static float s_divinityHolyInput;
    static float s_consecrationInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedSovereignId;
    static std::string s_selectedEternalId;
    static std::string s_selectedSacredId;
    static std::string s_selectedHolyId;
    static std::vector<nlohmann::json> s_divineEvents;
};

} // namespace IDE
