#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class HolyDominionPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnDominionEstablished(const std::string& dominionId);
    static void OnSacredManifested(const std::string& sacredId);
    static void OnBlessedRealized(const std::string& blessedId);
    static void OnSanctifiedDiscovered(const std::string& sanctifiedId);

private:
    static void RenderHolyStructureTab();
    static void RenderDominionHolyTab();
    static void RenderSacredDominionTab();
    static void RenderBlessedDominionTab();
    static void RenderSanctifiedDominionTab();
    static void RenderHolyMetricsTab();
    static void RenderHolyVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_holinessInput;
    static float s_dominionInput;
    static float s_authorityInput;
    static float s_graceInput;
    static float s_blessingInput;
    static float s_dominionHolyInput;
    static float s_holinessDominionInput;
    static float s_sovereigntyInput;
    static float s_sacrednessInput;
    static float s_dominionSacredInput;
    static float s_reverenceInput;
    static float s_sanctityInput;
    static float s_blessednessInput;
    static float s_dominionBlessedInput;
    static float s_favorInput;
    static float s_sanctificationInput;
    static float s_dominionSanctifiedInput;
    static float s_consecrationInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedDominionId;
    static std::string s_selectedSacredId;
    static std::string s_selectedBlessedId;
    static std::string s_selectedSanctifiedId;
    static std::vector<nlohmann::json> s_holyEvents;
};

} // namespace IDE
