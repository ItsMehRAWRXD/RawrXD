#pragma once

#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SacredSovereigntyPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();

    // Event handlers
    static void OnSacredStructureCreated(const std::string& sacredId);
    static void OnSovereigntyEstablished(const std::string& sovereigntyId);
    static void OnAuthorityAsserted(const std::string& authorityId);
    static void OnDominionExtended(const std::string& dominionId);
    static void OnSupremacyAchieved(const std::string& supremacyId);

private:
    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    
    // Input buffers
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    
    // Input values
    static float s_sacrednessInput;
    static float s_sovereigntyInput;
    static float s_authorityInput;
    static float s_dominionInput;
    static float s_supremacyInput;
    static float s_sovereigntySacredInput;
    static float s_sacrednessSovereigntyInput;
    static float s_ruleInput;
    static float s_reignInput;
    static float s_authoritySacredInput;
    static float s_sacrednessAuthorityInput;
    static float s_commandInput;
    static float s_controlInput;
    static float s_dominionSacredInput;
    static float s_sacrednessDominionInput;
    static float s_territoryInput;
    static float s_realmInput;
    static float s_supremacySacredInput;
    static float s_sacrednessSupremacyInput;
    static float s_dominanceInput;
    static float s_preeminenceInput;
    
    // Selection state
    static std::string s_selectedSacredId;
    static std::string s_selectedSovereigntyId;
    static std::string s_selectedAuthorityId;
    static std::string s_selectedDominionId;
    static std::string s_selectedSupremacyId;
    
    // Event log
    static std::vector<nlohmann::json> s_sacredEvents;
    
    // Tab renderers
    static void RenderSacredStructureTab();
    static void RenderSovereigntySacredTab();
    static void RenderAuthoritySacredTab();
    static void RenderDominionSacredTab();
    static void RenderSupremacySacredTab();
    static void RenderSacredMetricsTab();
    static void RenderSacredVisualizationTab();
};

} // namespace IDE
