#pragma once

#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class HolySovereigntyPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();

    // Event handlers
    static void OnHolyStructureCreated(const std::string& holyId);
    static void OnSovereigntyEstablished(const std::string& sovereigntyId);
    static void OnGloryBestowed(const std::string& gloryId);
    static void OnMajestyCrowned(const std::string& majestyId);
    static void OnPowerChanneled(const std::string& powerId);

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
    static float s_holinessInput;
    static float s_sovereigntyInput;
    static float s_gloryInput;
    static float s_majestyInput;
    static float s_powerInput;
    static float s_sovereigntyHolyInput;
    static float s_holinessSovereigntyInput;
    static float s_supremacyInput;
    static float s_dominionInput;
    static float s_gloryHolyInput;
    static float s_holinessGloryInput;
    static float s_brillianceInput;
    static float s_splendorInput;
    static float s_majestyHolyInput;
    static float s_holinessMajestyInput;
    static float s_grandeurInput;
    static float s_dignityInput;
    static float s_powerHolyInput;
    static float s_holinessPowerInput;
    static float s_strengthInput;
    static float s_mightInput;
    
    // Selection state
    static std::string s_selectedHolyId;
    static std::string s_selectedSovereigntyId;
    static std::string s_selectedGloryId;
    static std::string s_selectedMajestyId;
    static std::string s_selectedPowerId;
    
    // Event log
    static std::vector<nlohmann::json> s_holyEvents;
    
    // Tab renderers
    static void RenderHolyStructureTab();
    static void RenderSovereigntyHolyTab();
    static void RenderGloryHolyTab();
    static void RenderMajestyHolyTab();
    static void RenderPowerHolyTab();
    static void RenderHolyMetricsTab();
    static void RenderHolyVisualizationTab();
};

} // namespace IDE
