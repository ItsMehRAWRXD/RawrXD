#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class HolyInfinityPanel {
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
    static void OnInfinityEstablished(const std::string& infinityId);
    static void OnGraceBestowed(const std::string& graceId);
    static void OnMercyShown(const std::string& mercyId);
    static void OnBlessingGranted(const std::string& blessingId);

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
    static float s_infinityInput;
    static float s_graceInput;
    static float s_mercyInput;
    static float s_blessingInput;
    static float s_infinityHolyInput;
    static float s_holinessInfinityInput;
    static float s_boundlessnessInput;
    static float s_endlessnessInput;
    static float s_graceHolyInput;
    static float s_holinessGraceInput;
    static float s_favorInput;
    static float s_benevolenceInput;
    static float s_mercyHolyInput;
    static float s_holinessMercyInput;
    static float s_compassionInput;
    static float s_forgivenessInput;
    static float s_blessingHolyInput;
    static float s_holinessBlessingInput;
    static float s_abundanceInput;
    static float s_prosperityInput;
    
    // Selection state
    static std::string s_selectedHolyId;
    static std::string s_selectedInfinityId;
    static std::string s_selectedGraceId;
    static std::string s_selectedMercyId;
    static std::string s_selectedBlessingId;
    
    // Event log
    static std::vector<nlohmann::json> s_holyEvents;
    
    // Tab renderers
    static void RenderHolyStructureTab();
    static void RenderInfinityHolyTab();
    static void RenderGraceHolyTab();
    static void RenderMercyHolyTab();
    static void RenderBlessingHolyTab();
    static void RenderHolyMetricsTab();
    static void RenderHolyVisualizationTab();
};

} // namespace IDE
