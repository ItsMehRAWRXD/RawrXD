#pragma once

#include <string>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class HolyEternityPanel {
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
    static void OnEternityEstablished(const std::string& eternityId);
    static void OnDivineManifested(const std::string& divineId);
    static void OnTranscendentRealized(const std::string& transcendentId);
    static void OnGraceBestowed(const std::string& graceId);

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
    static float s_eternityInput;
    static float s_divinityInput;
    static float s_transcendenceInput;
    static float s_graceInput;
    static float s_eternityHolyInput;
    static float s_holinessEternityInput;
    static float s_infinityInput;
    static float s_perpetuityInput;
    static float s_divineHolyInput;
    static float s_holinessDivineInput;
    static float s_sacrednessInput;
    static float s_blessingInput;
    static float s_transcendentHolyInput;
    static float s_holinessTranscendentInput;
    static float s_elevationInput;
    static float s_ascensionInput;
    static float s_graceHolyInput;
    static float s_holinessGraceInput;
    static float s_mercyInput;
    static float s_favorInput;
    
    // Selection state
    static std::string s_selectedHolyId;
    static std::string s_selectedEternityId;
    static std::string s_selectedDivineId;
    static std::string s_selectedTranscendentId;
    static std::string s_selectedGraceId;
    
    // Event log
    static std::vector<nlohmann::json> s_holyEvents;
    
    // Tab renderers
    static void RenderHolyStructureTab();
    static void RenderEternityHolyTab();
    static void RenderDivineHolyTab();
    static void RenderTranscendentHolyTab();
    static void RenderGraceHolyTab();
    static void RenderHolyMetricsTab();
    static void RenderHolyVisualizationTab();
};

} // namespace IDE
