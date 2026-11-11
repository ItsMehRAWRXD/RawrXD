#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SacredEternityPanel {
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
    static void OnEternityEstablished(const std::string& eternityId);
    static void OnReverentManifested(const std::string& reverentId);
    static void OnSanctityRealized(const std::string& sanctityId);
    static void OnDevotedDiscovered(const std::string& devotedId);

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
    static float s_eternityInput;
    static float s_reverenceInput;
    static float s_sanctityInput;
    static float s_devotionInput;
    static float s_eternitySacredInput;
    static float s_sacrednessEternityInput;
    static float s_perpetuityInput;
    static float s_timelessnessInput;
    static float s_reverentSacredInput;
    static float s_sacrednessReverentInput;
    static float s_aweInput;
    static float s_venerationInput;
    static float s_sanctitySacredInput;
    static float s_sacrednessSanctityInput;
    static float s_holinessInput;
    static float s_blessednessInput;
    static float s_devotedSacredInput;
    static float s_sacrednessDevotedInput;
    static float s_dedicationInput;
    static float s_commitmentInput;
    
    // Selection state
    static std::string s_selectedSacredId;
    static std::string s_selectedEternityId;
    static std::string s_selectedReverentId;
    static std::string s_selectedSanctityId;
    static std::string s_selectedDevotedId;
    
    // Event log
    static std::vector<nlohmann::json> s_sacredEvents;
    
    // Tab renderers
    static void RenderSacredStructureTab();
    static void RenderEternitySacredTab();
    static void RenderReverentSacredTab();
    static void RenderSanctitySacredTab();
    static void RenderDevotedSacredTab();
    static void RenderSacredMetricsTab();
    static void RenderSacredVisualizationTab();
};

} // namespace IDE
