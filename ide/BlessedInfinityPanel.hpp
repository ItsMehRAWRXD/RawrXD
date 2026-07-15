#pragma once

#include <string>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class BlessedInfinityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();

    // Event handlers
    static void OnBlessedStructureCreated(const std::string& blessedId);
    static void OnInfinityEstablished(const std::string& infinityId);
    static void OnAbundanceManifested(const std::string& abundantId);
    static void OnProsperityRealized(const std::string& prosperousId);
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
    static float s_blessednessInput;
    static float s_infinityInput;
    static float s_abundanceInput;
    static float s_prosperityInput;
    static float s_graceInput;
    static float s_infinityBlessedInput;
    static float s_blessednessInfinityInput;
    static float s_endlessnessInput;
    static float s_boundlessnessInput;
    static float s_abundantBlessedInput;
    static float s_blessednessAbundantInput;
    static float s_plentyInput;
    static float s_wealthInput;
    static float s_prosperousBlessedInput;
    static float s_blessednessProsperousInput;
    static float s_successInput;
    static float s_flourishingInput;
    static float s_graceBlessedInput;
    static float s_blessednessGraceInput;
    static float s_mercyInput;
    static float s_favorInput;
    
    // Selection state
    static std::string s_selectedBlessedId;
    static std::string s_selectedInfinityId;
    static std::string s_selectedAbundantId;
    static std::string s_selectedProsperousId;
    static std::string s_selectedGraceId;
    
    // Event log
    static std::vector<nlohmann::json> s_blessedEvents;
    
    // Tab renderers
    static void RenderBlessedStructureTab();
    static void RenderInfinityBlessedTab();
    static void RenderAbundantBlessedTab();
    static void RenderProsperousBlessedTab();
    static void RenderGraceBlessedTab();
    static void RenderBlessedMetricsTab();
    static void RenderBlessedVisualizationTab();
};

} // namespace IDE
