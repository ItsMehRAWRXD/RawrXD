#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SanctifiedEternityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();

    // Event handlers
    static void OnSanctifiedStructureCreated(const std::string& sanctifiedId);
    static void OnEternityEstablished(const std::string& eternityId);
    static void OnConsecratedManifested(const std::string& consecratedId);
    static void OnDevotedRealized(const std::string& devotedId);
    static void OnPureDiscovered(const std::string& pureId);

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
    static float s_sanctificationInput;
    static float s_eternityInput;
    static float s_consecrationInput;
    static float s_devotionInput;
    static float s_purityInput;
    static float s_eternitySanctifiedInput;
    static float s_sanctificationEternityInput;
    static float s_perpetuityInput;
    static float s_timelessnessInput;
    static float s_consecratedSanctifiedInput;
    static float s_sanctificationConsecratedInput;
    static float s_dedicationInput;
    static float s_commitmentInput;
    static float s_devotedSanctifiedInput;
    static float s_sanctificationDevotedInput;
    static float s_loyaltyInput;
    static float s_faithfulnessInput;
    static float s_pureSanctifiedInput;
    static float s_sanctificationPureInput;
    static float s_clarityInput;
    static float s_innocenceInput;
    
    // Selection state
    static std::string s_selectedSanctifiedId;
    static std::string s_selectedEternityId;
    static std::string s_selectedConsecratedId;
    static std::string s_selectedDevotedId;
    static std::string s_selectedPureId;
    
    // Event log
    static std::vector<nlohmann::json> s_sanctifiedEvents;
    
    // Tab renderers
    static void RenderSanctifiedStructureTab();
    static void RenderEternitySanctifiedTab();
    static void RenderConsecratedSanctifiedTab();
    static void RenderDevotedSanctifiedTab();
    static void RenderPureSanctifiedTab();
    static void RenderSanctifiedMetricsTab();
    static void RenderSanctifiedVisualizationTab();
};

} // namespace IDE
