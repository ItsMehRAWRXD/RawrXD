#pragma once

#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SanctifiedDominionPanel {
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
    static void OnDominionEstablished(const std::string& dominionId);
    static void OnPurityBestowed(const std::string& purityId);
    static void OnDevotionInspired(const std::string& devotionId);
    static void OnConsecrationPerformed(const std::string& consecrationId);

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
    static float s_sanctifiednessInput;
    static float s_dominionInput;
    static float s_purityInput;
    static float s_devotionInput;
    static float s_consecrationInput;
    static float s_dominionSanctifiedInput;
    static float s_sanctifiednessDominionInput;
    static float s_authorityInput;
    static float s_ruleInput;
    static float s_puritySanctifiedInput;
    static float s_sanctifiednessPurityInput;
    static float s_cleanlinessInput;
    static float s_innocenceInput;
    static float s_devotionSanctifiedInput;
    static float s_sanctifiednessDevotionInput;
    static float s_dedicationInput;
    static float s_commitmentInput;
    static float s_consecrationSanctifiedInput;
    static float s_sanctifiednessConsecrationInput;
    static float s_dedicationConsecrationInput;
    static float s_sanctityInput;
    
    // Selection state
    static std::string s_selectedSanctifiedId;
    static std::string s_selectedDominionId;
    static std::string s_selectedPurityId;
    static std::string s_selectedDevotionId;
    static std::string s_selectedConsecrationId;
    
    // Event log
    static std::vector<nlohmann::json> s_sanctifiedEvents;
    
    // Tab renderers
    static void RenderSanctifiedStructureTab();
    static void RenderDominionSanctifiedTab();
    static void RenderPuritySanctifiedTab();
    static void RenderDevotionSanctifiedTab();
    static void RenderConsecrationSanctifiedTab();
    static void RenderSanctifiedMetricsTab();
    static void RenderSanctifiedVisualizationTab();
};

} // namespace IDE
