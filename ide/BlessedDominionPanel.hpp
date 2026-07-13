#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class BlessedDominionPanel {
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
    static void OnDominionEstablished(const std::string& dominionId);
    static void OnGraceBestowed(const std::string& graceId);
    static void OnFavorGranted(const std::string& favorId);
    static void OnProvidenceProvided(const std::string& providenceId);

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
    static float s_dominionInput;
    static float s_graceInput;
    static float s_favorInput;
    static float s_providenceInput;
    static float s_dominionBlessedInput;
    static float s_blessednessDominionInput;
    static float s_authorityInput;
    static float s_sovereigntyInput;
    static float s_graceBlessedInput;
    static float s_blessednessGraceInput;
    static float s_mercyInput;
    static float s_kindnessInput;
    static float s_favorBlessedInput;
    static float s_blessednessFavorInput;
    static float s_preferenceInput;
    static float s_approvalInput;
    static float s_providenceBlessedInput;
    static float s_blessednessProvidenceInput;
    static float s_guidanceInput;
    static float s_protectionInput;
    
    // Selection state
    static std::string s_selectedBlessedId;
    static std::string s_selectedDominionId;
    static std::string s_selectedGraceId;
    static std::string s_selectedFavorId;
    static std::string s_selectedProvidenceId;
    
    // Event log
    static std::vector<nlohmann::json> s_blessedEvents;
    
    // Tab renderers
    static void RenderBlessedStructureTab();
    static void RenderDominionBlessedTab();
    static void RenderGraceBlessedTab();
    static void RenderFavorBlessedTab();
    static void RenderProvidenceBlessedTab();
    static void RenderBlessedMetricsTab();
    static void RenderBlessedVisualizationTab();
};

} // namespace IDE
