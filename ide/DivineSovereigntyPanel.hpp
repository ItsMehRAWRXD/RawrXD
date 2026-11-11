#pragma once

#include <imgui.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class DivineSovereigntyPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnDivinePresenceManifested(const std::string& presenceId);
    static void OnCovenantEstablished(const std::string& covenantId);
    static void OnScriptureRevealed(const std::string& scriptureId);
    static void OnMiraclePerformed(const std::string& miracleId);
    static void OnRealmConsecrated(const std::string& realmId);

private:
    static void RenderDivinePresenceTab();
    static void RenderSacredCovenantTab();
    static void RenderHolyScriptureTab();
    static void RenderBlessedMiracleTab();
    static void RenderSanctifiedRealmTab();
    static void RenderDivineMetricsTab();
    static void RenderDivineVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_termsBuffer[512];
    static char s_textBuffer[1024];
    static char s_manifestationBuffer[512];
    static char s_entityIdBuffer[256];
    static char s_inhabitantIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_omnipresenceInput;
    static float s_sanctityInput;
    static float s_graceInput;
    static float s_bindingInput;
    static float s_eternalityInput;
    static float s_wisdomInput;
    static float s_truthInput;
    static float s_authorityInput;
    static float s_divinityInput;
    static float s_wonderInput;
    static float s_faithInput;
    static float s_holinessInput;
    static float s_protectionInput;
    static float s_blessingInput;
    static std::string s_selectedPresenceId;
    static std::string s_selectedCovenantId;
    static std::string s_selectedScriptureId;
    static std::string s_selectedMiracleId;
    static std::string s_selectedRealmId;
    static std::vector<nlohmann::json> s_divineEvents;
};

} // namespace IDE
