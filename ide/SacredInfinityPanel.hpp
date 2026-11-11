#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SacredInfinityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnInfiniteEstablished(const std::string& infiniteId);
    static void OnHolyManifested(const std::string& holyId);
    static void OnBlessedRealized(const std::string& blessedId);
    static void OnSanctifiedDiscovered(const std::string& sanctifiedId);

private:
    static void RenderSacredStructureTab();
    static void RenderInfiniteSacredTab();
    static void RenderHolyInfiniteTab();
    static void RenderBlessedInfiniteTab();
    static void RenderSanctifiedInfiniteTab();
    static void RenderSacredMetricsTab();
    static void RenderSacredVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_sacrednessInput;
    static float s_infinityInput;
    static float s_divinityInput;
    static float s_purityInput;
    static float s_transcendenceInput;
    static float s_infinitudeInput;
    static float s_sacrednessInfiniteInput;
    static float s_perpetuityInput;
    static float s_holinessInput;
    static float s_infinitudeHolyInput;
    static float s_graceInput;
    static float s_blessingInput;
    static float s_blessednessInput;
    static float s_infinityBlessedInput;
    static float s_favorInput;
    static float s_sanctificationInput;
    static float s_infinitySanctifiedInput;
    static float s_consecrationInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedInfiniteId;
    static std::string s_selectedHolyId;
    static std::string s_selectedBlessedId;
    static std::string s_selectedSanctifiedId;
    static std::vector<nlohmann::json> s_sacredEvents;
};

} // namespace IDE
