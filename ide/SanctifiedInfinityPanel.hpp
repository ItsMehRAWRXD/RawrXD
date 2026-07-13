#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class SanctifiedInfinityPanel {
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
    static void OnDivineManifested(const std::string& divineId);
    static void OnSacredRealized(const std::string& sacredId);
    static void OnHolyDiscovered(const std::string& holyId);

private:
    static void RenderSanctifiedStructureTab();
    static void RenderInfiniteSanctifiedTab();
    static void RenderDivineSanctifiedTab();
    static void RenderSacredSanctifiedTab();
    static void RenderHolySanctifiedTab();
    static void RenderSanctifiedMetricsTab();
    static void RenderSanctifiedVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_sanctificationInput;
    static float s_infinityInput;
    static float s_purityInput;
    static float s_consecrationInput;
    static float s_devotionInput;
    static float s_infinitudeInput;
    static float s_sanctificationInfiniteInput;
    static float s_perpetuityInput;
    static float s_divinityInput;
    static float s_sanctificationDivineInput;
    static float s_graceInput;
    static float s_gloryInput;
    static float s_sacrednessInput;
    static float s_sanctificationSacredInput;
    static float s_reverenceInput;
    static float s_holinessInput;
    static float s_sanctificationHolyInput;
    static float s_consecrationHolyInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedInfiniteId;
    static std::string s_selectedDivineId;
    static std::string s_selectedSacredId;
    static std::string s_selectedHolyId;
    static std::vector<nlohmann::json> s_sanctifiedEvents;
};

} // namespace IDE
