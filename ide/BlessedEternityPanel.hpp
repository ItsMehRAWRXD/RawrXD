#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class BlessedEternityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnEternalEstablished(const std::string& eternalId);
    static void OnDivineManifested(const std::string& divineId);
    static void OnSacredRealized(const std::string& sacredId);
    static void OnHolyDiscovered(const std::string& holyId);

private:
    static void RenderBlessedStructureTab();
    static void RenderEternalBlessedTab();
    static void RenderDivineBlessedTab();
    static void RenderSacredBlessedTab();
    static void RenderHolyBlessedTab();
    static void RenderBlessedMetricsTab();
    static void RenderBlessedVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_blessednessInput;
    static float s_eternityInput;
    static float s_graceInput;
    static float s_favorInput;
    static float s_abundanceInput;
    static float s_eternalityInput;
    static float s_blessednessEternalInput;
    static float s_perpetuityInput;
    static float s_divinityInput;
    static float s_blessednessDivineInput;
    static float s_sanctityInput;
    static float s_gloryInput;
    static float s_sacrednessInput;
    static float s_blessednessSacredInput;
    static float s_reverenceInput;
    static float s_holinessInput;
    static float s_blessednessHolyInput;
    static float s_consecrationInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedEternalId;
    static std::string s_selectedDivineId;
    static std::string s_selectedSacredId;
    static std::string s_selectedHolyId;
    static std::vector<nlohmann::json> s_blessedEvents;
};

} // namespace IDE
