#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class DivineEternityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnEternityEstablished(const std::string& eternityId);
    static void OnEternalManifested(const std::string& eternalId);
    static void OnBlessedRealized(const std::string& blessedId);
    static void OnSanctifiedDiscovered(const std::string& sanctifiedId);

private:
    static void RenderDivineStructureTab();
    static void RenderSacredEternityTab();
    static void RenderHolyEternalTab();
    static void RenderBlessedEternityTab();
    static void RenderSanctifiedEternalTab();
    static void RenderDivineMetricsTab();
    static void RenderDivineVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_divinityInput;
    static float s_eternalityInput;
    static float s_sanctityInput;
    static float s_sacrednessInput;
    static float s_perpetuityInput;
    static float s_holinessInput;
    static float s_holinessEternalInput;
    static float s_divinityEternalInput;
    static float s_graceInput;
    static float s_blessednessInput;
    static float s_eternalityBlessedInput;
    static float s_divinityBlessedInput;
    static float s_sanctificationInput;
    static float s_eternalitySanctifiedInput;
    static float s_divinitySanctifiedInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedEternityId;
    static std::string s_selectedEternalId;
    static std::string s_selectedBlessedId;
    static std::string s_selectedSanctifiedId;
    static std::vector<nlohmann::json> s_divineEvents;
};

} // namespace IDE
