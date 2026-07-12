#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class AbsoluteForeverPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnPerpetuityEstablished(const std::string& perpetuityId);
    static void OnAbsoluteManifested(const std::string& absoluteId);
    static void OnExistenceRealized(const std::string& existenceId);
    static void OnInfiniteDiscovered(const std::string& infiniteId);

private:
    static void RenderAbsoluteStructureTab();
    static void RenderUltimatePerpetuityTab();
    static void RenderEternalAbsoluteTab();
    static void RenderForeverExistenceTab();
    static void RenderInfiniteAbsoluteTab();
    static void RenderAbsoluteMetricsTab();
    static void RenderAbsoluteVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_absolutenessInput;
    static float s_perpetuityInput;
    static float s_eternalityInput;
    static float s_perpetuationInput;
    static float s_sustainabilityInput;
    static float s_continuityInput;
    static float s_eternalityAbsoluteInput;
    static float s_infinityInput;
    static float s_transcendenceInput;
    static float s_forevernessInput;
    static float s_permanenceInput;
    static float s_immortalityInput;
    static float s_infinityAbsoluteInput;
    static float s_boundlessnessInput;
    static float s_limitlessnessInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedPerpetuityId;
    static std::string s_selectedAbsoluteId;
    static std::string s_selectedExistenceId;
    static std::string s_selectedInfiniteId;
    static std::vector<nlohmann::json> s_absoluteEvents;
};

} // namespace IDE
