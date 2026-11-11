#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class UltimateEternityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnContinuumEstablished(const std::string& continuumId);
    static void OnTimeBegun(const std::string& timeId);
    static void OnExistenceManifested(const std::string& existenceId);
    static void OnHorizonDiscovered(const std::string& horizonId);

private:
    static void RenderUltimateStructureTab();
    static void RenderForeverContinuumTab();
    static void RenderEndlessTimeTab();
    static void RenderPerpetualExistenceTab();
    static void RenderEternalHorizonTab();
    static void RenderEternityMetricsTab();
    static void RenderEternityVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_forevernessInput;
    static float s_perpetuityInput;
    static float s_endlessnessInput;
    static float s_timelessnessInput;
    static float s_infinityInput;
    static float s_permanenceInput;
    static float s_durationInput;
    static float s_continuityInput;
    static float s_persistenceInput;
    static float s_perpetuationInput;
    static float s_sustainabilityInput;
    static float s_immortalityInput;
    static float s_eternityInput;
    static float s_vastnessInput;
    static float s_infinityHorizonInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedContinuumId;
    static std::string s_selectedTimeId;
    static std::string s_selectedExistenceId;
    static std::string s_selectedHorizonId;
    static std::vector<nlohmann::json> s_eternityEvents;
};

} // namespace IDE
