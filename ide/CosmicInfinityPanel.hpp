#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class CosmicInfinityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnStructureCreated(const std::string& structureId);
    static void OnExistenceManifested(const std::string& existenceId);
    static void OnContinuumEstablished(const std::string& continuumId);
    static void OnInfinityRealized(const std::string& infinityId);
    static void OnHorizonDiscovered(const std::string& horizonId);

private:
    static void RenderInfiniteStructureTab();
    static void RenderBoundlessExistenceTab();
    static void RenderEternalContinuumTab();
    static void RenderOmniversalInfinityTab();
    static void RenderInfiniteHorizonTab();
    static void RenderInfinityMetricsTab();
    static void RenderInfinityVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static float s_boundlessnessInput;
    static float s_endlessnessInput;
    static float s_limitlessnessInput;
    static float s_expansivenessInput;
    static float s_vastnessInput;
    static float s_immensityInput;
    static float s_perpetuityInput;
    static float s_timelessnessInput;
    static float s_permanenceInput;
    static float s_omnipresenceInput;
    static float s_ubiquityInput;
    static float s_infinityInput;
    static float s_horizonInput;
    static float s_frontierInput;
    static float s_edgeInput;
    static std::string s_selectedStructureId;
    static std::string s_selectedExistenceId;
    static std::string s_selectedContinuumId;
    static std::string s_selectedInfinityId;
    static std::string s_selectedHorizonId;
    static std::vector<nlohmann::json> s_infinityEvents;
};

} // namespace IDE
