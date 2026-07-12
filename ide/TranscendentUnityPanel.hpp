#pragma once

#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class TranscendentUnityPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();

    // Event handlers
    static void OnTranscendentStructureCreated(const std::string& transcendentId);
    static void OnUnityEstablished(const std::string& unityId);
    static void OnHarmonyCultivated(const std::string& harmonyId);
    static void OnBalanceEstablished(const std::string& balanceId);
    static void OnSynthesisAchieved(const std::string& synthesisId);

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
    static float s_transcendenceInput;
    static float s_unityInput;
    static float s_harmonyInput;
    static float s_balanceInput;
    static float s_synthesisInput;
    static float s_unityTranscendentInput;
    static float s_transcendenceUnityInput;
    static float s_cohesionInput;
    static float s_onenessInput;
    static float s_harmonyTranscendentInput;
    static float s_transcendenceHarmonyInput;
    static float s_resonanceInput;
    static float s_alignmentInput;
    static float s_balanceTranscendentInput;
    static float s_transcendenceBalanceInput;
    static float s_equilibriumInput;
    static float s_stabilityInput;
    static float s_synthesisTranscendentInput;
    static float s_transcendenceSynthesisInput;
    static float s_integrationInput;
    static float s_fusionInput;
    
    // Selection state
    static std::string s_selectedTranscendentId;
    static std::string s_selectedUnityId;
    static std::string s_selectedHarmonyId;
    static std::string s_selectedBalanceId;
    static std::string s_selectedSynthesisId;
    
    // Event log
    static std::vector<nlohmann::json> s_transcendentEvents;
    
    // Tab renderers
    static void RenderTranscendentStructureTab();
    static void RenderUnityTranscendentTab();
    static void RenderHarmonyTranscendentTab();
    static void RenderBalanceTranscendentTab();
    static void RenderSynthesisTranscendentTab();
    static void RenderTranscendentMetricsTab();
    static void RenderTranscendentVisualizationTab();
};

} // namespace IDE
