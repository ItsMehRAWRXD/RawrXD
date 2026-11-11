#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace EternalRadiance {
    class EternalRadianceEngine;
    struct EternalRadianceStructure;
    struct GlowEternal;
    struct ShineEternal;
    struct BrightnessEternal;
    struct IntensityEternal;
    struct LuminescenceEternal;
    struct TransparencyEternal;
}

namespace IDE {

// Panel for Eternal Radiance (Layer 115)
class EternalRadiancePanel {
public:
    EternalRadiancePanel();
    ~EternalRadiancePanel();

    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;

    // Rendering
    void Render();
    void RenderWindow();

    // Visibility
    void Show();
    void Hide();
    void ToggleVisibility();
    bool IsVisible() const;

    // Hotkey
    static const char* GetHotkey() { return "Ctrl+Shift+F115"; }
    static int GetLayerNumber() { return 115; }
    static const char* GetLayerName() { return "Eternal Radiance"; }

    // Selection
    void SelectEternalRadianceStructure(const std::string& eternalId);
    void SelectGlowEternal(const std::string& glowId);
    void SelectShineEternal(const std::string& shineId);
    void SelectBrightnessEternal(const std::string& brightnessId);
    void SelectIntensityEternal(const std::string& intensityId);
    void SelectLuminescenceEternal(const std::string& luminescenceId);
    void SelectTransparencyEternal(const std::string& transparencyId);

    // Creation helpers
    void CreateNewEternalRadianceStructure();
    void CreateNewGlowEternal();
    void CreateNewShineEternal();
    void CreateNewBrightnessEternal();
    void CreateNewIntensityEternal();
    void CreateNewLuminescenceEternal();
    void CreateNewTransparencyEternal();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        EternalStructures = 0,
        GlowEternals,
        ShineEternals,
        BrightnessEternals,
        IntensityEternals,
        LuminescenceEternals,
        TransparencyEternals,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedEternalId;
    std::string m_selectedGlowId;
    std::string m_selectedShineId;
    std::string m_selectedBrightnessId;
    std::string m_selectedIntensityId;
    std::string m_selectedLuminescenceId;
    std::string m_selectedTransparencyId;

    // Input buffers for creation
    char m_newEternalName[256];
    char m_newGlowName[256];
    char m_newShineName[256];
    char m_newBrightnessName[256];
    char m_newIntensityName[256];
    char m_newLuminescenceName[256];
    char m_newTransparencyName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderEternalStructuresTab();
    void RenderGlowEternalsTab();
    void RenderShineEternalsTab();
    void RenderBrightnessEternalsTab();
    void RenderIntensityEternalsTab();
    void RenderLuminescenceEternalsTab();
    void RenderTransparencyEternalsTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderEternalRadianceStructureDetails(const std::string& eternalId);
    void RenderGlowEternalDetails(const std::string& glowId);
    void RenderShineEternalDetails(const std::string& shineId);
    void RenderBrightnessEternalDetails(const std::string& brightnessId);
    void RenderIntensityEternalDetails(const std::string& intensityId);
    void RenderLuminescenceEternalDetails(const std::string& luminescenceId);
    void RenderTransparencyEternalDetails(const std::string& transparencyId);

    // Action handlers
    void OnExpandEternalRadiance(const std::string& eternalId);
    void OnAmplifyGlow(const std::string& eternalId);
    void OnIncreaseShine(const std::string& eternalId);
    void OnEnhanceBrightness(const std::string& eternalId);
    void OnIntensifyRadiance(const std::string& eternalId);
    void OnSpreadLuminescence(const std::string& eternalId);
    void OnClarifyTransparency(const std::string& eternalId);

    void OnIntensifyGlowEternal(const std::string& glowId);
    void OnAmplifyShineEternal(const std::string& glowId);
    void OnDeclareGlowEternal(const std::string& glowId);

    void OnIncreaseBrightnessEternal(const std::string& shineId);
    void OnIntensifyShineEternal(const std::string& shineId);
    void OnDeclareShineEternal(const std::string& shineId);

    void OnBrightenEternal(const std::string& brightnessId);
    void OnPolishEternal(const std::string& brightnessId);
    void OnDeclareBrightnessEternal(const std::string& brightnessId);

    void OnStrengthenEternal(const std::string& intensityId);
    void OnDeepenEternal(const std::string& intensityId);
    void OnDeclareIntensityEternal(const std::string& intensityId);

    void OnIlluminateEternal(const std::string& luminescenceId);
    void OnRadiateEternal(const std::string& luminescenceId);
    void OnDeclareLuminescenceEternal(const std::string& luminescenceId);

    void OnMakeEternalTransparent(const std::string& transparencyId);
    void OnIncreaseEternalClarity(const std::string& transparencyId);
    void OnDeclareTransparencyEternal(const std::string& transparencyId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
