#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace InfiniteLight {
    class InfiniteLightEngine;
    struct InfiniteLightStructure;
    struct RadianceAbsolute;
    struct BrillianceAbsolute;
    struct LuminosityAbsolute;
    struct IlluminationAbsolute;
    struct ClarityAbsolute;
}

namespace IDE {

// Panel for Infinite Light (Layer 114)
class InfiniteLightPanel {
public:
    InfiniteLightPanel();
    ~InfiniteLightPanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F114"; }
    static int GetLayerNumber() { return 114; }
    static const char* GetLayerName() { return "Infinite Light"; }

    // Selection
    void SelectInfiniteStructure(const std::string& infiniteId);
    void SelectRadianceAbsolute(const std::string& radianceId);
    void SelectBrillianceAbsolute(const std::string& brillianceId);
    void SelectLuminosityAbsolute(const std::string& luminosityId);
    void SelectIlluminationAbsolute(const std::string& illuminationId);
    void SelectClarityAbsolute(const std::string& clarityId);

    // Creation helpers
    void CreateNewInfiniteStructure();
    void CreateNewRadianceAbsolute();
    void CreateNewBrillianceAbsolute();
    void CreateNewLuminosityAbsolute();
    void CreateNewIlluminationAbsolute();
    void CreateNewClarityAbsolute();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        InfiniteStructures = 0,
        RadianceAbsolutes,
        BrillianceAbsolutes,
        LuminosityAbsolutes,
        IlluminationAbsolutes,
        ClarityAbsolutes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedInfiniteId;
    std::string m_selectedRadianceId;
    std::string m_selectedBrillianceId;
    std::string m_selectedLuminosityId;
    std::string m_selectedIlluminationId;
    std::string m_selectedClarityId;

    // Input buffers for creation
    char m_newInfiniteName[256];
    char m_newRadianceName[256];
    char m_newBrillianceName[256];
    char m_newLuminosityName[256];
    char m_newIlluminationName[256];
    char m_newClarityName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderInfiniteStructuresTab();
    void RenderRadianceAbsolutesTab();
    void RenderBrillianceAbsolutesTab();
    void RenderLuminosityAbsolutesTab();
    void RenderIlluminationAbsolutesTab();
    void RenderClarityAbsolutesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderInfiniteStructureDetails(const std::string& infiniteId);
    void RenderRadianceAbsoluteDetails(const std::string& radianceId);
    void RenderBrillianceAbsoluteDetails(const std::string& brillianceId);
    void RenderLuminosityAbsoluteDetails(const std::string& luminosityId);
    void RenderIlluminationAbsoluteDetails(const std::string& illuminationId);
    void RenderClarityAbsoluteDetails(const std::string& clarityId);

    // Action handlers
    void OnExpandInfiniteLight(const std::string& infiniteId);
    void OnAmplifyRadiance(const std::string& infiniteId);
    void OnIncreaseBrilliance(const std::string& infiniteId);
    void OnEnhanceLuminosity(const std::string& infiniteId);
    void OnSpreadIllumination(const std::string& infiniteId);
    void OnSharpenClarity(const std::string& infiniteId);

    void OnIntensifyGlow(const std::string& radianceId);
    void OnAmplifyShine(const std::string& radianceId);
    void OnDeclareRadiant(const std::string& radianceId);

    void OnIncreaseBrightness(const std::string& brillianceId);
    void OnIntensify(const std::string& brillianceId);
    void OnDeclareBrilliant(const std::string& brillianceId);

    void OnBrighten(const std::string& luminosityId);
    void OnPolishShine(const std::string& luminosityId);
    void OnDeclareLuminous(const std::string& luminosityId);

    void OnEnlighten(const std::string& illuminationId);
    void OnReveal(const std::string& illuminationId);
    void OnDeclareIlluminated(const std::string& illuminationId);

    void OnMakeTransparent(const std::string& clarityId);
    void OnIncreaseLucidity(const std::string& clarityId);
    void OnDeclareClear(const std::string& clarityId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
