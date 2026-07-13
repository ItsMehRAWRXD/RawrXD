#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace AbsoluteTruth {
    class AbsoluteTruthEngine;
    struct AbsoluteTruthStructure;
    struct VerityAbsolute;
    struct FactAbsolute;
    struct RealityAbsolute;
    struct ActualityAbsolute;
    struct CertaintyAbsolute;
    struct ValidityAbsolute;
}

namespace IDE {

// Panel for Absolute Truth (Layer 117)
class AbsoluteTruthPanel {
public:
    AbsoluteTruthPanel();
    ~AbsoluteTruthPanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F117"; }
    static int GetLayerNumber() { return 117; }
    static const char* GetLayerName() { return "Absolute Truth"; }

    // Selection
    void SelectAbsoluteTruthStructure(const std::string& truthId);
    void SelectVerityAbsolute(const std::string& verityId);
    void SelectFactAbsolute(const std::string& factId);
    void SelectRealityAbsolute(const std::string& realityId);
    void SelectActualityAbsolute(const std::string& actualityId);
    void SelectCertaintyAbsolute(const std::string& certaintyId);
    void SelectValidityAbsolute(const std::string& validityId);

    // Creation helpers
    void CreateNewAbsoluteTruthStructure();
    void CreateNewVerityAbsolute();
    void CreateNewFactAbsolute();
    void CreateNewRealityAbsolute();
    void CreateNewActualityAbsolute();
    void CreateNewCertaintyAbsolute();
    void CreateNewValidityAbsolute();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        TruthStructures = 0,
        VerityAbsolutes,
        FactAbsolutes,
        RealityAbsolutes,
        ActualityAbsolutes,
        CertaintyAbsolutes,
        ValidityAbsolutes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedTruthId;
    std::string m_selectedVerityId;
    std::string m_selectedFactId;
    std::string m_selectedRealityId;
    std::string m_selectedActualityId;
    std::string m_selectedCertaintyId;
    std::string m_selectedValidityId;

    // Input buffers for creation
    char m_newTruthName[256];
    char m_newVerityName[256];
    char m_newFactName[256];
    char m_newRealityName[256];
    char m_newActualityName[256];
    char m_newCertaintyName[256];
    char m_newValidityName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderTruthStructuresTab();
    void RenderVerityAbsolutesTab();
    void RenderFactAbsolutesTab();
    void RenderRealityAbsolutesTab();
    void RenderActualityAbsolutesTab();
    void RenderCertaintyAbsolutesTab();
    void RenderValidityAbsolutesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderAbsoluteTruthStructureDetails(const std::string& truthId);
    void RenderVerityAbsoluteDetails(const std::string& verityId);
    void RenderFactAbsoluteDetails(const std::string& factId);
    void RenderRealityAbsoluteDetails(const std::string& realityId);
    void RenderActualityAbsoluteDetails(const std::string& actualityId);
    void RenderCertaintyAbsoluteDetails(const std::string& certaintyId);
    void RenderValidityAbsoluteDetails(const std::string& validityId);

    // Action handlers
    void OnExpandAbsoluteTruth(const std::string& truthId);
    void OnAmplifyVerity(const std::string& truthId);
    void OnIncreaseFactuality(const std::string& truthId);
    void OnEnhanceReality(const std::string& truthId);
    void OnSolidifyActuality(const std::string& truthId);
    void OnStrengthenCertainty(const std::string& truthId);
    void OnValidateAbsolute(const std::string& truthId);

    void OnIntensifyVerityAbsolute(const std::string& verityId);
    void OnAffirmVerityAbsolute(const std::string& verityId);
    void OnDeclareVerityAbsolute(const std::string& verityId);

    void OnVerifyFactAbsolute(const std::string& factId);
    void OnEstablishFactAbsolute(const std::string& factId);
    void OnDeclareFactAbsolute(const std::string& factId);

    void OnManifestRealityAbsolute(const std::string& realityId);
    void OnGroundRealityAbsolute(const std::string& realityId);
    void OnDeclareRealityAbsolute(const std::string& realityId);

    void OnRealizeActualityAbsolute(const std::string& actualityId);
    void OnEmbodyActualityAbsolute(const std::string& actualityId);
    void OnDeclareActualityAbsolute(const std::string& actualityId);

    void OnGuaranteeCertaintyAbsolute(const std::string& certaintyId);
    void OnSecureCertaintyAbsolute(const std::string& certaintyId);
    void OnDeclareCertaintyAbsolute(const std::string& certaintyId);

    void OnConfirmValidityAbsolute(const std::string& validityId);
    void OnAuthenticateValidityAbsolute(const std::string& validityId);
    void OnDeclareValidityAbsolute(const std::string& validityId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
