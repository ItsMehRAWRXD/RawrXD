#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace AbsoluteReality {
    class AbsoluteRealityEngine;
    struct AbsoluteRealityStructure;
    struct RealityAbsolute;
    struct TruthAbsolute;
    struct ExistenceAbsolute;
    struct ActualityAbsolute;
    struct SubstanceAbsolute;
}

namespace IDE {

// Panel for Absolute Reality (Layer 110)
class AbsoluteRealityPanel {
public:
    AbsoluteRealityPanel();
    ~AbsoluteRealityPanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F110"; }
    static int GetLayerNumber() { return 110; }
    static const char* GetLayerName() { return "Absolute Reality"; }

    // Selection
    void SelectAbsoluteStructure(const std::string& absoluteId);
    void SelectRealityAbsolute(const std::string& realityId);
    void SelectTruthAbsolute(const std::string& truthId);
    void SelectExistenceAbsolute(const std::string& existenceId);
    void SelectActualityAbsolute(const std::string& actualityId);
    void SelectSubstanceAbsolute(const std::string& substanceId);

    // Creation helpers
    void CreateNewAbsoluteStructure();
    void CreateNewRealityAbsolute();
    void CreateNewTruthAbsolute();
    void CreateNewExistenceAbsolute();
    void CreateNewActualityAbsolute();
    void CreateNewSubstanceAbsolute();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        AbsoluteStructures = 0,
        RealityAbsolutes,
        TruthAbsolutes,
        ExistenceAbsolutes,
        ActualityAbsolutes,
        SubstanceAbsolutes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedAbsoluteId;
    std::string m_selectedRealityId;
    std::string m_selectedTruthId;
    std::string m_selectedExistenceId;
    std::string m_selectedActualityId;
    std::string m_selectedSubstanceId;

    // Input buffers for creation
    char m_newAbsoluteName[256];
    char m_newRealityName[256];
    char m_newTruthName[256];
    char m_newExistenceName[256];
    char m_newActualityName[256];
    char m_newSubstanceName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderAbsoluteStructuresTab();
    void RenderRealityAbsolutesTab();
    void RenderTruthAbsolutesTab();
    void RenderExistenceAbsolutesTab();
    void RenderActualityAbsolutesTab();
    void RenderSubstanceAbsolutesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderAbsoluteStructureDetails(const std::string& absoluteId);
    void RenderRealityAbsoluteDetails(const std::string& realityId);
    void RenderTruthAbsoluteDetails(const std::string& truthId);
    void RenderExistenceAbsoluteDetails(const std::string& existenceId);
    void RenderActualityAbsoluteDetails(const std::string& actualityId);
    void RenderSubstanceAbsoluteDetails(const std::string& substanceId);

    // Action handlers
    void OnExpandAbsoluteness(const std::string& absoluteId);
    void OnDeepenReality(const std::string& absoluteId);
    void OnRevealTruth(const std::string& absoluteId);
    void OnAffirmExistence(const std::string& absoluteId);
    void OnManifestActuality(const std::string& absoluteId);
    void OnSolidifySubstance(const std::string& absoluteId);

    void OnRealizeActuality(const std::string& realityId);
    void OnConfirmExistence(const std::string& realityId);
    void OnDeclareReal(const std::string& realityId);

    void OnVerifyVeracity(const std::string& truthId);
    void OnValidateTruth(const std::string& truthId);
    void OnDeclareTrue(const std::string& truthId);

    void OnAffirmBeing(const std::string& existenceId);
    void OnManifestPresence(const std::string& existenceId);
    void OnDeclareExisting(const std::string& existenceId);

    void OnEstablishFactuality(const std::string& actualityId);
    void OnEnsureCertainty(const std::string& actualityId);
    void OnDeclareActual(const std::string& actualityId);

    void OnDeepenEssence(const std::string& substanceId);
    void OnMaterializeMatter(const std::string& substanceId);
    void OnDeclareSubstantial(const std::string& substanceId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
