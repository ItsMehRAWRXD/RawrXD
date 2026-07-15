#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace PrimordialEssence {
    class PrimordialEssenceEngine;
    struct PrimordialEssenceStructure;
    struct OriginAbsolute;
    struct SourceAbsolute;
    struct RootAbsolute;
    struct FoundationAbsolute;
    struct GroundAbsolute;
}

namespace IDE {

// Panel for Primordial Essence (Layer 111)
class PrimordialEssencePanel {
public:
    PrimordialEssencePanel();
    ~PrimordialEssencePanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F111"; }
    static int GetLayerNumber() { return 111; }
    static const char* GetLayerName() { return "Primordial Essence"; }

    // Selection
    void SelectPrimordialStructure(const std::string& primordialId);
    void SelectOriginAbsolute(const std::string& originId);
    void SelectSourceAbsolute(const std::string& sourceId);
    void SelectRootAbsolute(const std::string& rootId);
    void SelectFoundationAbsolute(const std::string& foundationId);
    void SelectGroundAbsolute(const std::string& groundId);

    // Creation helpers
    void CreateNewPrimordialStructure();
    void CreateNewOriginAbsolute();
    void CreateNewSourceAbsolute();
    void CreateNewRootAbsolute();
    void CreateNewFoundationAbsolute();
    void CreateNewGroundAbsolute();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        PrimordialStructures = 0,
        OriginAbsolutes,
        SourceAbsolutes,
        RootAbsolutes,
        FoundationAbsolutes,
        GroundAbsolutes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedPrimordialId;
    std::string m_selectedOriginId;
    std::string m_selectedSourceId;
    std::string m_selectedRootId;
    std::string m_selectedFoundationId;
    std::string m_selectedGroundId;

    // Input buffers for creation
    char m_newPrimordialName[256];
    char m_newOriginName[256];
    char m_newSourceName[256];
    char m_newRootName[256];
    char m_newFoundationName[256];
    char m_newGroundName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderPrimordialStructuresTab();
    void RenderOriginAbsolutesTab();
    void RenderSourceAbsolutesTab();
    void RenderRootAbsolutesTab();
    void RenderFoundationAbsolutesTab();
    void RenderGroundAbsolutesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderPrimordialStructureDetails(const std::string& primordialId);
    void RenderOriginAbsoluteDetails(const std::string& originId);
    void RenderSourceAbsoluteDetails(const std::string& sourceId);
    void RenderRootAbsoluteDetails(const std::string& rootId);
    void RenderFoundationAbsoluteDetails(const std::string& foundationId);
    void RenderGroundAbsoluteDetails(const std::string& groundId);

    // Action handlers
    void OnDeepenPrimordiality(const std::string& primordialId);
    void OnTraceOrigin(const std::string& primordialId);
    void OnTapSource(const std::string& primordialId);
    void OnExtendRoot(const std::string& primordialId);
    void OnLayFoundation(const std::string& primordialId);
    void OnEstablishGround(const std::string& primordialId);

    void OnCommenceBeginning(const std::string& originId);
    void OnMarkInception(const std::string& originId);
    void OnDeclareOriginated(const std::string& originId);

    void OnOpenWellspring(const std::string& sourceId);
    void OnActivateFountain(const std::string& sourceId);
    void OnDeclareSourced(const std::string& sourceId);

    void OnStrengthenBasis(const std::string& rootId);
    void OnFortifyCore(const std::string& rootId);
    void OnDeclareRooted(const std::string& rootId);

    void OnPrepareGroundwork(const std::string& foundationId);
    void OnSecureUnderpinning(const std::string& foundationId);
    void OnDeclareFounded(const std::string& foundationId);

    void OnCultivateSoil(const std::string& groundId);
    void OnExposeBedrock(const std::string& groundId);
    void OnDeclareGrounded(const std::string& groundId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
