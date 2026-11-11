#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace EternalVoid {
    class EternalVoidEngine;
    struct EternalVoidStructure;
    struct EmptinessAbsolute;
    struct NothingnessAbsolute;
    struct SilenceAbsolute;
    struct StillnessAbsolute;
    struct DarknessAbsolute;
}

namespace IDE {

// Panel for Eternal Void (Layer 113)
class EternalVoidPanel {
public:
    EternalVoidPanel();
    ~EternalVoidPanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F113"; }
    static int GetLayerNumber() { return 113; }
    static const char* GetLayerName() { return "Eternal Void"; }

    // Selection
    void SelectEternalStructure(const std::string& eternalId);
    void SelectEmptinessAbsolute(const std::string& emptinessId);
    void SelectNothingnessAbsolute(const std::string& nothingnessId);
    void SelectSilenceAbsolute(const std::string& silenceId);
    void SelectStillnessAbsolute(const std::string& stillnessId);
    void SelectDarknessAbsolute(const std::string& darknessId);

    // Creation helpers
    void CreateNewEternalStructure();
    void CreateNewEmptinessAbsolute();
    void CreateNewNothingnessAbsolute();
    void CreateNewSilenceAbsolute();
    void CreateNewStillnessAbsolute();
    void CreateNewDarknessAbsolute();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        EternalStructures = 0,
        EmptinessAbsolutes,
        NothingnessAbsolutes,
        SilenceAbsolutes,
        StillnessAbsolutes,
        DarknessAbsolutes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedEternalId;
    std::string m_selectedEmptinessId;
    std::string m_selectedNothingnessId;
    std::string m_selectedSilenceId;
    std::string m_selectedStillnessId;
    std::string m_selectedDarknessId;

    // Input buffers for creation
    char m_newEternalName[256];
    char m_newEmptinessName[256];
    char m_newNothingnessName[256];
    char m_newSilenceName[256];
    char m_newStillnessName[256];
    char m_newDarknessName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderEternalStructuresTab();
    void RenderEmptinessAbsolutesTab();
    void RenderNothingnessAbsolutesTab();
    void RenderSilenceAbsolutesTab();
    void RenderStillnessAbsolutesTab();
    void RenderDarknessAbsolutesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderEternalStructureDetails(const std::string& eternalId);
    void RenderEmptinessAbsoluteDetails(const std::string& emptinessId);
    void RenderNothingnessAbsoluteDetails(const std::string& nothingnessId);
    void RenderSilenceAbsoluteDetails(const std::string& silenceId);
    void RenderStillnessAbsoluteDetails(const std::string& stillnessId);
    void RenderDarknessAbsoluteDetails(const std::string& darknessId);

    // Action handlers
    void OnDeepenEternalVoid(const std::string& eternalId);
    void OnEmbraceEmptiness(const std::string& eternalId);
    void OnAcceptNothingness(const std::string& eternalId);
    void OnEnterSilence(const std::string& eternalId);
    void OnAchieveStillness(const std::string& eternalId);
    void OnDescendIntoDarkness(const std::string& eternalId);

    void OnCreateVacancy(const std::string& emptinessId);
    void OnDeepenHollowness(const std::string& emptinessId);
    void OnDeclareEmpty(const std::string& emptinessId);

    void OnEmbraceNullity(const std::string& nothingnessId);
    void OnExpandVoidness(const std::string& nothingnessId);
    void OnDeclareNothing(const std::string& nothingnessId);

    void OnCultivateQuietude(const std::string& silenceId);
    void OnDeepenMuteness(const std::string& silenceId);
    void OnDeclareSilent(const std::string& silenceId);

    void OnAchieveMotionlessness(const std::string& stillnessId);
    void OnCultivateCalmness(const std::string& stillnessId);
    void OnDeclareStill(const std::string& stillnessId);

    void OnDeepenObscurity(const std::string& darknessId);
    void OnExtendShadow(const std::string& darknessId);
    void OnDeclareDark(const std::string& darknessId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
