#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <map>

namespace Sovereign {
namespace IDE {

/**
 * @brief Docking positions
 */
enum class DockPosition {
    Left,
    Right,
    Top,
    Bottom,
    Center,
    Floating
};

/**
 * @brief Panel information
 */
struct PanelInfo {
    std::string name;
    HWND hwnd;
    DockPosition position;
    int width;
    int height;
    bool visible;
    bool collapsed;
};

/**
 * @brief Layout preset
 */
struct LayoutPreset {
    std::string name;
    std::vector<PanelInfo> panels;
};

/**
 * @brief Sovereign Docking Layout Presets
 * 
 * Manages IDE panel layouts with presets for:
 * - Development (code + health + profiler)
 * - Debugging (replay + scheduler + health)
 * - Profiling (profiler + GPU graph + KV heatmap)
 * - Minimal (just code)
 */
class DockingLayout {
public:
    static DockingLayout& Instance();

    void Initialize(HWND mainWindow);
    void Shutdown();

    // Panel management
    void AddPanel(const std::string& name, HWND hwnd, DockPosition pos, int size);
    void RemovePanel(const std::string& name);
    void ShowPanel(const std::string& name);
    void HidePanel(const std::string& name);
    void TogglePanel(const std::string& name);
    
    // Layout presets
    void SavePreset(const std::string& name);
    void LoadPreset(const std::string& name);
    void DeletePreset(const std::string& name);
    std::vector<std::string> GetPresetNames() const;
    
    // Built-in presets
    void ApplyDevelopmentLayout();
    void ApplyDebuggingLayout();
    void ApplyProfilingLayout();
    void ApplyMinimalLayout();
    
    // Layout operations
    void SaveLayout(const std::wstring& path);
    void LoadLayout(const std::wstring& path);
    void ResetLayout();
    
    // Auto-save/restore
    void EnableAutoSave(bool enable);
    void RestoreLastLayout();

private:
    DockingLayout() = default;
    
    HWND m_mainWindow = nullptr;
    std::map<std::string, PanelInfo> m_panels;
    std::map<std::string, LayoutPreset> m_presets;
    bool m_autoSave = false;
    
    void ArrangePanels();
    void CalculateLayout(std::vector<RECT>& panelRects);
};

} // namespace IDE
} // namespace Sovereign
