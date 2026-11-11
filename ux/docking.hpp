// docking.hpp — Docking & Layout System
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>

namespace RawrXD {
namespace UX {

// ============================================================================
// Dock Position
// ============================================================================
enum class DockPosition {
    Left,
    Right,
    Top,
    Bottom,
    Center,
    Floating
};

// ============================================================================
// Panel Definition
// ============================================================================
struct PanelDefinition {
    std::string id;
    std::string title;
    std::string icon;
    DockPosition defaultPosition = DockPosition::Left;
    bool closable = true;
    bool movable = true;
    bool resizable = true;
    int defaultWidth = 300;
    int defaultHeight = 200;
    int minWidth = 100;
    int minHeight = 50;
};

// ============================================================================
// Panel Instance
// ============================================================================
class PanelInstance {
public:
    PanelInstance(const PanelDefinition& def);
    ~PanelInstance();

    const std::string& GetId() const { return m_definition.id; }
    const PanelDefinition& GetDefinition() const { return m_definition; }

    DockPosition GetPosition() const { return m_position; }
    void SetPosition(DockPosition pos) { m_position = pos; }

    int GetX() const { return m_x; }
    int GetY() const { return m_y; }
    int GetWidth() const { return m_width; }
    int GetHeight() const { return m_height; }

    void SetBounds(int x, int y, int w, int h) { m_x = x; m_y = y; m_width = w; m_height = h; }

    bool IsVisible() const { return m_visible; }
    void SetVisible(bool visible) { m_visible = visible; }

    bool IsFocused() const { return m_focused; }
    void SetFocused(bool focused) { m_focused = focused; }

    // Render callback
    using RenderCallback = std::function<void(void* hdc, int x, int y, int w, int h)>;
    void SetRenderCallback(RenderCallback callback) { m_renderCallback = callback; }
    void Render(void* hdc, int x, int y, int w, int h);

private:
    PanelDefinition m_definition;
    DockPosition m_position = DockPosition::Left;
    int m_x = 0, m_y = 0, m_width = 300, m_height = 200;
    bool m_visible = true;
    bool m_focused = false;
    RenderCallback m_renderCallback;
};

// ============================================================================
// Layout Preset
// ============================================================================
struct LayoutPreset {
    std::string name;
    std::map<std::string, DockPosition> panelPositions;
    std::map<std::string, bool> panelVisibility;
    std::map<std::string, int> panelSizes;
};

// ============================================================================
// Docking Manager
// ============================================================================
class DockingManager {
public:
    static DockingManager& Get();

    // Register a panel type
    void RegisterPanel(const PanelDefinition& def);

    // Open a panel instance
    PanelInstance* OpenPanel(const std::string& panelId);

    // Close a panel
    void ClosePanel(const std::string& panelId);

    // Get panel by ID
    PanelInstance* GetPanel(const std::string& panelId);

    // List all open panels
    std::vector<PanelInstance*> GetOpenPanels() const;

    // List panels at a position
    std::vector<PanelInstance*> GetPanelsAt(DockPosition position) const;

    // Toggle panel visibility
    void TogglePanel(const std::string& panelId);

    // Focus a panel
    void FocusPanel(const std::string& panelId);

    // Move panel to new position
    void MovePanel(const std::string& panelId, DockPosition newPosition);

    // Layout management
    bool SaveLayout(const std::string& name);
    bool LoadLayout(const std::string& name);
    std::vector<std::string> ListLayouts() const;
    void ResetLayout();

    // Split management
    void SplitPanel(const std::string& panelId, DockPosition direction);
    void MergePanels(const std::string& targetId, const std::string& sourceId);

    // Events
    using PanelEventCallback = std::function<void(const std::string& panelId)>;
    void OnPanelOpened(PanelEventCallback callback) { m_onOpened = callback; }
    void OnPanelClosed(PanelEventCallback callback) { m_onClosed = callback; }
    void OnPanelFocused(PanelEventCallback callback) { m_onFocused = callback; }
    void OnLayoutChanged(std::function<void()> callback) { m_onLayoutChanged = callback; }

private:
    DockingManager() = default;

    std::map<std::string, PanelDefinition> m_panelDefinitions;
    std::map<std::string, std::unique_ptr<PanelInstance>> m_openPanels;
    std::map<std::string, LayoutPreset> m_layouts;
    std::string m_activeLayout;

    PanelEventCallback m_onOpened;
    PanelEventCallback m_onClosed;
    PanelEventCallback m_onFocused;
    std::function<void()> m_onLayoutChanged;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
