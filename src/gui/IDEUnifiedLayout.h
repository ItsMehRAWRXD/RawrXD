//==============================================================================
// IDEUnifiedLayout.h - Sovereign IDE Unified Panel Layout System
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef IDE_UNIFIED_LAYOUT_H
#define IDE_UNIFIED_LAYOUT_H

#include <windows.h>

// Panel dock positions
enum DockPosition {
    DOCK_LEFT,
    DOCK_RIGHT,
    DOCK_TOP,
    DOCK_BOTTOM,
    DOCK_CENTER,
    DOCK_FLOATING
};

// Panel structure
struct Panel {
    const char* name;
    void* userData;
    DockPosition dock;
    int x, y, width, height;
    bool visible;
    bool active;
};

// Layout configuration
struct LayoutConfig {
    int leftPanelWidth;
    int rightPanelWidth;
    int topPanelHeight;
    int bottomPanelHeight;
    bool showMenuBar;
    bool showStatusBar;
};

// Unified layout system
class IDEUnifiedLayout {
public:
    static void Initialize(int screenWidth, int screenHeight);
    static void Shutdown();
    
    static void RegisterPanel(const char* name, void* userData, DockPosition defaultDock);
    static void ShowPanel(const char* name);
    static void HidePanel(const char* name);
    static void TogglePanel(const char* name);
    
    static void SetLayout(const LayoutConfig* config);
    static void GetLayout(LayoutConfig* config);
    
    static void Draw();
    static void UpdateLayout();
    
    static Panel* GetPanel(const char* name);
    static Panel* GetActivePanel();
    
    static void SaveLayout(const char* path);
    static void LoadLayout(const char* path);
    
private:
    static const unsigned int MAX_PANELS = 32;
    
    static Panel s_panels[MAX_PANELS];
    static unsigned int s_panelCount;
    static LayoutConfig s_config;
    static int s_screenWidth;
    static int s_screenHeight;
    static bool s_initialized;
};

// MoE-specific layout presets
void IDEUnifiedLayout_ApplyMoELayout();
void IDEUnifiedLayout_ApplyDebugLayout();
void IDEUnifiedLayout_ApplyMinimalLayout();

#endif // IDE_UNIFIED_LAYOUT_H
