//==============================================================================
// IDEUnifiedLayout.cpp - Sovereign IDE Unified Panel Layout Implementation
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "IDEUnifiedLayout.h"
#include "MoEPanel.h"
#include "MoEDiagnosticsPanel.h"
#include "MoEDebuggerPanel.h"
#include "MoEHeatmapPanel.h"
#include "MoESpecExplorerPanel.h"
#include "MASMEditorPanel.h"

// Static members
Panel IDEUnifiedLayout::s_panels[IDEUnifiedLayout::MAX_PANELS];
unsigned int IDEUnifiedLayout::s_panelCount = 0;
LayoutConfig IDEUnifiedLayout::s_config = {};
int IDEUnifiedLayout::s_screenWidth = 0;
int IDEUnifiedLayout::s_screenHeight = 0;
bool IDEUnifiedLayout::s_initialized = false;

//==============================================================================
// Implementation
//==============================================================================

void IDEUnifiedLayout::Initialize(int screenWidth, int screenHeight) {
    if (s_initialized) return;
    
    s_screenWidth = screenWidth;
    s_screenHeight = screenHeight;
    s_panelCount = 0;
    
    // Default layout
    s_config.leftPanelWidth = 250;
    s_config.rightPanelWidth = 300;
    s_config.topPanelHeight = 30;
    s_config.bottomPanelHeight = 150;
    s_config.showMenuBar = true;
    s_config.showStatusBar = true;
    
    s_initialized = true;
}

void IDEUnifiedLayout::Shutdown() {
    s_initialized = false;
    s_panelCount = 0;
}

void IDEUnifiedLayout::RegisterPanel(const char* name, void* userData, DockPosition defaultDock) {
    if (s_panelCount >= MAX_PANELS) return;
    
    Panel* p = &s_panels[s_panelCount];
    p->name = name;
    p->userData = userData;
    p->dock = defaultDock;
    p->visible = false;
    p->active = false;
    
    // Calculate initial position based on dock
    switch (defaultDock) {
        case DOCK_LEFT:
            p->x = 0;
            p->y = s_config.topPanelHeight;
            p->width = s_config.leftPanelWidth;
            p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
            break;
        case DOCK_RIGHT:
            p->x = s_screenWidth - s_config.rightPanelWidth;
            p->y = s_config.topPanelHeight;
            p->width = s_config.rightPanelWidth;
            p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
            break;
        case DOCK_BOTTOM:
            p->x = s_config.leftPanelWidth;
            p->y = s_screenHeight - s_config.bottomPanelHeight;
            p->width = s_screenWidth - s_config.leftPanelWidth - s_config.rightPanelWidth;
            p->height = s_config.bottomPanelHeight;
            break;
        case DOCK_CENTER:
            p->x = s_config.leftPanelWidth;
            p->y = s_config.topPanelHeight;
            p->width = s_screenWidth - s_config.leftPanelWidth - s_config.rightPanelWidth;
            p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
            break;
        default:
            p->x = 100;
            p->y = 100;
            p->width = 400;
            p->height = 300;
            break;
    }
    
    s_panelCount++;
}

void IDEUnifiedLayout::ShowPanel(const char* name) {
    Panel* p = GetPanel(name);
    if (p) {
        p->visible = true;
        p->active = true;
    }
}

void IDEUnifiedLayout::HidePanel(const char* name) {
    Panel* p = GetPanel(name);
    if (p) {
        p->visible = false;
        p->active = false;
    }
}

void IDEUnifiedLayout::TogglePanel(const char* name) {
    Panel* p = GetPanel(name);
    if (p) {
        p->visible = !p->visible;
        p->active = p->visible;
    }
}

void IDEUnifiedLayout::SetLayout(const LayoutConfig* config) {
    s_config = *config;
    UpdateLayout();
}

void IDEUnifiedLayout::GetLayout(LayoutConfig* config) {
    *config = s_config;
}

void IDEUnifiedLayout::UpdateLayout() {
    // Recalculate all panel positions
    for (unsigned int i = 0; i < s_panelCount; i++) {
        Panel* p = &s_panels[i];
        
        switch (p->dock) {
            case DOCK_LEFT:
                p->width = s_config.leftPanelWidth;
                p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
                break;
            case DOCK_RIGHT:
                p->x = s_screenWidth - s_config.rightPanelWidth;
                p->width = s_config.rightPanelWidth;
                p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
                break;
            case DOCK_BOTTOM:
                p->y = s_screenHeight - s_config.bottomPanelHeight;
                p->width = s_screenWidth - s_config.leftPanelWidth - s_config.rightPanelWidth;
                break;
            case DOCK_CENTER:
                p->width = s_screenWidth - s_config.leftPanelWidth - s_config.rightPanelWidth;
                p->height = s_screenHeight - s_config.topPanelHeight - s_config.bottomPanelHeight;
                break;
            default:
                break;
        }
    }
}

void IDEUnifiedLayout::Draw() {
    if (!s_initialized) return;
    
    // Draw menu bar
    if (s_config.showMenuBar) {
        DrawRect(0, 0, s_screenWidth, s_config.topPanelHeight);
        DrawText("Sovereign IDE - MoE Kernel Active");
    }
    
    // Draw status bar
    if (s_config.showStatusBar) {
        DrawRect(0, s_screenHeight - 20, s_screenWidth, 20);
        DrawText("Ready | MoE Backend: Loaded | Experts: 64");
    }
    
    // Draw visible panels
    for (unsigned int i = 0; i < s_panelCount; i++) {
        Panel* p = &s_panels[i];
        if (p->visible) {
            DrawPanel(p);
        }
    }
}

Panel* IDEUnifiedLayout::GetPanel(const char* name) {
    for (unsigned int i = 0; i < s_panelCount; i++) {
        if (strcmp(s_panels[i].name, name) == 0) {
            return &s_panels[i];
        }
    }
    return nullptr;
}

Panel* IDEUnifiedLayout::GetActivePanel() {
    for (unsigned int i = 0; i < s_panelCount; i++) {
        if (s_panels[i].active) {
            return &s_panels[i];
        }
    }
    return nullptr;
}

void IDEUnifiedLayout::SaveLayout(const char* path) {
    // Write layout to file (sovereign file I/O)
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr, 
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD written;
    WriteFile(hFile, &s_config, sizeof(s_config), &written, nullptr);
    WriteFile(hFile, &s_panelCount, sizeof(s_panelCount), &written, nullptr);
    WriteFile(hFile, s_panels, sizeof(Panel) * s_panelCount, &written, nullptr);
    
    CloseHandle(hFile);
}

void IDEUnifiedLayout::LoadLayout(const char* path) {
    // Read layout from file (sovereign file I/O)
    HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, nullptr, 
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD read;
    ReadFile(hFile, &s_config, sizeof(s_config), &read, nullptr);
    ReadFile(hFile, &s_panelCount, sizeof(s_panelCount), &read, nullptr);
    ReadFile(hFile, s_panels, sizeof(Panel) * s_panelCount, &read, nullptr);
    
    CloseHandle(hFile);
    UpdateLayout();
}

//==============================================================================
// MoE Layout Presets
//==============================================================================

void IDEUnifiedLayout_ApplyMoELayout() {
    // Standard MoE development layout
    LayoutConfig config = {};
    config.leftPanelWidth = 250;
    config.rightPanelWidth = 350;
    config.topPanelHeight = 30;
    config.bottomPanelHeight = 200;
    config.showMenuBar = true;
    config.showStatusBar = true;
    
    IDEUnifiedLayout::SetLayout(&config);
    
    // Show MoE panels
    IDEUnifiedLayout::ShowPanel("MoE Output");
    IDEUnifiedLayout::ShowPanel("MoE Diagnostics");
    IDEUnifiedLayout::ShowPanel("MoE Heatmap");
}

void IDEUnifiedLayout_ApplyDebugLayout() {
    // Debug-focused layout
    LayoutConfig config = {};
    config.leftPanelWidth = 300;
    config.rightPanelWidth = 400;
    config.topPanelHeight = 30;
    config.bottomPanelHeight = 250;
    config.showMenuBar = true;
    config.showStatusBar = true;
    
    IDEUnifiedLayout::SetLayout(&config);
    
    // Show debug panels
    IDEUnifiedLayout::ShowPanel("MoE Debugger");
    IDEUnifiedLayout::ShowPanel("MoE Spec Explorer");
    IDEUnifiedLayout::ShowPanel("MoE Diagnostics");
}

void IDEUnifiedLayout_ApplyMinimalLayout() {
    // Minimal layout - just output
    LayoutConfig config = {};
    config.leftPanelWidth = 0;
    config.rightPanelWidth = 0;
    config.topPanelHeight = 30;
    config.bottomPanelHeight = 150;
    config.showMenuBar = true;
    config.showStatusBar = true;
    
    IDEUnifiedLayout::SetLayout(&config);
    
    // Show only output
    IDEUnifiedLayout::ShowPanel("MoE Output");
}
