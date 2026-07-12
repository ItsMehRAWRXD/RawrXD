#include "ide/DockingLayout.hpp"
#include <fstream>
#include <algorithm>

namespace Sovereign {
namespace IDE {

DockingLayout& DockingLayout::Instance() {
    static DockingLayout instance;
    return instance;
}

void DockingLayout::Initialize(HWND mainWindow) {
    m_mainWindow = mainWindow;
    
    // Initialize built-in presets
    ApplyDevelopmentLayout();
}

void DockingLayout::Shutdown() {
    if (m_autoSave) {
        SaveLayout(L"last_layout.ini");
    }
}

void DockingLayout::AddPanel(const std::string& name, HWND hwnd, DockPosition pos, int size) {
    PanelInfo info;
    info.name = name;
    info.hwnd = hwnd;
    info.position = pos;
    info.visible = true;
    info.collapsed = false;
    
    if (pos == DockPosition::Left || pos == DockPosition::Right) {
        info.width = size;
        info.height = 0;
    } else {
        info.width = 0;
        info.height = size;
    }
    
    m_panels[name] = info;
    ArrangePanels();
}

void DockingLayout::RemovePanel(const std::string& name) {
    auto it = m_panels.find(name);
    if (it != m_panels.end()) {
        m_panels.erase(it);
        ArrangePanels();
    }
}

void DockingLayout::ShowPanel(const std::string& name) {
    auto it = m_panels.find(name);
    if (it != m_panels.end()) {
        it->second.visible = true;
        ShowWindow(it->second.hwnd, SW_SHOW);
        ArrangePanels();
    }
}

void DockingLayout::HidePanel(const std::string& name) {
    auto it = m_panels.find(name);
    if (it != m_panels.end()) {
        it->second.visible = false;
        ShowWindow(it->second.hwnd, SW_HIDE);
        ArrangePanels();
    }
}

void DockingLayout::TogglePanel(const std::string& name) {
    auto it = m_panels.find(name);
    if (it != m_panels.end()) {
        if (it->second.visible) {
            HidePanel(name);
        } else {
            ShowPanel(name);
        }
    }
}

void DockingLayout::SavePreset(const std::string& name) {
    LayoutPreset preset;
    preset.name = name;
    
    for (const auto& pair : m_panels) {
        preset.panels.push_back(pair.second);
    }
    
    m_presets[name] = preset;
}

void DockingLayout::LoadPreset(const std::string& name) {
    auto it = m_presets.find(name);
    if (it == m_presets.end()) return;
    
    // Hide all current panels
    for (auto& pair : m_panels) {
        ShowWindow(pair.second.hwnd, SW_HIDE);
    }
    
    // Apply preset
    for (const auto& panel : it->second.panels) {
        auto panelIt = m_panels.find(panel.name);
        if (panelIt != m_panels.end()) {
            panelIt->second.position = panel.position;
            panelIt->second.width = panel.width;
            panelIt->second.height = panel.height;
            panelIt->second.visible = panel.visible;
            panelIt->second.collapsed = panel.collapsed;
            
            if (panel.visible) {
                ShowWindow(panelIt->second.hwnd, SW_SHOW);
            }
        }
    }
    
    ArrangePanels();
}

void DockingLayout::DeletePreset(const std::string& name) {
    m_presets.erase(name);
}

std::vector<std::string> DockingLayout::GetPresetNames() const {
    std::vector<std::string> names;
    for (const auto& pair : m_presets) {
        names.push_back(pair.first);
    }
    return names;
}

void DockingLayout::ApplyDevelopmentLayout() {
    // Left: Model Browser (300px)
    // Right: Health Panel (350px)
    // Bottom: Profiler (200px)
    // Center: Code Editor
    
    // This is a simplified layout - actual implementation would use splitter windows
    ArrangePanels();
}

void DockingLayout::ApplyDebuggingLayout() {
    // Left: Replay Debugger (400px)
    // Right: Health Panel (350px)
    // Bottom: Scheduler (150px)
    // Center: Code Editor
    
    ArrangePanels();
}

void DockingLayout::ApplyProfilingLayout() {
    // Left: Profiler (300px)
    // Right: GPU Pipeline Graph (400px)
    // Bottom: KV Heatmap (150px)
    // Center: Code Editor
    
    ArrangePanels();
}

void DockingLayout::ApplyMinimalLayout() {
    // Hide all panels except code editor
    for (auto& pair : m_panels) {
        if (pair.first != "CodeEditor") {
            ShowWindow(pair.second.hwnd, SW_HIDE);
            pair.second.visible = false;
        }
    }
    
    ArrangePanels();
}

void DockingLayout::SaveLayout(const std::wstring& path) {
    std::ofstream file(path, std::ios::out);
    if (!file.is_open()) return;
    
    file << "# Sovereign IDE Layout\n";
    for (const auto& pair : m_panels) {
        const auto& panel = pair.second;
        file << "[" << panel.name << "]\n";
        file << "Position=" << static_cast<int>(panel.position) << "\n";
        file << "Width=" << panel.width << "\n";
        file << "Height=" << panel.height << "\n";
        file << "Visible=" << (panel.visible ? 1 : 0) << "\n";
        file << "Collapsed=" << (panel.collapsed ? 1 : 0) << "\n";
        file << "\n";
    }
    
    file.close();
}

void DockingLayout::LoadLayout(const std::wstring& path) {
    // Implementation would parse the layout file
    // and apply settings to panels
}

void DockingLayout::ResetLayout() {
    ApplyDevelopmentLayout();
}

void DockingLayout::EnableAutoSave(bool enable) {
    m_autoSave = enable;
}

void DockingLayout::RestoreLastLayout() {
    LoadLayout(L"last_layout.ini");
}

void DockingLayout::ArrangePanels() {
    if (!m_mainWindow) return;
    
    RECT clientRect;
    GetClientRect(m_mainWindow, &clientRect);
    
    std::vector<RECT> panelRects;
    CalculateLayout(panelRects);
    
    // Apply calculated positions to panels
    // This is a simplified implementation
}

void DockingLayout::CalculateLayout(std::vector<RECT>& panelRects) {
    // Calculate positions for all visible panels
    // based on their docking positions and sizes
    
    // This would implement a full docking layout algorithm
    // For now, it's a placeholder
}

} // namespace IDE
} // namespace Sovereign
