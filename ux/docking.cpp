// docking.cpp — Docking & Layout Implementation
#include "docking.hpp"
#include <algorithm>
#include <fstream>

namespace RawrXD {
namespace UX {

// ============================================================================
// PanelInstance
// ============================================================================
PanelInstance::PanelInstance(const PanelDefinition& def)
    : m_definition(def)
    , m_position(def.defaultPosition)
    , m_width(def.defaultWidth)
    , m_height(def.defaultHeight)
{
}

PanelInstance::~PanelInstance() = default;

void PanelInstance::Render(void* hdc, int x, int y, int w, int h) {
    if (m_renderCallback) {
        m_renderCallback(hdc, x, y, w, h);
    }
}

// ============================================================================
// DockingManager
// ============================================================================
DockingManager& DockingManager::Get() {
    static DockingManager instance;
    return instance;
}

void DockingManager::RegisterPanel(const PanelDefinition& def) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_panelDefinitions[def.id] = def;
}

PanelInstance* DockingManager::OpenPanel(const std::string& panelId) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check if already open
    auto existing = m_openPanels.find(panelId);
    if (existing != m_openPanels.end()) {
        existing->second->SetVisible(true);
        return existing->second.get();
    }

    // Find definition
    auto defIt = m_panelDefinitions.find(panelId);
    if (defIt == m_panelDefinitions.end()) return nullptr;

    auto panel = std::make_unique<PanelInstance>(defIt->second);
    auto* ptr = panel.get();
    m_openPanels[panelId] = std::move(panel);

    if (m_onOpened) m_onOpened(panelId);
    if (m_onLayoutChanged) m_onLayoutChanged();

    return ptr;
}

void DockingManager::ClosePanel(const std::string& panelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_openPanels.find(panelId);
    if (it == m_openPanels.end()) return;

    if (!it->second->GetDefinition().closable) return;

    m_openPanels.erase(it);
    if (m_onClosed) m_onClosed(panelId);
    if (m_onLayoutChanged) m_onLayoutChanged();
}

PanelInstance* DockingManager::GetPanel(const std::string& panelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_openPanels.find(panelId);
    return it != m_openPanels.end() ? it->second.get() : nullptr;
}

std::vector<PanelInstance*> DockingManager::GetOpenPanels() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PanelInstance*> result;
    for (const auto& [id, panel] : m_openPanels) {
        result.push_back(panel.get());
    }
    return result;
}

std::vector<PanelInstance*> DockingManager::GetPanelsAt(DockPosition position) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PanelInstance*> result;
    for (const auto& [id, panel] : m_openPanels) {
        if (panel->GetPosition() == position) {
            result.push_back(panel.get());
        }
    }
    return result;
}

void DockingManager::TogglePanel(const std::string& panelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_openPanels.find(panelId);
    if (it == m_openPanels.end()) return;
    it->second->SetVisible(!it->second->IsVisible());
    if (m_onLayoutChanged) m_onLayoutChanged();
}

void DockingManager::FocusPanel(const std::string& panelId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, panel] : m_openPanels) {
        panel->SetFocused(id == panelId);
    }
    if (m_onFocused) m_onFocused(panelId);
}

void DockingManager::MovePanel(const std::string& panelId, DockPosition newPosition) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_openPanels.find(panelId);
    if (it == m_openPanels.end()) return;
    it->second->SetPosition(newPosition);
    if (m_onLayoutChanged) m_onLayoutChanged();
}

bool DockingManager::SaveLayout(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    LayoutPreset preset;
    preset.name = name;

    for (const auto& [id, panel] : m_openPanels) {
        preset.panelPositions[id] = panel->GetPosition();
        preset.panelVisibility[id] = panel->IsVisible();
        preset.panelSizes[id] = panel->GetWidth();
    }

    m_layouts[name] = preset;
    m_activeLayout = name;
    return true;
}

bool DockingManager::LoadLayout(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_layouts.find(name);
    if (it == m_layouts.end()) return false;

    const auto& preset = it->second;

    for (auto& [id, panel] : m_openPanels) {
        auto posIt = preset.panelPositions.find(id);
        if (posIt != preset.panelPositions.end()) panel->SetPosition(posIt->second);

        auto visIt = preset.panelVisibility.find(id);
        if (visIt != preset.panelVisibility.end()) panel->SetVisible(visIt->second);

        auto sizeIt = preset.panelSizes.find(id);
        if (sizeIt != preset.panelSizes.end()) {
            panel->SetBounds(0, 0, sizeIt->second, panel->GetHeight());
        }
    }

    m_activeLayout = name;
    if (m_onLayoutChanged) m_onLayoutChanged();
    return true;
}

std::vector<std::string> DockingManager::ListLayouts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    for (const auto& [name, _] : m_layouts) {
        names.push_back(name);
    }
    return names;
}

void DockingManager::ResetLayout() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, panel] : m_openPanels) {
        panel->SetPosition(panel->GetDefinition().defaultPosition);
        panel->SetBounds(0, 0, panel->GetDefinition().defaultWidth, panel->GetDefinition().defaultHeight);
    }
    if (m_onLayoutChanged) m_onLayoutChanged();
}

void DockingManager::SplitPanel(const std::string& panelId, DockPosition direction) {
    // TODO: Implement panel splitting
}

void DockingManager::MergePanels(const std::string& targetId, const std::string& sourceId) {
    // TODO: Implement panel merging
}

} // namespace UX
} // namespace RawrXD
