// ============================================================================
// PanelManager.cpp — Native Panel Manager Implementation
// ============================================================================

#include "PanelManager.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <algorithm>

namespace rawr {

PanelManager& PanelManager::Get() {
    static PanelManager instance;
    return instance;
}

bool PanelManager::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "PanelManager initialized");
    return true;
}

void PanelManager::Shutdown() {
    for (uint32_t i = 0; i < m_panelCount; ++i) {
        if (m_panels[i].active) {
            DeactivatePanel(i);
        }
    }
    m_panelCount = 0;
    RawrRuntime::Get().Log(LogLevel::Info, "PanelManager shutdown");
}

uint32_t PanelManager::RegisterPanel(const char* id, const char* title, uint32_t iconId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_panelCount >= kMaxPanels) return UINT32_MAX;

    uint32_t idx = m_panelCount++;
    m_panels[idx].id = id ? id : "";
    m_panels[idx].title = title ? title : "";
    m_panels[idx].iconId = iconId;
    m_panels[idx].flags = 0;
    m_panels[idx].active = false;
    m_panels[idx].visible = false;
    m_panels[idx].hwnd = nullptr;

    return idx;
}

bool PanelManager::UnregisterPanel(uint32_t panelIndex) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (panelIndex >= m_panelCount) return false;

    if (m_panels[panelIndex].active) {
        // Deactivate first
    }

    // Shift remaining panels
    for (uint32_t i = panelIndex; i < m_panelCount - 1; ++i) {
        m_panels[i] = m_panels[i + 1];
    }
    m_panelCount--;
    return true;
}

bool PanelManager::ActivatePanel(uint32_t panelIndex) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (panelIndex >= m_panelCount) return false;

    m_panels[panelIndex].active = true;
    m_panels[panelIndex].visible = true;
    return true;
}

bool PanelManager::DeactivatePanel(uint32_t panelIndex) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (panelIndex >= m_panelCount) return false;

    m_panels[panelIndex].active = false;
    m_panels[panelIndex].visible = false;
    return true;
}

bool PanelManager::ShowPanel(uint32_t panelIndex, bool show) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (panelIndex >= m_panelCount) return false;
    m_panels[panelIndex].visible = show;
    return true;
}

PanelInfo* PanelManager::GetPanel(uint32_t panelIndex) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (panelIndex >= m_panelCount) return nullptr;
    return &m_panels[panelIndex];
}

PanelInfo* PanelManager::FindPanel(const char* id) {
    if (!id) return nullptr;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (uint32_t i = 0; i < m_panelCount; ++i) {
        if (m_panels[i].id == id) return &m_panels[i];
    }
    return nullptr;
}

uint32_t PanelManager::GetActiveCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(std::count_if(m_panels, m_panels + m_panelCount,
        [](const PanelInfo& p) { return p.active; }));
}

std::vector<PanelInfo> PanelManager::ListPanels() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PanelInfo> result;
    for (uint32_t i = 0; i < m_panelCount; ++i) {
        result.push_back(m_panels[i]);
    }
    return result;
}

} // namespace rawr
