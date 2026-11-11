// ============================================================================
// PanelManager.hpp — Native Panel Manager
// Load, unload, activate, register panels
// ============================================================================

#ifndef PANEL_MANAGER_HPP
#define PANEL_MANAGER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Panel State
// ============================================================================
struct PanelInfo {
    std::string id;
    std::string title;
    uint32_t iconId;
    uint32_t flags;
    bool active;
    bool visible;
    void* hwnd;  // Panel window handle
};

// ============================================================================
// PanelManager — Manages panel lifecycle
// ============================================================================
class PanelManager {
public:
    static PanelManager& Get();

    bool Initialize();
    void Shutdown();

    // Registration
    uint32_t RegisterPanel(const char* id, const char* title, uint32_t iconId);
    bool UnregisterPanel(uint32_t panelIndex);

    // Lifecycle
    bool ActivatePanel(uint32_t panelIndex);
    bool DeactivatePanel(uint32_t panelIndex);
    bool ShowPanel(uint32_t panelIndex, bool show);

    // Query
    PanelInfo* GetPanel(uint32_t panelIndex);
    PanelInfo* FindPanel(const char* id);
    uint32_t GetPanelCount() const { return m_panelCount; }
    uint32_t GetActiveCount() const;

    // Iteration
    std::vector<PanelInfo> ListPanels() const;

private:
    PanelManager() = default;
    ~PanelManager() = default;
    PanelManager(const PanelManager&) = delete;
    PanelManager& operator=(const PanelManager&) = delete;

    static const uint32_t kMaxPanels = 32;

    PanelInfo m_panels[kMaxPanels];
    uint32_t m_panelCount = 0;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // PANEL_MANAGER_HPP
