// SovereignControlPlane.hpp
// Coordination Primitive #10: Sovereign Control Plane UI
// Central dashboard for system visibility and control

#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace Sovereign {

// Control plane view types
enum class ControlView {
    OVERVIEW,       // System health summary
    AGENTS,         // Agent management
    TERMINALS,      // Terminal sessions
    BUILDS,         // Build status
    LOGS,           // System logs
    SETTINGS        // Configuration
};

// Control action
struct ControlAction {
    std::string id;
    std::string label;
    std::string icon;
    std::function<void()> handler;
    bool enabled;
};

// Control plane panel
struct ControlPanel {
    std::string title;
    ControlView view;
    std::vector<ControlAction> actions;
    std::function<void()> render_content;
};

// Sovereign control plane
class SovereignControlPlane {
public:
    static SovereignControlPlane& Instance();
    
    // Panel management
    void RegisterPanel(const ControlPanel& panel);
    void ShowPanel(ControlView view);
    void HidePanel(ControlView view);
    
    // Actions
    void ExecuteAction(const std::string& action_id);
    std::vector<ControlAction> GetAvailableActions() const;
    
    // Rendering
    void Render();
    void RenderPanel(ControlView view);
    
    // State
    ControlView GetCurrentView() const { return current_view_; }

private:
    SovereignControlPlane() = default;
    ControlView current_view_ = ControlView::OVERVIEW;
    std::map<ControlView, ControlPanel> panels_;
};

} // namespace Sovereign
