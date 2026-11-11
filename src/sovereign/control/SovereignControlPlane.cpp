// SovereignControlPlane.cpp
// Implementation of the Sovereign Control Plane

#include "SovereignControlPlane.hpp"

namespace Sovereign {

SovereignControlPlane& SovereignControlPlane::Instance() {
    static SovereignControlPlane instance;
    return instance;
}

void SovereignControlPlane::RegisterPanel(const ControlPanel& panel) {
    panels_[panel.view] = panel;
}

void SovereignControlPlane::ShowPanel(ControlView view) {
    current_view_ = view;
}

void SovereignControlPlane::HidePanel(ControlView view) {
    (void)view;
}

void SovereignControlPlane::ExecuteAction(const std::string& action_id) {
    auto it = panels_.find(current_view_);
    if (it != panels_.end()) {
        for (const auto& action : it->second.actions) {
            if (action.id == action_id && action.handler) {
                action.handler();
                break;
            }
        }
    }
}

std::vector<ControlAction> SovereignControlPlane::GetAvailableActions() const {
    auto it = panels_.find(current_view_);
    if (it != panels_.end()) {
        return it->second.actions;
    }
    return {};
}

void SovereignControlPlane::Render() {
    RenderPanel(current_view_);
}

void SovereignControlPlane::RenderPanel(ControlView view) {
    auto it = panels_.find(view);
    if (it != panels_.end() && it->second.render_content) {
        it->second.render_content();
    }
}

} // namespace Sovereign
