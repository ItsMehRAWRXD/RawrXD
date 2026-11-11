// ============================================================================
// RawrXD View State - Shared UI State Management
// Centralized view configuration shared across all IDE components
// ============================================================================

#pragma once

#include <string>

namespace RawrXD {
namespace Core {

// ============================================================================
// View State Structure - Single source of truth for IDE UI state
// Uses plain values for C compatibility with snprintf/printf
// ============================================================================
struct ViewState {
    // Panel visibility
    bool floatingPanelVisible = false;
    bool minimapEnabled = true;
    bool moduleBrowserVisible = false;
    bool monacoDevtoolsOpen = false;
    bool monacoVisible = true;
    bool outputPanelVisible = true;
    bool sidebarVisible = true;
    bool terminalVisible = false;
    bool fullscreen = false;
    
    // Zoom levels
    int zoomLevel = 100;        // percentage
    int monacoZoomLevel = 100;
    
    // Renderer state
    bool streamingLoaderActive = false;
    bool vulkanRendererActive = false;
    
    // Theme
    const char* currentTheme = "dark-rawrxd";
    
    // ============================================================================
    // Singleton Access
    // ============================================================================
    static ViewState& instance() {
        static ViewState s_instance;
        return s_instance;
    }
    
    // Prevent copy/move
    ViewState(const ViewState&) = delete;
    ViewState& operator=(const ViewState&) = delete;
    ViewState(ViewState&&) = delete;
    ViewState& operator=(ViewState&&) = delete;
    
private:
    ViewState() = default;
};

// Global accessor for C-style code
inline ViewState& GetViewState() {
    return ViewState::instance();
}

} // namespace Core
} // namespace RawrXD

// Legacy global for backward compatibility with existing handlers
// TODO: Migrate all handlers to use RawrXD::Core::GetViewState()
inline RawrXD::Core::ViewState& g_viewState = RawrXD::Core::ViewState::instance();
