// ============================================================================
// Win32IDE ViewState Integration - Replaces duplicate member variables
// Enterprise-grade UI state management via x64 MASM
// ============================================================================
// This header provides the bridge between Win32IDE and the MASM ViewState
// implementation. It eliminates the dual-state problem by making Win32IDE
// use the shared MASM state exclusively.
// ============================================================================

#pragma once

#include "../core/view_state_masm.hpp"
#include <windows.h>

// ============================================================================
// Win32IDE ViewState Mixin
// ============================================================================
// Add this as a base class to Win32IDE to replace duplicate state members:
//   class Win32IDE : public Win32IDE_ViewStateMixin, ...
//
// Or use the macros below to selectively replace specific state groups.
// ============================================================================

class Win32IDE_ViewStateMixin {
protected:
    // Access to MASM ViewState
    [[nodiscard]] RawrXD::Core::ViewStateMasm& vs() noexcept {
        return RawrXD::Core::ViewStateMasm::instance();
    }
    
    [[nodiscard]] const RawrXD::Core::ViewStateMasm& vs() const noexcept {
        return RawrXD::Core::ViewStateMasm::instance();
    }
    
public:
    // =========================================================================
    // Panel Visibility (replaces m_*Visible members)
    // =========================================================================
    [[nodiscard]] bool isSidebarVisible() const noexcept { return vs().isSidebarVisible(); }
    [[nodiscard]] bool isOutputPanelVisible() const noexcept { return vs().isOutputPanelVisible(); }
    [[nodiscard]] bool isMinimapVisible() const noexcept { return vs().isMinimapEnabled(); }
    [[nodiscard]] bool isTerminalVisible() const noexcept { return vs().isTerminalVisible(); }
    [[nodiscard]] bool isModuleBrowserVisible() const noexcept { return vs().isModuleBrowserVisible(); }
    [[nodiscard]] bool isSecondarySidebarVisible() const noexcept { return vs().isSecondarySidebarVisible(); }
    [[nodiscard]] bool isPanelVisible() const noexcept { return vs().isPanelVisible(); }
    [[nodiscard]] bool isPowerShellPanelVisible() const noexcept { return vs().isPowerShellPanelVisible(); }
    [[nodiscard]] bool isFloatingPanelVisible() const noexcept { return vs().isFloatingPanelVisible(); }
    [[nodiscard]] bool isAnnotationsVisible() const noexcept { return vs().isAnnotationsVisible(); }
    
    void setSidebarVisible(bool v) noexcept { vs().setSidebarVisible(v); }
    void setOutputPanelVisible(bool v) noexcept { vs().setOutputPanelVisible(v); }
    void setMinimapVisible(bool v) noexcept { vs().setMinimapEnabled(v); }
    void setTerminalVisible(bool v) noexcept { vs().setTerminalVisible(v); }
    void setModuleBrowserVisible(bool v) noexcept { vs().setModuleBrowserVisible(v); }
    void setSecondarySidebarVisible(bool v) noexcept { vs().setSecondarySidebarVisible(v); }
    void setPanelVisible(bool v) noexcept { vs().setPanelVisible(v); }
    void setPowerShellPanelVisible(bool v) noexcept { vs().setPowerShellPanelVisible(v); }
    void setFloatingPanelVisible(bool v) noexcept { vs().setFloatingPanelVisible(v); }
    void setAnnotationsVisible(bool v) noexcept { vs().setAnnotationsVisible(v); }
    
    bool toggleSidebar() noexcept { return vs().toggleSidebar(); }
    bool toggleOutputPanel() noexcept { return vs().toggleOutputPanel(); }
    bool toggleMinimap() noexcept { return vs().toggleMinimap(); }
    bool toggleTerminal() noexcept { return vs().toggleTerminal(); }
    bool toggleModuleBrowser() noexcept { return vs().toggleModuleBrowser(); }
    bool toggleSecondarySidebar() noexcept { return vs().toggleSecondarySidebar(); }
    bool togglePanel() noexcept { return vs().togglePanel(); }
    bool togglePowerShellPanel() noexcept { return vs().togglePowerShellPanel(); }
    bool toggleFloatingPanel() noexcept { return vs().toggleFloatingPanel(); }
    bool toggleAnnotations() noexcept { return vs().toggleAnnotations(); }
    
    // =========================================================================
    // Renderer State (replaces m_useStreamingLoader, m_useVulkanRenderer)
    // =========================================================================
    [[nodiscard]] bool isStreamingLoaderActive() const noexcept { return vs().isStreamingLoaderActive(); }
    [[nodiscard]] bool isVulkanRendererActive() const noexcept { return vs().isVulkanRendererActive(); }
    [[nodiscard]] bool isGPUTextEnabled() const noexcept { return vs().isGPUTextEnabled(); }
    
    void setStreamingLoaderActive(bool v) noexcept { vs().setStreamingLoaderActive(v); }
    void setVulkanRendererActive(bool v) noexcept { vs().setVulkanRendererActive(v); }
    void setGPUTextEnabled(bool v) noexcept { vs().setGPUTextEnabled(v); }
    
    bool toggleStreamingLoader() noexcept { return vs().toggleStreamingLoader(); }
    bool toggleVulkanRenderer() noexcept { return vs().toggleVulkanRenderer(); }
    bool toggleGPUText() noexcept { return vs().toggleGPUText(); }
    
    // =========================================================================
    // Debugger State (replaces m_debugger* members)
    // =========================================================================
    [[nodiscard]] bool isDebuggerEnabled() const noexcept { return vs().isDebuggerEnabled(); }
    [[nodiscard]] bool isDebuggerAttached() const noexcept { return vs().isDebuggerAttached(); }
    [[nodiscard]] bool isDebuggerPaused() const noexcept { return vs().isDebuggerPaused(); }
    
    void setDebuggerEnabled(bool v) noexcept { vs().setDebuggerEnabled(v); }
    void setDebuggerAttached(bool v) noexcept { vs().setDebuggerAttached(v); }
    void setDebuggerPaused(bool v) noexcept { vs().setDebuggerPaused(v); }
    
    // =========================================================================
    // Monaco/Editor State (replaces m_monaco* members)
    // =========================================================================
    [[nodiscard]] bool isMonacoVisible() const noexcept { return vs().isMonacoVisible(); }
    [[nodiscard]] bool isMonacoDevtoolsOpen() const noexcept { return vs().isMonacoDevtoolsOpen(); }
    [[nodiscard]] int getMonacoZoomLevel() const noexcept { return vs().getMonacoZoomLevel(); }
    
    void setMonacoVisible(bool v) noexcept { vs().setMonacoVisible(v); }
    void setMonacoDevtoolsOpen(bool v) noexcept { vs().setMonacoDevtoolsOpen(v); }
    void setMonacoZoomLevel(int v) noexcept { vs().setMonacoZoomLevel(v); }
    
    bool toggleMonaco() noexcept { return vs().toggleMonaco(); }
    bool toggleMonacoDevtools() noexcept { return vs().toggleMonacoDevtools(); }
    
    // =========================================================================
    // Zoom Levels (replaces m_*ZoomLevel members)
    // =========================================================================
    [[nodiscard]] int getZoomLevel() const noexcept { return vs().getZoomLevel(); }
    
    void setZoomLevel(int v) noexcept { vs().setZoomLevel(v); }
    
    // =========================================================================
    // Dimensions (replaces m_*Width/Height members)
    // =========================================================================
    [[nodiscard]] int getSidebarWidth() const noexcept { return vs().getSidebarWidth(); }
    [[nodiscard]] int getPanelHeight() const noexcept { return vs().getPanelHeight(); }
    [[nodiscard]] int getSecondarySidebarWidth() const noexcept { return vs().getSecondarySidebarWidth(); }
    [[nodiscard]] int getMinimapWidth() const noexcept { return vs().getMinimapWidth(); }
    
    void setSidebarWidth(int v) noexcept { vs().setSidebarWidth(v); }
    void setPanelHeight(int v) noexcept { vs().setPanelHeight(v); }
    void setSecondarySidebarWidth(int v) noexcept { vs().setSecondarySidebarWidth(v); }
    void setMinimapWidth(int v) noexcept { vs().setMinimapWidth(v); }
    
    // =========================================================================
    // Theme (replaces m_currentTheme member)
    // =========================================================================
    [[nodiscard]] const char* getCurrentTheme() const noexcept { return vs().getCurrentTheme(); }
    void setCurrentTheme(const char* theme) noexcept { vs().setCurrentTheme(theme); }
    
    // =========================================================================
    // Session State (replaces m_sessionRestored member)
    // =========================================================================
    [[nodiscard]] bool isSessionRestored() const noexcept { return vs().isSessionRestored(); }
    void setSessionRestored(bool v) noexcept { vs().setSessionRestored(v); }
    
    // =========================================================================
    // Profiling State (replaces m_profilingActive member)
    // =========================================================================
    [[nodiscard]] bool isProfilingActive() const noexcept { return vs().isProfilingActive(); }
    void setProfilingActive(bool v) noexcept { vs().setProfilingActive(v); }
    bool toggleProfiling() noexcept { return vs().toggleProfiling(); }
    
    // =========================================================================
    // Chat Mode (replaces m_chatMode member)
    // =========================================================================
    [[nodiscard]] bool isChatModeActive() const noexcept { return vs().isChatModeActive(); }
    void setChatModeActive(bool v) noexcept { vs().setChatModeActive(v); }
    bool toggleChatMode() noexcept { return vs().toggleChatMode(); }
    
    // =========================================================================
    // Fullscreen (replaces m_fullscreen member)
    // =========================================================================
    [[nodiscard]] bool isFullscreen() const noexcept { return vs().isFullscreen(); }
    void setFullscreen(bool v) noexcept { vs().setFullscreen(v); }
    bool toggleFullscreen() noexcept { return vs().toggleFullscreen(); }
    
    // =========================================================================
    // Batch Operations
    // =========================================================================
    void resetViewStateToDefaults() noexcept { vs().resetToDefaults(); }
    
    [[nodiscard]] uint64_t getViewStateSequence() const noexcept { return vs().getSequence(); }
    uint64_t incrementViewStateSequence() noexcept { return vs().incrementSequence(); }
    
    // Snapshot for detecting changes
    [[nodiscard]] auto makeViewStateSnapshotGuard() noexcept { return vs().makeSnapshotGuard(); }
};

// ============================================================================
// Legacy Member Variable Replacements
// ============================================================================
// Use these macros to replace specific member variables in Win32IDE.h
//
// Example:
//   // OLD:
//   bool m_sidebarVisible;
//   bool m_outputPanelVisible;
//   
//   // NEW:
//   RAWRXD_VIEWSTATE_BOOL_GETTER(sidebarVisible)
//   RAWRXD_VIEWSTATE_BOOL_GETTER(outputPanelVisible)
// ============================================================================

#define RAWRXD_VIEWSTATE_BOOL_GETTER(name) \
    [[nodiscard]] bool is##name() const noexcept { \
        return RawrXD::Core::ViewStateMasm::instance().is##name(); \
    }

#define RAWRXD_VIEWSTATE_BOOL_SETTER(name) \
    void set##name(bool v) noexcept { \
        RawrXD::Core::ViewStateMasm::instance().set##name(v); \
    }

#define RAWRXD_VIEWSTATE_BOOL_TOGGLE(name) \
    bool toggle##name() noexcept { \
        return RawrXD::Core::ViewStateMasm::instance().toggle##name(); \
    }

#define RAWRXD_VIEWSTATE_BOOL_FULL(name) \
    RAWRXD_VIEWSTATE_BOOL_GETTER(name) \
    RAWRXD_VIEWSTATE_BOOL_SETTER(name) \
    RAWRXD_VIEWSTATE_BOOL_TOGGLE(name)

#define RAWRXD_VIEWSTATE_INT_GETTER(name) \
    [[nodiscard]] int get##name() const noexcept { \
        return RawrXD::Core::ViewStateMasm::instance().get##name(); \
    }

#define RAWRXD_VIEWSTATE_INT_SETTER(name) \
    void set##name(int v) noexcept { \
        RawrXD::Core::ViewStateMasm::instance().set##name(v); \
    }

#define RAWRXD_VIEWSTATE_INT_FULL(name) \
    RAWRXD_VIEWSTATE_INT_GETTER(name) \
    RAWRXD_VIEWSTATE_INT_SETTER(name)

// ============================================================================
// Migration Helper
// ============================================================================
// This function helps migrate from old member variables to ViewState
// Call once during Win32IDE construction to sync initial state
// ============================================================================
inline void InitializeViewStateFromLegacy(
    bool sidebarVisible = true,
    bool outputPanelVisible = true,
    bool minimapVisible = true,
    bool terminalVisible = false,
    bool moduleBrowserVisible = false,
    bool secondarySidebarVisible = false,
    bool panelVisible = true,
    bool powerShellPanelVisible = false,
    bool floatingPanelVisible = false,
    bool annotationsVisible = false,
    bool streamingLoaderActive = false,
    bool vulkanRendererActive = false,
    bool gpuTextEnabled = false,
    bool debuggerEnabled = false,
    bool monacoVisible = true,
    int zoomLevel = 100,
    int monacoZoomLevel = 100,
    int sidebarWidth = 250,
    int panelHeight = 200,
    int secondarySidebarWidth = 300,
    int minimapWidth = 150,
    const char* theme = "dark-rawrxd"
) {
    auto& vs = RawrXD::Core::ViewStateMasm::instance();
    
    vs.setSidebarVisible(sidebarVisible);
    vs.setOutputPanelVisible(outputPanelVisible);
    vs.setMinimapEnabled(minimapVisible);
    vs.setTerminalVisible(terminalVisible);
    vs.setModuleBrowserVisible(moduleBrowserVisible);
    vs.setSecondarySidebarVisible(secondarySidebarVisible);
    vs.setPanelVisible(panelVisible);
    vs.setPowerShellPanelVisible(powerShellPanelVisible);
    vs.setFloatingPanelVisible(floatingPanelVisible);
    vs.setAnnotationsVisible(annotationsVisible);
    vs.setStreamingLoaderActive(streamingLoaderActive);
    vs.setVulkanRendererActive(vulkanRendererActive);
    vs.setGPUTextEnabled(gpuTextEnabled);
    vs.setDebuggerEnabled(debuggerEnabled);
    vs.setMonacoVisible(monacoVisible);
    vs.setZoomLevel(zoomLevel);
    vs.setMonacoZoomLevel(monacoZoomLevel);
    vs.setSidebarWidth(sidebarWidth);
    vs.setPanelHeight(panelHeight);
    vs.setSecondarySidebarWidth(secondarySidebarWidth);
    vs.setMinimapWidth(minimapWidth);
    vs.setCurrentTheme(theme);
}

// ============================================================================
// Event Notification System
// ============================================================================
// When ViewState changes, Win32IDE needs to update the actual UI.
// This callback system allows registering for specific state changes.
// ============================================================================

enum class ViewStateChangeType {
    Sidebar,
    OutputPanel,
    Minimap,
    Terminal,
    ModuleBrowser,
    SecondarySidebar,
    Panel,
    PowerShellPanel,
    FloatingPanel,
    Annotations,
    StreamingLoader,
    VulkanRenderer,
    GPUText,
    Debugger,
    Monaco,
    Zoom,
    Theme,
    Fullscreen,
    Generic
};

using ViewStateChangeCallback = void (*)(ViewStateChangeType type, void* userData);

class ViewStateChangeNotifier {
public:
    static ViewStateChangeNotifier& instance() {
        static ViewStateChangeNotifier s_instance;
        return s_instance;
    }
    
    void registerCallback(ViewStateChangeType type, ViewStateChangeCallback cb, void* userData) {
        m_callbacks[static_cast<int>(type)].push_back({cb, userData});
    }
    
    void notify(ViewStateChangeType type) {
        for (auto& [cb, userData] : m_callbacks[static_cast<int>(type)]) {
            cb(type, userData);
        }
    }
    
private:
    struct CallbackEntry {
        ViewStateChangeCallback callback;
        void* userData;
    };
    
    std::vector<CallbackEntry> m_callbacks[20];  // One per change type
};

// Helper macro to notify on state change
#define RAWRXD_VIEWSTATE_NOTIFY(type) \
    ViewStateChangeNotifier::instance().notify(ViewStateChangeType::type)
