// ============================================================================
// RawrXD ViewState MASM Bridge - C++ Interface to x64 Assembly Implementation
// Zero-overhead, lock-free, enterprise-grade UI state management
// ============================================================================
// This header provides the C++ interface to the pure x64 MASM ViewState
// implementation. All operations are atomic and cache-line optimized.
// ============================================================================

#pragma once

#include <cstdint>
#include <atomic>

// ============================================================================
// C Linkage - MASM exports
// ============================================================================
extern "C" {
    // Core singleton access
    void* ViewState_GetInstance();
    
    // Boolean flag operations (atomic)
    int   ViewState_GetBool(int flag);
    int   ViewState_SetBool(int flag, int value);
    int   ViewState_ToggleBool(int flag);
    
    // 32-bit integer operations (atomic)
    int   ViewState_GetInt32(int offset);
    int   ViewState_SetInt32(int offset, int value);
    
    // String pointer operations (atomic)
    const char* ViewState_GetString(int offset);
    const char* ViewState_SetString(int offset, const char* value);
    
    // Sequence number for optimistic locking
    unsigned long long ViewState_GetSequence();
    unsigned long long ViewState_IncrementSequence();
    
    // Bulk operations
    void  ViewState_ResetToDefaults();
    void  ViewState_Snapshot(void* dest);
    int   ViewState_CompareSnapshot(const void* snapshot);
    
    // Data exports
    extern unsigned char g_ViewState[];
    extern const char g_DefaultTheme[];
}

namespace RawrXD {
namespace Core {

// ============================================================================
// Flag Indices - Must match MASM implementation
// ============================================================================
enum class ViewStateFlag : int {
    FloatingPanel       = 0,
    Minimap             = 1,
    ModuleBrowser       = 2,
    MonacoDevtools      = 3,
    MonacoVisible       = 4,
    OutputPanel         = 5,
    Sidebar             = 6,
    Terminal            = 7,
    Fullscreen          = 8,
    StreamingLoader     = 9,
    VulkanRenderer      = 10,
    SecondarySidebar    = 11,
    Panel               = 12,
    PowerShellPanel     = 13,
    GPUText             = 14,
    DebuggerEnabled     = 15,
    DebuggerAttached    = 16,
    DebuggerPaused      = 17,
    Annotations         = 18,
    Profiling           = 19,
    ChatMode            = 20,
    SessionRestored     = 21,
    
    // Aliases for backward compatibility
    MinimapEnabled      = Minimap,
    SidebarVisible      = Sidebar,
    OutputPanelVisible  = OutputPanel,
    TerminalVisible     = Terminal,
    ModuleBrowserVisible = ModuleBrowser,
    MonacoDevtoolsOpen  = MonacoDevtools,
    StreamingLoaderActive = StreamingLoader,
    VulkanRendererActive = VulkanRenderer,
    SecondarySidebarVisible = SecondarySidebar,
    PanelVisible        = Panel,
    PowerShellPanelVisible = PowerShellPanel,
    GPUTextEnabled      = GPUText,
    AnnotationsVisible  = Annotations,
    ProfilingActive     = Profiling,
    ChatModeActive      = ChatMode,
    SessionRestoredFlag = SessionRestored
};

// ============================================================================
// Field Offsets - Must match MASM memory layout
// ============================================================================
enum class ViewStateOffset : int {
    // Boolean flags (bytes 0-23)
    FlagsStart          = 0,
    
    // 32-bit integers (bytes 24-39)
    ZoomLevel           = 24,
    MonacoZoomLevel     = 28,
    SidebarWidth        = 32,
    PanelHeight         = 36,
    SecondarySidebarWidth = 40,
    MinimapWidth        = 44,
    
    // String pointer (bytes 48-55)
    CurrentTheme        = 48,
    
    // Sequence number (bytes 56-63)
    ModificationSequence = 56
};

// ============================================================================
// ViewStateMasm - Zero-overhead C++ wrapper
// ============================================================================
class ViewStateMasm {
public:
    // Singleton access
    static ViewStateMasm& instance() noexcept {
        static ViewStateMasm s_instance;
        return s_instance;
    }
    
    // Get raw pointer to MASM state
    [[nodiscard]] static void* getRawPtr() noexcept {
        return ViewState_GetInstance();
    }
    
    // =========================================================================
    // Boolean Operations
    // =========================================================================
    [[nodiscard]] bool getBool(ViewStateFlag flag) const noexcept {
        return ViewState_GetBool(static_cast<int>(flag)) != 0;
    }
    
    bool setBool(ViewStateFlag flag, bool value) noexcept {
        return ViewState_SetBool(static_cast<int>(flag), value ? 1 : 0) != 0;
    }
    
    bool toggleBool(ViewStateFlag flag) noexcept {
        return ViewState_ToggleBool(static_cast<int>(flag)) != 0;
    }
    
    // Convenience getters
    [[nodiscard]] bool isFloatingPanelVisible() const noexcept { return getBool(ViewStateFlag::FloatingPanel); }
    [[nodiscard]] bool isMinimapEnabled() const noexcept { return getBool(ViewStateFlag::Minimap); }
    [[nodiscard]] bool isModuleBrowserVisible() const noexcept { return getBool(ViewStateFlag::ModuleBrowser); }
    [[nodiscard]] bool isMonacoDevtoolsOpen() const noexcept { return getBool(ViewStateFlag::MonacoDevtools); }
    [[nodiscard]] bool isMonacoVisible() const noexcept { return getBool(ViewStateFlag::MonacoVisible); }
    [[nodiscard]] bool isOutputPanelVisible() const noexcept { return getBool(ViewStateFlag::OutputPanel); }
    [[nodiscard]] bool isSidebarVisible() const noexcept { return getBool(ViewStateFlag::Sidebar); }
    [[nodiscard]] bool isTerminalVisible() const noexcept { return getBool(ViewStateFlag::Terminal); }
    [[nodiscard]] bool isFullscreen() const noexcept { return getBool(ViewStateFlag::Fullscreen); }
    [[nodiscard]] bool isStreamingLoaderActive() const noexcept { return getBool(ViewStateFlag::StreamingLoader); }
    [[nodiscard]] bool isVulkanRendererActive() const noexcept { return getBool(ViewStateFlag::VulkanRenderer); }
    [[nodiscard]] bool isSecondarySidebarVisible() const noexcept { return getBool(ViewStateFlag::SecondarySidebar); }
    [[nodiscard]] bool isPanelVisible() const noexcept { return getBool(ViewStateFlag::Panel); }
    [[nodiscard]] bool isPowerShellPanelVisible() const noexcept { return getBool(ViewStateFlag::PowerShellPanel); }
    [[nodiscard]] bool isGPUTextEnabled() const noexcept { return getBool(ViewStateFlag::GPUText); }
    [[nodiscard]] bool isDebuggerEnabled() const noexcept { return getBool(ViewStateFlag::DebuggerEnabled); }
    [[nodiscard]] bool isDebuggerAttached() const noexcept { return getBool(ViewStateFlag::DebuggerAttached); }
    [[nodiscard]] bool isDebuggerPaused() const noexcept { return getBool(ViewStateFlag::DebuggerPaused); }
    [[nodiscard]] bool isAnnotationsVisible() const noexcept { return getBool(ViewStateFlag::Annotations); }
    [[nodiscard]] bool isProfilingActive() const noexcept { return getBool(ViewStateFlag::Profiling); }
    [[nodiscard]] bool isChatModeActive() const noexcept { return getBool(ViewStateFlag::ChatMode); }
    [[nodiscard]] bool isSessionRestored() const noexcept { return getBool(ViewStateFlag::SessionRestored); }
    
    // Convenience setters
    void setFloatingPanelVisible(bool v) noexcept { setBool(ViewStateFlag::FloatingPanel, v); }
    void setMinimapEnabled(bool v) noexcept { setBool(ViewStateFlag::Minimap, v); }
    void setModuleBrowserVisible(bool v) noexcept { setBool(ViewStateFlag::ModuleBrowser, v); }
    void setMonacoDevtoolsOpen(bool v) noexcept { setBool(ViewStateFlag::MonacoDevtools, v); }
    void setMonacoVisible(bool v) noexcept { setBool(ViewStateFlag::MonacoVisible, v); }
    void setOutputPanelVisible(bool v) noexcept { setBool(ViewStateFlag::OutputPanel, v); }
    void setSidebarVisible(bool v) noexcept { setBool(ViewStateFlag::Sidebar, v); }
    void setTerminalVisible(bool v) noexcept { setBool(ViewStateFlag::Terminal, v); }
    void setFullscreen(bool v) noexcept { setBool(ViewStateFlag::Fullscreen, v); }
    void setStreamingLoaderActive(bool v) noexcept { setBool(ViewStateFlag::StreamingLoader, v); }
    void setVulkanRendererActive(bool v) noexcept { setBool(ViewStateFlag::VulkanRenderer, v); }
    void setSecondarySidebarVisible(bool v) noexcept { setBool(ViewStateFlag::SecondarySidebar, v); }
    void setPanelVisible(bool v) noexcept { setBool(ViewStateFlag::Panel, v); }
    void setPowerShellPanelVisible(bool v) noexcept { setBool(ViewStateFlag::PowerShellPanel, v); }
    void setGPUTextEnabled(bool v) noexcept { setBool(ViewStateFlag::GPUText, v); }
    void setDebuggerEnabled(bool v) noexcept { setBool(ViewStateFlag::DebuggerEnabled, v); }
    void setDebuggerAttached(bool v) noexcept { setBool(ViewStateFlag::DebuggerAttached, v); }
    void setDebuggerPaused(bool v) noexcept { setBool(ViewStateFlag::DebuggerPaused, v); }
    void setAnnotationsVisible(bool v) noexcept { setBool(ViewStateFlag::Annotations, v); }
    void setProfilingActive(bool v) noexcept { setBool(ViewStateFlag::Profiling, v); }
    void setChatModeActive(bool v) noexcept { setBool(ViewStateFlag::ChatMode, v); }
    void setSessionRestored(bool v) noexcept { setBool(ViewStateFlag::SessionRestored, v); }
    
    // Toggle helpers
    bool toggleFloatingPanel() noexcept { return toggleBool(ViewStateFlag::FloatingPanel); }
    bool toggleMinimap() noexcept { return toggleBool(ViewStateFlag::Minimap); }
    bool toggleModuleBrowser() noexcept { return toggleBool(ViewStateFlag::ModuleBrowser); }
    bool toggleMonacoDevtools() noexcept { return toggleBool(ViewStateFlag::MonacoDevtools); }
    bool toggleMonaco() noexcept { return toggleBool(ViewStateFlag::MonacoVisible); }
    bool toggleOutputPanel() noexcept { return toggleBool(ViewStateFlag::OutputPanel); }
    bool toggleSidebar() noexcept { return toggleBool(ViewStateFlag::Sidebar); }
    bool toggleTerminal() noexcept { return toggleBool(ViewStateFlag::Terminal); }
    bool toggleFullscreen() noexcept { return toggleBool(ViewStateFlag::Fullscreen); }
    bool toggleStreamingLoader() noexcept { return toggleBool(ViewStateFlag::StreamingLoader); }
    bool toggleVulkanRenderer() noexcept { return toggleBool(ViewStateFlag::VulkanRenderer); }
    bool toggleSecondarySidebar() noexcept { return toggleBool(ViewStateFlag::SecondarySidebar); }
    bool togglePanel() noexcept { return toggleBool(ViewStateFlag::Panel); }
    bool togglePowerShellPanel() noexcept { return toggleBool(ViewStateFlag::PowerShellPanel); }
    bool toggleGPUText() noexcept { return toggleBool(ViewStateFlag::GPUText); }
    bool toggleAnnotations() noexcept { return toggleBool(ViewStateFlag::Annotations); }
    bool toggleProfiling() noexcept { return toggleBool(ViewStateFlag::Profiling); }
    bool toggleChatMode() noexcept { return toggleBool(ViewStateFlag::ChatMode); }
    
    // =========================================================================
    // Integer Operations
    // =========================================================================
    [[nodiscard]] int getInt32(ViewStateOffset offset) const noexcept {
        return ViewState_GetInt32(static_cast<int>(offset));
    }
    
    int setInt32(ViewStateOffset offset, int value) noexcept {
        return ViewState_SetInt32(static_cast<int>(offset), value);
    }
    
    // Zoom level
    [[nodiscard]] int getZoomLevel() const noexcept { return getInt32(ViewStateOffset::ZoomLevel); }
    [[nodiscard]] int getMonacoZoomLevel() const noexcept { return getInt32(ViewStateOffset::MonacoZoomLevel); }
    [[nodiscard]] int getSidebarWidth() const noexcept { return getInt32(ViewStateOffset::SidebarWidth); }
    [[nodiscard]] int getPanelHeight() const noexcept { return getInt32(ViewStateOffset::PanelHeight); }
    [[nodiscard]] int getSecondarySidebarWidth() const noexcept { return getInt32(ViewStateOffset::SecondarySidebarWidth); }
    [[nodiscard]] int getMinimapWidth() const noexcept { return getInt32(ViewStateOffset::MinimapWidth); }
    
    void setZoomLevel(int v) noexcept { setInt32(ViewStateOffset::ZoomLevel, v); }
    void setMonacoZoomLevel(int v) noexcept { setInt32(ViewStateOffset::MonacoZoomLevel, v); }
    void setSidebarWidth(int v) noexcept { setInt32(ViewStateOffset::SidebarWidth, v); }
    void setPanelHeight(int v) noexcept { setInt32(ViewStateOffset::PanelHeight, v); }
    void setSecondarySidebarWidth(int v) noexcept { setInt32(ViewStateOffset::SecondarySidebarWidth, v); }
    void setMinimapWidth(int v) noexcept { setInt32(ViewStateOffset::MinimapWidth, v); }
    
    // =========================================================================
    // String Operations
    // =========================================================================
    [[nodiscard]] const char* getString(ViewStateOffset offset) const noexcept {
        return ViewState_GetString(static_cast<int>(offset));
    }
    
    const char* setString(ViewStateOffset offset, const char* value) noexcept {
        return ViewState_SetString(static_cast<int>(offset), value);
    }
    
    [[nodiscard]] const char* getCurrentTheme() const noexcept {
        return getString(ViewStateOffset::CurrentTheme);
    }
    
    void setCurrentTheme(const char* theme) noexcept {
        setString(ViewStateOffset::CurrentTheme, theme);
    }
    
    // =========================================================================
    // Sequence Number (Optimistic Locking)
    // =========================================================================
    [[nodiscard]] uint64_t getSequence() const noexcept {
        return ViewState_GetSequence();
    }
    
    uint64_t incrementSequence() noexcept {
        return ViewState_IncrementSequence();
    }
    
    // =========================================================================
    // Bulk Operations
    // =========================================================================
    void resetToDefaults() noexcept {
        ViewState_ResetToDefaults();
    }
    
    void snapshot(void* dest) const noexcept {
        ViewState_Snapshot(dest);
    }
    
    [[nodiscard]] bool compareSnapshot(const void* snapshot) const noexcept {
        return ViewState_CompareSnapshot(snapshot) == 0;
    }
    
    // =========================================================================
    // RAII Snapshot Guard (for batch operations)
    // =========================================================================
    class SnapshotGuard {
    public:
        explicit SnapshotGuard(ViewStateMasm& state) : m_state(state) {
            m_state.snapshot(m_buffer);
        }
        
        [[nodiscard]] bool hasChanged() const noexcept {
            return !m_state.compareSnapshot(m_buffer);
        }
        
        void update() noexcept {
            m_state.snapshot(m_buffer);
        }
        
    private:
        ViewStateMasm& m_state;
        alignas(64) unsigned char m_buffer[64];
    };
    
    [[nodiscard]] SnapshotGuard makeSnapshotGuard() noexcept {
        return SnapshotGuard(*this);
    }
    
private:
    ViewStateMasm() = default;
    ~ViewStateMasm() = default;
    ViewStateMasm(const ViewStateMasm&) = delete;
    ViewStateMasm& operator=(const ViewStateMasm&) = delete;
    ViewStateMasm(ViewStateMasm&&) = delete;
    ViewStateMasm& operator=(ViewStateMasm&&) = delete;
};

// ============================================================================
// Legacy Global Accessor (backward compatible)
// ============================================================================
inline ViewStateMasm& GetViewStateMasm() {
    return ViewStateMasm::instance();
}

// Legacy global reference
inline ViewStateMasm& g_viewStateMasm = ViewStateMasm::instance();

} // namespace Core
} // namespace RawrXD

// ============================================================================
// Legacy C++ ViewState Compatibility Layer
// ============================================================================
// This allows gradual migration from the old C++ ViewState to the new
// MASM implementation. Eventually this should be removed.
// ============================================================================
namespace RawrXD {
namespace Core {

// Legacy ViewState struct for compatibility
struct ViewState {
    // These delegate to the MASM implementation
    [[nodiscard]] bool getBool(ViewStateFlag flag) const { 
        return ViewStateMasm::instance().getBool(flag); 
    }
    bool setBool(ViewStateFlag flag, bool value) { 
        return ViewStateMasm::instance().setBool(flag, value); 
    }
    bool toggleBool(ViewStateFlag flag) { 
        return ViewStateMasm::instance().toggleBool(flag); 
    }
    
    // Direct field access (delegates to MASM)
    [[nodiscard]] bool floatingPanelVisible() const { return getBool(ViewStateFlag::FloatingPanel); }
    [[nodiscard]] bool minimapEnabled() const { return getBool(ViewStateFlag::Minimap); }
    [[nodiscard]] bool moduleBrowserVisible() const { return getBool(ViewStateFlag::ModuleBrowser); }
    [[nodiscard]] bool monacoDevtoolsOpen() const { return getBool(ViewStateFlag::MonacoDevtools); }
    [[nodiscard]] bool monacoVisible() const { return getBool(ViewStateFlag::MonacoVisible); }
    [[nodiscard]] bool outputPanelVisible() const { return getBool(ViewStateFlag::OutputPanel); }
    [[nodiscard]] bool sidebarVisible() const { return getBool(ViewStateFlag::Sidebar); }
    [[nodiscard]] bool terminalVisible() const { return getBool(ViewStateFlag::Terminal); }
    [[nodiscard]] bool fullscreen() const { return getBool(ViewStateFlag::Fullscreen); }
    [[nodiscard]] bool streamingLoaderActive() const { return getBool(ViewStateFlag::StreamingLoader); }
    [[nodiscard]] bool vulkanRendererActive() const { return getBool(ViewStateFlag::VulkanRenderer); }
    [[nodiscard]] bool secondarySidebarVisible() const { return getBool(ViewStateFlag::SecondarySidebar); }
    [[nodiscard]] bool panelVisible() const { return getBool(ViewStateFlag::Panel); }
    [[nodiscard]] bool powerShellPanelVisible() const { return getBool(ViewStateFlag::PowerShellPanel); }
    [[nodiscard]] bool gpuTextEnabled() const { return getBool(ViewStateFlag::GPUText); }
    [[nodiscard]] bool debuggerEnabled() const { return getBool(ViewStateFlag::DebuggerEnabled); }
    [[nodiscard]] bool debuggerAttached() const { return getBool(ViewStateFlag::DebuggerAttached); }
    [[nodiscard]] bool debuggerPaused() const { return getBool(ViewStateFlag::DebuggerPaused); }
    [[nodiscard]] bool annotationsVisible() const { return getBool(ViewStateFlag::Annotations); }
    [[nodiscard]] bool profilingActive() const { return getBool(ViewStateFlag::Profiling); }
    [[nodiscard]] bool chatMode() const { return getBool(ViewStateFlag::ChatMode); }
    [[nodiscard]] bool sessionRestored() const { return getBool(ViewStateFlag::SessionRestored); }
    
    [[nodiscard]] int zoomLevel() const { return ViewStateMasm::instance().getZoomLevel(); }
    [[nodiscard]] int monacoZoomLevel() const { return ViewStateMasm::instance().getMonacoZoomLevel(); }
    [[nodiscard]] int sidebarWidth() const { return ViewStateMasm::instance().getSidebarWidth(); }
    [[nodiscard]] int panelHeight() const { return ViewStateMasm::instance().getPanelHeight(); }
    [[nodiscard]] int secondarySidebarWidth() const { return ViewStateMasm::instance().getSecondarySidebarWidth(); }
    [[nodiscard]] int minimapWidth() const { return ViewStateMasm::instance().getMinimapWidth(); }
    
    [[nodiscard]] const char* currentTheme() const { return ViewStateMasm::instance().getCurrentTheme(); }
    
    // Singleton
    static ViewState& instance() {
        static ViewState s_instance;
        return s_instance;
    }
};

} // namespace Core
} // namespace RawrXD

// Legacy global for maximum compatibility
inline RawrXD::Core::ViewState& g_viewState = RawrXD::Core::ViewState::instance();
