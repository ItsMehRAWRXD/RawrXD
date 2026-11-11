#pragma once
#include <windows.h>
#include <functional>
#include <map>
#include <string>

namespace Sovereign {
namespace IDE {

/**
 * @brief Hotkey action types
 */
enum class HotkeyAction {
    None = 0,
    ShowHealthPanel,
    ShowProfiler,
    ShowScheduler,
    ShowReplayDebugger,
    ShowModelBrowser,
    ShowArchitectureDiagram,
    ShowKVHeatmap,
    ShowMoETimeline,
    ShowGPUPipelineGraph,
    RunSmoketest,
    RunStressTest,
    ToggleTheme,
    ToggleFullscreen,
    SaveLayout,
    LoadLayout,
    ResetLayout,
    EmergencyRepair,
    ToggleWatchdog,
    OpenCommandPalette
};

/**
 * @brief Hotkey definition
 */
struct Hotkey {
    UINT modifiers;  // MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN
    UINT vk;         // Virtual key code
    HotkeyAction action;
    std::string description;
};

/**
 * @brief Sovereign Hotkey System (F1-F12 mapped to panels/actions)
 * 
 * Default mappings:
 * - F1: Show Health Panel
 * - F2: Show Profiler
 * - F3: Show Scheduler
 * - F4: Show Replay Debugger
 * - F5: Run Smoketest
 * - F6: Run Stress Test
 * - F7: Toggle Theme
 * - F8: Toggle Fullscreen
 * - F9: Show Model Browser
 * - F10: Show Architecture Diagram
 * - F11: Show KV Heatmap
 * - F12: Open Command Palette
 * - Ctrl+F5: Emergency Repair
 * - Ctrl+F6: Toggle Watchdog
 */
class HotkeySystem {
public:
    static HotkeySystem& Instance();

    void Initialize(HWND hwnd);
    void Shutdown();

    // Register hotkeys
    void RegisterDefaultHotkeys();
    void RegisterHotkey(const Hotkey& hotkey);
    void UnregisterHotkey(HotkeyAction action);
    void UnregisterAllHotkeys();

    // Handle hotkey messages
    bool ProcessHotkey(WPARAM wParam);

    // Set action handler
    void SetActionHandler(HotkeyAction action, std::function<void()> handler);

    // Get hotkey info
    std::vector<Hotkey> GetRegisteredHotkeys() const;
    std::string GetHotkeyDescription(HotkeyAction action) const;

    // Save/Load hotkey configuration
    bool SaveConfig(const std::wstring& path);
    bool LoadConfig(const std::wstring& path);

private:
    HotkeySystem() = default;
    
    HWND m_hwnd = nullptr;
    std::map<int, Hotkey> m_hotkeys;  // ID -> Hotkey
    std::map<HotkeyAction, std::function<void()>> m_handlers;
    int m_nextId = 1;
};

} // namespace IDE
} // namespace Sovereign
