#include "ide/HotkeySystem.hpp"
#include <fstream>
#include <sstream>

namespace Sovereign {
namespace IDE {

HotkeySystem& HotkeySystem::Instance() {
    static HotkeySystem instance;
    return instance;
}

void HotkeySystem::Initialize(HWND hwnd) {
    m_hwnd = hwnd;
    RegisterDefaultHotkeys();
}

void HotkeySystem::Shutdown() {
    UnregisterAllHotkeys();
}

void HotkeySystem::RegisterDefaultHotkeys() {
    // F1: Health Panel
    RegisterHotkey({ 0, VK_F1, HotkeyAction::ShowHealthPanel, "Show Health Panel" });
    
    // F2: Profiler
    RegisterHotkey({ 0, VK_F2, HotkeyAction::ShowProfiler, "Show Profiler" });
    
    // F3: Scheduler
    RegisterHotkey({ 0, VK_F3, HotkeyAction::ShowScheduler, "Show Scheduler" });
    
    // F4: Replay Debugger
    RegisterHotkey({ 0, VK_F4, HotkeyAction::ShowReplayDebugger, "Show Replay Debugger" });
    
    // F5: Run Smoketest
    RegisterHotkey({ 0, VK_F5, HotkeyAction::RunSmoketest, "Run Smoketest" });
    
    // F6: Run Stress Test
    RegisterHotkey({ 0, VK_F6, HotkeyAction::RunStressTest, "Run Stress Test" });
    
    // F7: Toggle Theme
    RegisterHotkey({ 0, VK_F7, HotkeyAction::ToggleTheme, "Toggle Theme" });
    
    // F8: Toggle Fullscreen
    RegisterHotkey({ 0, VK_F8, HotkeyAction::ToggleFullscreen, "Toggle Fullscreen" });
    
    // F9: Model Browser
    RegisterHotkey({ 0, VK_F9, HotkeyAction::ShowModelBrowser, "Show Model Browser" });
    
    // F10: Architecture Diagram
    RegisterHotkey({ 0, VK_F10, HotkeyAction::ShowArchitectureDiagram, "Show Architecture Diagram" });
    
    // F11: KV Heatmap
    RegisterHotkey({ 0, VK_F11, HotkeyAction::ShowKVHeatmap, "Show KV Heatmap" });
    
    // F12: Command Palette
    RegisterHotkey({ 0, VK_F12, HotkeyAction::OpenCommandPalette, "Open Command Palette" });
    
    // Ctrl+F5: Emergency Repair
    RegisterHotkey({ MOD_CONTROL, VK_F5, HotkeyAction::EmergencyRepair, "Emergency Repair" });
    
    // Ctrl+F6: Toggle Watchdog
    RegisterHotkey({ MOD_CONTROL, VK_F6, HotkeyAction::ToggleWatchdog, "Toggle Watchdog" });
    
    // Ctrl+Shift+S: Save Layout
    RegisterHotkey({ MOD_CONTROL | MOD_SHIFT, 'S', HotkeyAction::SaveLayout, "Save Layout" });
    
    // Ctrl+Shift+L: Load Layout
    RegisterHotkey({ MOD_CONTROL | MOD_SHIFT, 'L', HotkeyAction::LoadLayout, "Load Layout" });
}

void HotkeySystem::RegisterHotkey(const Hotkey& hotkey) {
    if (!m_hwnd) return;
    
    int id = m_nextId++;
    
    if (RegisterHotKey(m_hwnd, id, hotkey.modifiers, hotkey.vk)) {
        m_hotkeys[id] = hotkey;
    }
}

void HotkeySystem::UnregisterHotkey(HotkeyAction action) {
    for (auto it = m_hotkeys.begin(); it != m_hotkeys.end(); ) {
        if (it->second.action == action) {
            UnregisterHotKey(m_hwnd, it->first);
            it = m_hotkeys.erase(it);
        } else {
            ++it;
        }
    }
}

void HotkeySystem::UnregisterAllHotkeys() {
    for (const auto& pair : m_hotkeys) {
        UnregisterHotKey(m_hwnd, pair.first);
    }
    m_hotkeys.clear();
    m_nextId = 1;
}

bool HotkeySystem::ProcessHotkey(WPARAM wParam) {
    auto it = m_hotkeys.find((int)wParam);
    if (it == m_hotkeys.end()) return false;
    
    HotkeyAction action = it->second.action;
    auto handlerIt = m_handlers.find(action);
    if (handlerIt != m_handlers.end() && handlerIt->second) {
        handlerIt->second();
        return true;
    }
    
    return false;
}

void HotkeySystem::SetActionHandler(HotkeyAction action, std::function<void()> handler) {
    m_handlers[action] = handler;
}

std::vector<Hotkey> HotkeySystem::GetRegisteredHotkeys() const {
    std::vector<Hotkey> result;
    for (const auto& pair : m_hotkeys) {
        result.push_back(pair.second);
    }
    return result;
}

std::string HotkeySystem::GetHotkeyDescription(HotkeyAction action) const {
    for (const auto& pair : m_hotkeys) {
        if (pair.second.action == action) {
            return pair.second.description;
        }
    }
    return "";
}

bool HotkeySystem::SaveConfig(const std::wstring& path) {
    std::ofstream file(path, std::ios::out);
    if (!file.is_open()) return false;
    
    file << "# Sovereign IDE Hotkey Configuration\n";
    for (const auto& pair : m_hotkeys) {
        const auto& hotkey = pair.second;
        file << "Action=" << static_cast<int>(hotkey.action) << "\n";
        file << "Modifiers=" << hotkey.modifiers << "\n";
        file << "VK=" << hotkey.vk << "\n";
        file << "Description=" << hotkey.description << "\n";
        file << "\n";
    }
    
    file.close();
    return true;
}

bool HotkeySystem::LoadConfig(const std::wstring& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    UnregisterAllHotkeys();
    
    std::string line;
    Hotkey currentHotkey;
    bool inHotkey = false;
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        if (key == "Action") {
            currentHotkey.action = static_cast<HotkeyAction>(std::stoi(value));
            inHotkey = true;
        } else if (key == "Modifiers") {
            currentHotkey.modifiers = std::stoul(value);
        } else if (key == "VK") {
            currentHotkey.vk = std::stoul(value);
        } else if (key == "Description") {
            currentHotkey.description = value;
        }
        
        // Empty line indicates end of hotkey definition
        if (line.empty() && inHotkey) {
            RegisterHotkey(currentHotkey);
            inHotkey = false;
        }
    }
    
    // Register last hotkey if file doesn't end with empty line
    if (inHotkey) {
        RegisterHotkey(currentHotkey);
    }
    
    file.close();
    return true;
}

} // namespace IDE
} // namespace Sovereign
