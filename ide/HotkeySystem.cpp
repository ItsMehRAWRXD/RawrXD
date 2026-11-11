#include "ide/HotkeySystem.hpp"
#include "sovereign/Beaconism.hpp"

namespace IDE {

HotkeySystem& HotkeySystem::Instance() {
    static HotkeySystem instance;
    return instance;
}

bool HotkeySystem::Initialize(HWND hwnd) {
    m_hwnd = hwnd;
    RegisterHotkeys();
    m_initialized = true;

    Beaconism::Emit(Beaconism::BEACON_UIEvent, {{"component", "HotkeySystem"}, {"action", "initialized"}});
    return true;
}

void HotkeySystem::Shutdown() {
    if (m_initialized) {
        for (int i = static_cast<int>(HotkeyId::F1_Help); i <= static_cast<int>(HotkeyId::F12_SelfOptimization); ++i) {
            UnregisterHotKey(m_hwnd, i);
        }
        m_initialized = false;
    }
}

void HotkeySystem::RegisterCallback(HotkeyId id, HotkeyCallback cb) {
    m_callbacks[id] = cb;
}

void HotkeySystem::UnregisterCallback(HotkeyId id) {
    m_callbacks.erase(id);
}

bool HotkeySystem::ProcessMessage(MSG& msg) {
    if (msg.message == WM_HOTKEY) {
        int id = static_cast<int>(msg.wParam);
        auto it = m_callbacks.find(static_cast<HotkeyId>(id));
        if (it != m_callbacks.end() && it->second) {
            it->second();
            return true;
        }
    }
    return false;
}

void HotkeySystem::RegisterHotkeys() {
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F1_Help), 0, VK_F1);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F2_Architecture), 0, VK_F2);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F3_KVHeatmap), 0, VK_F3);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F4_MoETimeline), 0, VK_F4);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F5_GPUPipeline), 0, VK_F5);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F6_Health), 0, VK_F6);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F7_Models), 0, VK_F7);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F8_Settings), 0, VK_F8);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F9_GlobalAttention), 0, VK_F9);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F10_MemoryLake), 0, VK_F10);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F11_AgentFederation), 0, VK_F11);
    RegisterHotKey(m_hwnd, static_cast<int>(HotkeyId::F12_SelfOptimization), 0, VK_F12);
}

void HotkeySystem::RegisterShift(const std::string& key, HotkeyCallback cb) {
    // Placeholder: treat Shift+key same as key for now
    // In production, this would register with MOD_SHIFT
}

}
