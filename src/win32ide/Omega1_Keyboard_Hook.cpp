// ============================================================================
// Omega1 Keyboard Hook Implementation
// Intercepts Ctrl+Space for completion trigger
// ============================================================================

#include "Omega1_Keyboard_Hook.h"
#include "Omega1_IDE_Bridge.h"
#include <cstring>

#pragma comment(lib, "user32.lib")

namespace RawrXD {
namespace Omega1 {

// Static instance pointer
KeyboardHook* KeyboardHook::s_instance = nullptr;

// ============================================================================
// Singleton
// ============================================================================

KeyboardHook& KeyboardHook::GetInstance() {
    static KeyboardHook instance;
    return instance;
}

// ============================================================================
// Hook Installation
// ============================================================================

bool KeyboardHook::Install(HWND hTargetWindow) {
    if (m_installed) return true;

    m_hTargetWindow = hTargetWindow;
    s_instance = this;

    // Install low-level keyboard hook
    m_hHook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandleW(nullptr),
        0
    );

    if (!m_hHook) {
        return false;
    }

    // Subclass the editor window for direct message handling
    // This allows us to intercept Tab/Esc before editor processes them
    SetWindowSubclass(hTargetWindow, EditorSubclassProc, 0, (DWORD_PTR)this);

    m_installed = true;
    return true;
}

void KeyboardHook::Remove() {
    if (!m_installed) return;

    if (m_hHook) {
        UnhookWindowsHookEx(m_hHook);
        m_hHook = nullptr;
    }

    if (m_hTargetWindow) {
        RemoveWindowSubclass(m_hTargetWindow, EditorSubclassProc, 0);
        m_hTargetWindow = nullptr;
    }

    m_installed = false;
    s_instance = nullptr;
}

// ============================================================================
// Configuration
// ============================================================================

void KeyboardHook::SetTriggerKey(UINT vkCode, bool ctrl, bool shift, bool alt) {
    m_triggerKey = vkCode;
    m_triggerCtrl = ctrl;
    m_triggerShift = shift;
    m_triggerAlt = alt;
}

// ============================================================================
// Low-Level Keyboard Hook
// ============================================================================

LRESULT CALLBACK KeyboardHook::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0 || !s_instance) {
        return CallNextHookEx(nullptr, nCode, wParam, lParam);
    }

    auto* pKbd = (KBDLLHOOKSTRUCT*)lParam;
    UINT vkCode = pKbd->vkCode;
    bool keyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
    bool keyUp = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);

    // Track modifier states
    if (vkCode == VK_LCONTROL || vkCode == VK_RCONTROL || vkCode == VK_CONTROL) {
        s_instance->m_ctrlPressed = keyDown;
    }
    if (vkCode == VK_LSHIFT || vkCode == VK_RSHIFT || vkCode == VK_SHIFT) {
        s_instance->m_shiftPressed = keyDown;
    }
    if (vkCode == VK_LMENU || vkCode == VK_RMENU || vkCode == VK_MENU) {
        s_instance->m_altPressed = keyDown;
    }

    // Check for trigger key combination
    if (keyDown && vkCode == s_instance->m_triggerKey) {
        bool modsMatch = (s_instance->m_triggerCtrl == s_instance->m_ctrlPressed) &&
                        (s_instance->m_triggerShift == s_instance->m_shiftPressed) &&
                        (s_instance->m_triggerAlt == s_instance->m_altPressed);

        if (modsMatch) {
            // Trigger completion
            auto& bridge = IDEIntegrationBridge::GetInstance();
            if (bridge.IsInitialized()) {
                HWND hForeground = GetForegroundWindow();
                HWND hFocus = GetFocus();

                // Find editor window in focus
                // This would need to be the actual editor HWND
                // For now, use the target window
                bridge.TriggerGhostCompletion(s_instance->m_hTargetWindow);
            }
            return 1; // Swallow the key
        }
    }

    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// ============================================================================
// Editor Subclass Procedure
// ============================================================================

LRESULT CALLBACK KeyboardHook::EditorSubclassProc(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {

    auto* self = (KeyboardHook*)dwRefData;
    if (!self) {
        return DefSubclassProc(hWnd, msg, wParam, lParam);
    }

    auto& bridge = IDEIntegrationBridge::GetInstance();

    switch (msg) {
    case WM_KEYDOWN: {
        // If ghost text is active, handle Tab/Esc
        if (bridge.IsGenerating() || !bridge.GetCurrentGhostText().empty()) {
            if (wParam == self->m_acceptKey) { // Tab
                // Accept ghost text
                bridge.AcceptGhostText();
                self->m_ghostActive = false;
                return 0; // Swallow Tab
            }

            if (wParam == self->m_cancelKey) { // Esc
                // Cancel ghost text
                bridge.RejectGhostText();
                self->m_ghostActive = false;
                return 0; // Swallow Esc
            }

            // Any other key cancels ghost text
            bridge.RejectGhostText();
            self->m_ghostActive = false;
        }
        break;
    }

    case WM_CHAR: {
        // Cancel ghost text on any character input
        if (bridge.IsGenerating() || !bridge.GetCurrentGhostText().empty()) {
            bridge.RejectGhostText();
            self->m_ghostActive = false;
        }
        break;
    }
    }

    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

} // namespace Omega1
} // namespace RawrXD
