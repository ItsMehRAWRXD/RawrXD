// ============================================================================
// Omega1 Keyboard Hook - Intercepts editor keystrokes for ghost text trigger
// Ctrl+Space = Trigger completion, Tab = Accept, Esc = Cancel
// ============================================================================

#pragma once
#include <windows.h>

namespace RawrXD {
namespace Omega1 {

// Keyboard hook manager
class KeyboardHook {
public:
    static KeyboardHook& GetInstance();

    // Install/remove hook
    bool Install(HWND hTargetWindow);
    void Remove();
    bool IsInstalled() const { return m_installed; }

    // Configuration
    void SetTriggerKey(UINT vkCode, bool ctrl, bool shift, bool alt);
    void SetAcceptKey(UINT vkCode) { m_acceptKey = vkCode; }
    void SetCancelKey(UINT vkCode) { m_cancelKey = vkCode; }

    // State
    bool IsGhostTextActive() const { return m_ghostActive; }
    void SetGhostTextActive(bool active) { m_ghostActive = active; }

private:
    KeyboardHook() = default;
    ~KeyboardHook() { Remove(); }

    // Non-copyable
    KeyboardHook(const KeyboardHook&) = delete;
    KeyboardHook& operator=(const KeyboardHook&) = delete;

    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK EditorSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

    bool m_installed = false;
    HHOOK m_hHook = nullptr;
    HWND m_hTargetWindow = nullptr;
    WNDPROC m_origEditorProc = nullptr;

    // Key bindings
    UINT m_triggerKey = VK_SPACE;     // Ctrl+Space
    bool m_triggerCtrl = true;
    bool m_triggerShift = false;
    bool m_triggerAlt = false;
    UINT m_acceptKey = VK_TAB;          // Tab
    UINT m_cancelKey = VK_ESCAPE;       // Esc

    // State
    bool m_ghostActive = false;
    bool m_ctrlPressed = false;
    bool m_shiftPressed = false;
    bool m_altPressed = false;

    // Static instance for callback
    static KeyboardHook* s_instance;
};

} // namespace Omega1
} // namespace RawrXD
