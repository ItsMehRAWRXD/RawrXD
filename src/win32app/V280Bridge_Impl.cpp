// ============================================================================
// V280Bridge_Impl.cpp - IV280Bridge implementation using GhostTextBuffer (Day 2)
// ============================================================================
// Connects the ghost_text_engine (Day 1) to the IDE's IV280Bridge interface.
// This allows Win32IDE_Core.cpp to display ghost text from the inference engine.
//
// DAY 2 DELIVERABLE:
// - Implements IV280Bridge interface
// - Reads from GhostTextBuffer (populated by Bridge_OnSuggestionReady)
// - Provides IsGhostActive() and GetGhostText() for WM_PAINT rendering
// ============================================================================

#include "IV280Bridge.h"
#include "../ghost_text_engine.h"
#include <string>
#include <windows.h>

// ============================================================================
// V280Bridge Implementation
// ============================================================================

class V280Bridge_Impl : public IV280Bridge {
public:
    V280Bridge_Impl() = default;
    ~V280Bridge_Impl() override = default;

    // Window procedure hook - not used for ghost text, but required by interface
    int64_t WndProcHook(void* hwnd, uint32_t uMsg, uint64_t wParam, int64_t lParam) override {
        (void)hwnd;
        (void)uMsg;
        (void)wParam;
        (void)lParam;
        return 0; // Pass through all messages
    }

    // Check if ghost text is available
    bool IsGhostActive() const override {
        return RawrXD::GhostText_IsActive();
    }

    // Get ghost text into buffer
    int GetGhostText(char* buf, int bufSize) const override {
        if (!buf || bufSize <= 0) return 0;
        
        std::string text = RawrXD::GhostText_GetCurrentText();
        if (text.empty()) {
            buf[0] = '\0';
            return 0;
        }
        
        // Copy to buffer, truncating if necessary
        int copyLen = static_cast<int>(text.length());
        if (copyLen >= bufSize) {
            copyLen = bufSize - 1;
        }
        
        std::memcpy(buf, text.c_str(), copyLen);
        buf[copyLen] = '\0';
        
        return copyLen;
    }

    // Timer management (not used in this implementation)
    void InstallPollTimer(void* hwnd) override {
        (void)hwnd;
        // Ghost text is pushed via WM_APP messages, no polling needed
    }

    void KillPollTimer() override {
        // No timer to kill
    }

    // Trigger repaint (called when new suggestion arrives)
    void TriggerRepaint() override {
        // This is called by the inference thread via Bridge_OnSuggestionComplete
        // The actual repaint is triggered by WM_APP_GHOST_TEXT_UPDATE message
    }
};

// ============================================================================
// Global Singleton
// ============================================================================

static IV280Bridge* g_v280Bridge = nullptr;

IV280Bridge* CreateV280Bridge() {
    if (!g_v280Bridge) {
        g_v280Bridge = new V280Bridge_Impl();
    }
    return g_v280Bridge;
}

IV280Bridge* GetV280Bridge() {
    if (!g_v280Bridge) {
        g_v280Bridge = CreateV280Bridge();
    }
    return g_v280Bridge;
}

void DestroyV280Bridge() {
    delete g_v280Bridge;
    g_v280Bridge = nullptr;
}
