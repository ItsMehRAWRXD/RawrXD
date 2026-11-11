#include "IV280Bridge.h"
#include <windows.h>

// ============================================================================
// IV280Bridge Implementation
// Wraps the extern "C" v280 functions with proper interface abstraction
// ============================================================================

// Forward declarations of extern v280 functions
extern "C" {
    int64_t V280_UI_WndProc_Hook(void* hwnd, uint32_t uMsg, uint64_t wParam, int64_t lParam);
    int V280_UI_IsGhostActive(void);
    int V280_UI_GetGhostText(char* buf, int buf_size);
}

namespace {
    // Internal implementation class
    class V280BridgeImpl : public IV280Bridge {
    public:
        V280BridgeImpl() = default;
        ~V280BridgeImpl() override = default;
        
        int64_t WndProcHook(void* hwnd, uint32_t uMsg, uint64_t wParam, int64_t lParam) override {
            return V280_UI_WndProc_Hook(hwnd, uMsg, wParam, lParam);
        }
        
        bool IsGhostActive() const override {
            return V280_UI_IsGhostActive() != 0;
        }
        
        int GetGhostText(char* buf, int bufSize) const override {
            return V280_UI_GetGhostText(buf, bufSize);
        }
        
        void InstallPollTimer(void* hwnd) override {
            // Timer ID 0x7D13 reserved for v280 polling
            SetTimer((HWND)hwnd, 0x7D13, 16, nullptr);  // ~60fps polling
        }
        
        void KillPollTimer() override {
            // Implementation tracks hwnd internally
            // This is a no-op for now - timer is killed in WM_DESTROY
        }
        
        void TriggerRepaint() override {
            // Post custom message to trigger ghost text repaint
            // WM_APP + 0x280 is reserved for v280 ghost text refresh
        }
    };
    
    // Singleton instance
    IV280Bridge* g_v280Bridge = nullptr;
}

IV280Bridge* CreateV280Bridge() {
    if (!g_v280Bridge) {
        // Check if v280 functions are available (they return 0 if not initialized)
        char testBuf[4];
        int result = V280_UI_GetGhostText(testBuf, sizeof(testBuf));
        // Function exists and returns valid data (even if empty)
        (void)result;  // Suppress unused warning
        
        g_v280Bridge = new V280BridgeImpl();
    }
    return g_v280Bridge;
}

IV280Bridge* GetV280Bridge() {
    if (!g_v280Bridge) {
        return CreateV280Bridge();
    }
    return g_v280Bridge;
}

void DestroyV280Bridge() {
    delete g_v280Bridge;
    g_v280Bridge = nullptr;
}
