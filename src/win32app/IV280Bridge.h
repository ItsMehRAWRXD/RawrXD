#pragma once
#include <cstdint>

// ============================================================================
// IV280Bridge Interface
// Abstract interface for v280 Shared Memory Bridge operations
// Replaces direct extern function calls with proper interface abstraction
// ============================================================================

class IV280Bridge {
public:
    virtual ~IV280Bridge() = default;
    
    // Window procedure hook for message interception
    // Returns non-zero if message was consumed, 0 to pass through
    virtual int64_t WndProcHook(void* hwnd, uint32_t uMsg, uint64_t wParam, int64_t lParam) = 0;
    
    // Ghost text state queries
    virtual bool IsGhostActive() const = 0;
    virtual int GetGhostText(char* buf, int bufSize) const = 0;
    
    // Token polling control
    virtual void InstallPollTimer(void* hwnd) = 0;
    virtual void KillPollTimer() = 0;
    
    // Trigger repaint for ghost text updates
    virtual void TriggerRepaint() = 0;
};

// Factory function to create the bridge implementation
// Returns nullptr if v280 bridge is not available
IV280Bridge* CreateV280Bridge();

// Singleton accessor for the global bridge instance
IV280Bridge* GetV280Bridge();

// Destroy the bridge instance (call on shutdown)
void DestroyV280Bridge();
