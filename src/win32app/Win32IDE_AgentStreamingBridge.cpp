// Win32IDE_AgentStreamingBridge.cpp — C API for agent streaming → IDE output
// Routes AgentPanel_AppendMessage / AgentPanel_AppendToken to appendToOutput("Agent").

#include "Win32IDE.h"
#include "FailureModeFirewall.h"
#include <mutex>
#include <new>
#include <string>
#include <atomic>

namespace {

// Global flag to track if IDE is fully initialized
// Using volatile bool instead of std::atomic to avoid static initialization issues
volatile bool s_ideFullyInitialized = false;

// Diagnostic capture structure for crash analysis
struct FinalizeStreamDiagnostics {
    void* thisPtr;
    void* stream;
    void* agentBridge;
    void* renderSurface;
    void* completionQueue;
    void* annotationOverlay;
    bool ideInitialized;
    bool mainWindowValid;
    bool bridgeEnabled;
    DWORD threadId;
    DWORD lastError;
    char exceptionType[256];
    char exceptionMessage[512];
    void* stackFrames[8];  // Captured stack trace
    USHORT stackFrameCount;
};

static FinalizeStreamDiagnostics s_lastDiagnostics = {};

// Write diagnostics to a file for post-mortem analysis (no debugger needed)
static void WriteDiagnosticsToFile(const char* eventName, DWORD exCode = 0) {
    FILE* f = nullptr;
    errno_t err = fopen_s(&f, "agentpanel_diagnostics.log", "a");
    if (err != 0 || !f) return;
    
    SYSTEMTIME st;
    GetSystemTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] EVENT=%s PID=%lu TID=%lu\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        eventName, GetCurrentProcessId(), GetCurrentThreadId());
    fprintf(f, "  thisPtr=%p ideInit=%d winValid=%d bridge=%d\n",
        s_lastDiagnostics.thisPtr,
        s_lastDiagnostics.ideInitialized,
        s_lastDiagnostics.mainWindowValid,
        s_lastDiagnostics.bridgeEnabled);
    if (exCode != 0) {
        fprintf(f, "  EXCEPTION_CODE=0x%08X\n", exCode);
    }
    if (s_lastDiagnostics.stackFrameCount > 0) {
        fprintf(f, "  StackTrace:\n");
        for (USHORT i = 0; i < s_lastDiagnostics.stackFrameCount; i++) {
            fprintf(f, "    [%u] %p\n", i, s_lastDiagnostics.stackFrames[i]);
        }
    }
    fprintf(f, "---\n");
    fclose(f);
}

// Capture stack trace for debugging
static void CaptureStackTrace(void** frames, USHORT maxFrames, USHORT& captured) {
    captured = RtlCaptureStackBackTrace(0, maxFrames, frames, nullptr);
}

// Helper to check if IDE is ready
bool IsIDEFullyInitialized() {
    return s_ideFullyInitialized;
}

std::string wideToUtf8(const wchar_t* wstr) {
    if (!wstr) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// Safely post text to the Agent output tab from any thread.
// Heap-allocates a copy of text; the UI-thread handler (WM_IDE_OUTPUT_APPEND_SAFE) frees it.
void postAgentOutputSafe(std::string text) {
    if (!g_pMainIDE) return;
    HWND hwnd = g_pMainIDE->getMainWindow();
    if (!hwnd || !IsWindow(hwnd)) return;
    if (text.empty()) return;  // Skip empty strings
    try {
        auto* payload = new (std::nothrow) std::string(std::move(text));
        if (!payload) return;
        if (!PostMessage(hwnd, WM_IDE_OUTPUT_APPEND_SAFE, 0, reinterpret_cast<LPARAM>(payload))) {
            delete payload;
        }
    } catch (...) {
        // Ignore exceptions during posting
        OutputDebugStringA("[AgentStreamingBridge] postAgentOutputSafe exception caught\n");
    }
}

std::mutex* s_tokenBufMtx = nullptr;
// DEFENSIVE: Use pointer to heap-allocated string to avoid static destructor issues
std::string* s_tokenBuf = nullptr;

// Helper to safely get mutex
std::mutex* GetTokenBufMtx() {
    if (!s_tokenBufMtx) {
        s_tokenBufMtx = new (std::nothrow) std::mutex();
    }
    return s_tokenBufMtx;
}

// Helper to safely get token buffer
std::string* GetTokenBuf() {
    if (!s_tokenBuf) {
        s_tokenBuf = new (std::nothrow) std::string();
    }
    return s_tokenBuf;
}

} // namespace

extern "C" {

// Called when IDE is fully initialized and ready for agent bridge operations
void AgentBridge_SetReady(bool ready) {
    s_ideFullyInitialized = ready;
    if (ready) {
        OutputDebugStringA("[AgentStreamingBridge] IDE fully initialized, agent bridge ready\n");
    } else {
        OutputDebugStringA("[AgentStreamingBridge] IDE not ready, agent bridge disabled\n");
    }
}

static void AgentPanel_AppendMessage_Impl(const wchar_t* role, const wchar_t* content) {
    // DEFENSIVE: Completely disable during early startup
    static bool s_bridgeDisabled = true;
    if (s_bridgeDisabled && s_ideFullyInitialized) {
        s_bridgeDisabled = false;
    }
    if (s_bridgeDisabled) return;
    
    // DEFENSIVE: Skip if IDE not initialized (race condition during startup)
    if (!g_pMainIDE) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendMessage: g_pMainIDE is null, skipping\n");
        return;
    }
    
    // EXTRA DEFENSIVE: Skip if IDE not fully initialized yet
    if (!s_ideFullyInitialized) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendMessage: IDE not fully initialized, skipping\n");
        return;
    }
    
    std::string r = wideToUtf8(role);
    std::string c = wideToUtf8(content);
    if (r.empty() && c.empty()) return;
    if (r.empty()) r = "agent";
    std::string line = "[Agent] " + r + ": " + c;
    if (!line.empty() && line.back() != '\n') line += "\n";
    postAgentOutputSafe(std::move(line));
    
    try {
        g_pMainIDE->bridgeRecordSimpleEvent(AgentEventType::AgentCompleted, r + ": " + c.substr(0, 80));
    } catch (...) {
        OutputDebugStringA("[AgentStreamingBridge] bridgeRecordSimpleEvent exception caught\n");
    }
}

static void AgentPanel_AppendToken_Impl(const wchar_t* token) {
    // DEFENSIVE: Completely disable during early startup
    static bool s_bridgeDisabled = true;
    if (s_bridgeDisabled && s_ideFullyInitialized) {
        s_bridgeDisabled = false;
    }
    if (s_bridgeDisabled) return;
    
    // DEFENSIVE: Skip if IDE not initialized (race condition during startup)
    if (!g_pMainIDE) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendToken: g_pMainIDE is null, skipping\n");
        return;
    }
    
    // EXTRA DEFENSIVE: Skip if IDE not fully initialized yet
    if (!s_ideFullyInitialized) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendToken: IDE not fully initialized, skipping\n");
        return;
    }
    
    if (!token) return;
    std::string t = wideToUtf8(token);
    std::string toFlush;
    {
        std::mutex* mtx = GetTokenBufMtx();
        if (mtx) {
            std::lock_guard<std::mutex> lk(*mtx);
            std::string* buf = GetTokenBuf();
            if (buf) {
                *buf += t;
                if (!buf->empty() && (buf->back() == '\n' || buf->size() > 256)) {
                    toFlush = std::move(*buf);
                    buf->clear();
                }
            }
        }
    }
    if (!toFlush.empty()) {
        postAgentOutputSafe(std::move(toFlush));
    }
}

static bool AgentPanel_FinalizeStream_Impl(void) {
    // FMF: Mark this as a real execution path
    FMF_REAL_ENTRY("AgentPanel_FinalizeStream");
    
    // DEFENSIVE: Completely disable during early startup to prevent crashes
    // The agent bridge will be enabled once the IDE is fully initialized
    static bool s_bridgeDisabled = true;  // Start disabled
    
    // Check if we should enable the bridge (only once)
    if (s_bridgeDisabled && s_ideFullyInitialized) {
        s_bridgeDisabled = false;
        OutputDebugStringA("[AgentStreamingBridge] Agent bridge enabled\n");
    }
    
    if (s_bridgeDisabled) {
        // Silently skip during startup - no logging to avoid overhead
        FMF_FALLBACK("AgentPanel_FinalizeStream: bridge disabled during startup");
        return false;
    }
    
    // DEFENSIVE: Don't finalize if IDE isn't fully initialized
    // This prevents race conditions during startup when the sidebar panel
    // hasn't been created yet but the agent bridge tries to finalize output
    if (!g_pMainIDE) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream: g_pMainIDE is null, skipping\n");
        FMF_FALLBACK("AgentPanel_FinalizeStream: g_pMainIDE is null");
        return false;
    }
    
    // EXTRA DEFENSIVE: Skip if IDE not fully initialized yet
    if (!s_ideFullyInitialized) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream: IDE not fully initialized, skipping\n");
        FMF_FALLBACK("AgentPanel_FinalizeStream: IDE not fully initialized");
        return false;
    }
    
    // EXTRA DEFENSIVE: Try-catch around everything to prevent crashes
    // with detailed exception logging
    try {
        HWND hwnd = nullptr;
        try {
            hwnd = g_pMainIDE->getMainWindow();
        } catch (const std::exception& e) {
            char buf[512];
            snprintf(buf, sizeof(buf), 
                "[AgentStreamingBridge] AgentPanel_FinalizeStream: getMainWindow() threw std::exception: %s\n", 
                e.what());
            OutputDebugStringA(buf);
            FMF_FALLBACK("AgentPanel_FinalizeStream: getMainWindow() threw std::exception");
            return false;
        } catch (...) {
            OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream: getMainWindow() threw unknown exception\n");
            FMF_FALLBACK("AgentPanel_FinalizeStream: getMainWindow() threw unknown exception");
            return false;
        }
        
        if (!hwnd || !IsWindow(hwnd)) {
            OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream: Main window not ready, skipping\n");
            FMF_FALLBACK("AgentPanel_FinalizeStream: Main window not ready");
            return false;
        }
        
        // Additional safety: Check if window is fully created and visible
        // During initialization, the window may exist but not be ready for messages
        if (!IsWindowVisible(hwnd) && !IsIconic(hwnd)) {
            // Window exists but may not be fully initialized yet
            // Still process the flush but don't send the completion message
            std::string toFlush;
            {
                std::mutex* mtx = GetTokenBufMtx();
                if (mtx) {
                    std::lock_guard<std::mutex> lk(*mtx);
                    std::string* buf = GetTokenBuf();
                    if (buf && !buf->empty()) {
                        toFlush = std::move(*buf);
                        buf->clear();
                    }
                }
            }
            if (!toFlush.empty()) {
                postAgentOutputSafe(std::move(toFlush));
            }
            OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream: Window not visible yet, partial flush only\n");
            return true;  // Partial success
        }
        
        std::string toFlush;
        {
            std::mutex* mtx = GetTokenBufMtx();
            if (mtx) {
                std::lock_guard<std::mutex> lk(*mtx);
                std::string* buf = GetTokenBuf();
                if (buf && !buf->empty()) {
                    toFlush = std::move(*buf);
                    buf->clear();
                }
            }
        }
        if (!toFlush.empty()) {
            postAgentOutputSafe(std::move(toFlush));
        }
        postAgentOutputSafe("\n");
        
        // Send completion notification - window should be ready now
        if (!PostMessage(hwnd, WM_APP + 112, 0, 0)) {
            DWORD error = GetLastError();
            char buf[256];
            snprintf(buf, sizeof(buf), "[AgentStreamingBridge] PostMessage failed with error %lu\n", error);
            OutputDebugStringA(buf);
        }
        
        return true;  // Success
    } catch (const std::exception& e) {
        char buf[1024];
        snprintf(buf, sizeof(buf),
            "[AgentStreamingBridge] AgentPanel_FinalizeStream_Impl: Caught std::exception: %s (type: %s)\n",
            e.what(),
#ifdef __cpp_rtti
            typeid(e).name()
#else
            "unknown (RTTI disabled)"
#endif
        );
        OutputDebugStringA(buf);
        
        // Store in diagnostics
        strncpy(s_lastDiagnostics.exceptionMessage, e.what(), sizeof(s_lastDiagnostics.exceptionMessage) - 1);
        strncpy(s_lastDiagnostics.exceptionType, 
#ifdef __cpp_rtti
            typeid(e).name(),
#else
            "unknown",
#endif
            sizeof(s_lastDiagnostics.exceptionType) - 1);
        
        // Report to FMF
        FMF_FALLBACK("AgentPanel_FinalizeStream_Impl: Caught std::exception");
        
        // Return failure - do not re-throw
        return false;
    } catch (...) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream_Impl: Caught unknown exception\n");
        FMF_FALLBACK("AgentPanel_FinalizeStream_Impl: Caught unknown exception");
        return false;
    }
}

#ifdef _WIN32
__declspec(dllexport)
#endif
void AgentPanel_AppendMessage(const wchar_t* role, const wchar_t* content) {
    // ABSOLUTE EARLY RETURN: Completely disable during startup
    if (!s_ideFullyInitialized) {
        return;
    }
    
    __try {
        AgentPanel_AppendMessage_Impl(role, content);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendMessage trapped SEH exception\n");
    }
}

#ifdef _WIN32
__declspec(dllexport)
#endif
void AgentPanel_AppendToken(const wchar_t* token) {
    // ABSOLUTE EARLY RETURN: Completely disable during startup
    if (!s_ideFullyInitialized) {
        return;
    }
    
    __try {
        AgentPanel_AppendToken_Impl(token);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringA("[AgentStreamingBridge] AgentPanel_AppendToken trapped SEH exception\n");
    }
}

#ifdef _WIN32
__declspec(dllexport)
#endif
void AgentPanel_FinalizeStream(void) {
    // ABSOLUTE EARLY RETURN: Completely disable during startup
    // This function is causing heap corruption during early initialization
    // The agent bridge will be re-enabled once the IDE is fully initialized
    // via AgentBridge_SetReady(true) called from deferredHeavyInitBody
    static volatile bool s_bridgeEnabled = false;
    
    // Clear diagnostics for this invocation
    memset(&s_lastDiagnostics, 0, sizeof(s_lastDiagnostics));
    s_lastDiagnostics.threadId = GetCurrentThreadId();
    
    // Check if bridge should be enabled (only check once per call)
    if (!s_bridgeEnabled) {
        // Try to enable if IDE is fully initialized
        if (s_ideFullyInitialized) {
            s_bridgeEnabled = true;
            OutputDebugStringA("[AgentStreamingBridge] Bridge enabled\n");
        } else {
            // Bridge disabled - silently return
            return;
        }
    }
    
    s_lastDiagnostics.bridgeEnabled = s_bridgeEnabled;
    s_lastDiagnostics.ideInitialized = s_ideFullyInitialized;
    
    // Capture state before attempting execution
    if (g_pMainIDE) {
        s_lastDiagnostics.thisPtr = reinterpret_cast<void*>(g_pMainIDE);
        // Use SEH for this check too to avoid mixing exception types
        __try {
            HWND hwnd = g_pMainIDE->getMainWindow();
            s_lastDiagnostics.mainWindowValid = (hwnd != nullptr && IsWindow(hwnd));
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            s_lastDiagnostics.mainWindowValid = false;
        }
    }
    
    __try {
        bool result = AgentPanel_FinalizeStream_Impl();
        if (!result) {
            OutputDebugStringA("[AgentStreamingBridge] AgentPanel_FinalizeStream_Impl returned false\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        s_lastDiagnostics.lastError = exCode;
        
        // Capture stack trace
        CaptureStackTrace(s_lastDiagnostics.stackFrames, 8, s_lastDiagnostics.stackFrameCount);
        
        // Write to file immediately (no debugger needed)
        WriteDiagnosticsToFile("FinalizeStream_SEH", exCode);
        
        // Log the exception code
        char buf[512];
        snprintf(buf, sizeof(buf), 
            "[AgentStreamingBridge] AgentPanel_FinalizeStream trapped SEH exception. Code: 0x%08X\n", 
            exCode);
        OutputDebugStringA(buf);
        
        // Log captured stack
        if (s_lastDiagnostics.stackFrameCount > 0) {
            OutputDebugStringA("[AgentStreamingBridge] Stack trace:\n");
            for (USHORT i = 0; i < s_lastDiagnostics.stackFrameCount; i++) {
                snprintf(buf, sizeof(buf), "  [%u] %p\n", i, s_lastDiagnostics.stackFrames[i]);
                OutputDebugStringA(buf);
            }
        }
        
        // Log diagnostics
        snprintf(buf, sizeof(buf),
            "[AgentStreamingBridge] Diagnostics - this: %p, ideInit: %d, winValid: %d, bridge: %d, tid: %lu\n",
            s_lastDiagnostics.thisPtr,
            s_lastDiagnostics.ideInitialized,
            s_lastDiagnostics.mainWindowValid,
            s_lastDiagnostics.bridgeEnabled,
            s_lastDiagnostics.threadId);
        OutputDebugStringA(buf);
        
        // DO NOT re-throw - preserve first fault location but allow continuation
        // The function returns void, so we simply return
    }
}

} // extern "C"
