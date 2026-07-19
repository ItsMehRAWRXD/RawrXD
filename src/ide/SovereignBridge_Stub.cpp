/*=============================================================================
 * SovereignBridge_Stub.cpp
 * Stub implementation of Sovereign Runtime Bridge for testing
 * Simulates inference without actual model calls
 *
 * Build: cl /c /W4 /EHsc /O2 SovereignBridge_Stub.cpp
 *===========================================================================*/

#include <windows.h>
#include <string>
#include <cstring>
#include <cstdlib>

/*=============================================================================
 * CONFIGURATION
 *===========================================================================*/
static constexpr UINT   STUB_DELAY_MS = 150;        /* Simulated inference time */
static constexpr float  STUB_CONFIDENCE = 0.87f;    /* Mock confidence score */

/*=============================================================================
 * STATE
 *===========================================================================*/
struct StubState {
    BOOL        requestPending;
    DWORD       requestTime;
    std::string lastContext;
    int         lastLine;
    int         lastCol;
    std::string cachedSuggestion;
    float       cachedConfidence;
};

static StubState g_stubState = { FALSE, 0, "", 0, 0, "", 0.0f };

/*=============================================================================
 * MOCK SUGGESTION DATABASE
 *===========================================================================*/
static const char* GetMockSuggestionForContext(const char* context) {
    /* Pattern matching for different code contexts */
    if (strstr(context, "int main")) {
        return "(int argc, char** argv) {\r\n    return 0;\r\n}";
    }
    if (strstr(context, "for ") || strstr(context, "for(")) {
        return "(int i = 0; i < count; i++) {\r\n    \r\n}";
    }
    if (strstr(context, "if ") || strstr(context, "if(")) {
        return "(condition) {\r\n    /* TODO */\r\n}";
    }
    if (strstr(context, "while ") || strstr(context, "while(")) {
        return "(running) {\r\n    /* Loop body */\r\n}";
    }
    if (strstr(context, "class ") || strstr(context, "struct ")) {
        return " {\r\npublic:\r\n    \r\nprivate:\r\n    \r\n};";
    }
    if (strstr(context, "void ") || strstr(context, "int ") || 
        strstr(context, "bool ") || strstr(context, "auto ")) {
        return "() {\r\n    /* Function body */\r\n    return;\r\n}";
    }
    if (strstr(context, "std::")) {
        return "vector<int> items;";
    }
    if (strstr(context, "return")) {
        return " 0;";
    }
    if (strstr(context, "//")) {
        return " TODO: ";
    }
    
    /* Default suggestion */
    return " = 0;";
}

/*=============================================================================
 * BRIDGE API IMPLEMENTATION
 *===========================================================================*/

/**
 * @brief Initialize the stub bridge
 */
extern "C" __declspec(dllexport) BOOL SovereignBridge_Initialize(void) {
    ZeroMemory(&g_stubState, sizeof(g_stubState));
    OutputDebugStringA("[SovereignBridge] Stub initialized\n");
    return TRUE;
}

/**
 * @brief Shutdown the stub bridge
 */
extern "C" __declspec(dllexport) void SovereignBridge_Shutdown(void) {
    g_stubState.requestPending = FALSE;
    OutputDebugStringA("[SovereignBridge] Stub shutdown\n");
}

/**
 * @brief Check if bridge is ready
 */
extern "C" __declspec(dllexport) BOOL SovereignBridge_IsReady(void) {
    return TRUE; /* Stub is always ready */
}

/**
 * @brief Request a completion (async)
 */
extern "C" __declspec(dllexport) BOOL SovereignBridge_RequestCompletion(
    const char* context,
    int line,
    int col,
    int maxTokens
) {
    if (!context) return FALSE;
    
    /* Store request state */
    g_stubState.requestPending = TRUE;
    g_stubState.requestTime = GetTickCount();
    g_stubState.lastContext = context;
    g_stubState.lastLine = line;
    g_stubState.lastCol = col;
    
    /* Pre-generate suggestion */
    g_stubState.cachedSuggestion = GetMockSuggestionForContext(context);
    g_stubState.cachedConfidence = STUB_CONFIDENCE + ((float)(rand() % 20) / 100.0f - 0.1f);
    
    OutputDebugStringA("[SovereignBridge] Request received (stub)\n");
    
    return TRUE;
}

/**
 * @brief Check if completion is ready
 */
extern "C" __declspec(dllexport) BOOL SovereignBridge_IsCompletionReady(void) {
    if (!g_stubState.requestPending) return FALSE;
    
    /* Simulate delay */
    DWORD elapsed = GetTickCount() - g_stubState.requestTime;
    if (elapsed >= STUB_DELAY_MS) {
        return TRUE;
    }
    
    return FALSE;
}

/**
 * @brief Get completion result
 */
extern "C" __declspec(dllexport) int SovereignBridge_GetCompletion(
    char* outBuffer,
    int bufferSize,
    float* outConfidence
) {
    if (!g_stubState.requestPending || !outBuffer || bufferSize <= 0) {
        return 0;
    }
    
    /* Copy suggestion to output buffer */
    int len = (int)g_stubState.cachedSuggestion.length();
    if (len >= bufferSize) {
        len = bufferSize - 1;
    }
    
    memcpy(outBuffer, g_stubState.cachedSuggestion.c_str(), len);
    outBuffer[len] = '\0';
    
    if (outConfidence) {
        *outConfidence = g_stubState.cachedConfidence;
    }
    
    /* Clear pending state */
    g_stubState.requestPending = FALSE;
    
    OutputDebugStringA("[SovereignBridge] Completion returned (stub)\n");
    
    return len;
}

/**
 * @brief Cancel pending completion
 */
extern "C" __declspec(dllexport) void SovereignBridge_CancelCompletion(void) {
    g_stubState.requestPending = FALSE;
    OutputDebugStringA("[SovereignBridge] Request cancelled\n");
}

/**
 * @brief Get bridge status string
 */
extern "C" __declspec(dllexport) const char* SovereignBridge_GetStatus(void) {
    if (g_stubState.requestPending) {
        return "Processing (stub)";
    }
    return "Ready (stub mode)";
}

/**
 * @brief Get last error message
 */
extern "C" __declspec(dllexport) const char* SovereignBridge_GetLastError(void) {
    return "No error (stub mode)";
}

/*=============================================================================
 * LEGACY BRIDGE COMPATIBILITY (for GhostText_TimerHook.cpp)
 *===========================================================================*/

extern "C" {

/**
 * @brief Legacy bridge function - Request suggestion
 */
__declspec(dllexport) void Bridge_RequestSuggestion(void) {
    /* Get current tick count for delay simulation */
    g_stubState.requestTime = GetTickCount();
    g_stubState.requestPending = TRUE;
    g_stubState.cachedSuggestion = " = 0; /* stub suggestion */";
}

/**
 * @brief Legacy bridge function - Check if ready
 */
__declspec(dllexport) int Bridge_IsSuggestionReady(void) {
    if (!g_stubState.requestPending) return 0;
    
    DWORD elapsed = GetTickCount() - g_stubState.requestTime;
    return (elapsed >= STUB_DELAY_MS) ? 1 : 0;
}

/**
 * @brief Legacy bridge function - Get suggestion text
 */
__declspec(dllexport) int Bridge_GetSuggestionText(
    const char* contextLine,
    int cursorCol,
    char* outBuffer,
    int bufferSize
) {
    if (!outBuffer || bufferSize <= 0) return 0;
    
    /* Simple context-aware suggestion */
    const char* suggestion = GetMockSuggestionForContext(contextLine);
    int len = (int)strlen(suggestion);
    
    if (len >= bufferSize) len = bufferSize - 1;
    memcpy(outBuffer, suggestion, len);
    outBuffer[len] = '\0';
    
    g_stubState.requestPending = FALSE;
    
    return len;
}

/**
 * @brief Legacy bridge function - Clear suggestion
 */
__declspec(dllexport) void Bridge_ClearSuggestion(void) {
    g_stubState.requestPending = FALSE;
    g_stubState.cachedSuggestion.clear();
}

} /* extern "C" */

/*=============================================================================
 * BUILD NOTES
 *===========================================================================*/
/*
 * Compile as static library:
 *   cl /c /W4 /EHsc /O2 /DUNICODE /D_UNICODE SovereignBridge_Stub.cpp
 *   lib /OUT:SovereignBridge_Stub.lib SovereignBridge_Stub.obj
 *
 * Or compile directly into IDE:
 *   cl /W4 /O2 /DUNICODE /D_UNICODE RawrXD_IDE_Win32.cpp SovereignBridge_Stub.cpp
 *
 * Link with: user32.lib kernel32.lib
 */
