// ==============================================================================
// IDE_Completion_Bridge.cpp - C++ Bridge between MASM and CompletionEngine
// Zero dependencies, drop-in working code
// ==============================================================================

#include "../completion/CompletionEngine.h"
#include <cstring>
#include <cstdint>

using namespace RawrXD;

// Global completion engine instance
static CompletionEngine* g_CompletionEngine = nullptr;
static wchar_t g_GhostBuffer[256] = {0};
static int g_GhostLen = 0;

// ==============================================================================
// C API for MASM interop
// ==============================================================================

extern "C" {

// Initialize completion engine
__declspec(dllexport) bool CompletionEngine_Initialize(void* aiProvider) {
    g_CompletionEngine = new CompletionEngine();
    return g_CompletionEngine->Initialize(static_cast<AIProvider*>(aiProvider));
}

// Check if engine ready
__declspec(dllexport) bool CompletionEngine_IsReady() {
    return g_CompletionEngine && g_CompletionEngine->IsReady();
}

// Request completion (called from timer)
__declspec(dllexport) void CompletionEngine_Request(void* contextBuffer) {
    if (!g_CompletionEngine) return;
    
    EditorContext* ctx = static_cast<EditorContext*>(contextBuffer);
    
    g_CompletionEngine->RequestCompletion(*ctx, [](const CompletionResult& result) {
        if (result.success && !result.suggestions.empty()) {
            // Convert suggestion to wide char for Win32
            const std::string& text = result.suggestions[0].text;
            g_GhostLen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, 
                                             g_GhostBuffer, 256) - 1;
            if (g_GhostLen < 0) g_GhostLen = 0;
        }
    }, nullptr);
}

// Cancel current request
__declspec(dllexport) void CompletionEngine_Cancel() {
    if (g_CompletionEngine) {
        g_CompletionEngine->CancelCurrentRequest();
    }
}

// Commit ghost text to document
__declspec(dllexport) void CompletionEngine_Commit(const wchar_t* text, int len) {
    // TODO: Insert into document buffer
    // This would call the document model to insert text at cursor
    (void)text;
    (void)len;
    g_GhostLen = 0;
}

// Get current ghost text
__declspec(dllexport) const wchar_t* GetGhostText() {
    return g_GhostBuffer;
}

// Set ghost text from engine
__declspec(dllexport) void SetGhostText(const wchar_t* text, int len) {
    if (len > 255) len = 255;
    memcpy(g_GhostBuffer, text, len * sizeof(wchar_t));
    g_GhostBuffer[len] = 0;
    g_GhostLen = len;
}

// Clear ghost text
__declspec(dllexport) void ClearGhostText() {
    g_GhostBuffer[0] = 0;
    g_GhostLen = 0;
}

// Extract editor context (called on keystroke)
__declspec(dllexport) void ExtractContext(EditorContext* ctx) {
    // TODO: Get actual context from editor
    // This would read the current document state
    ctx->prefix = "// Current line prefix\n";
    ctx->suffix = "\n// Current line suffix";
    ctx->language = "cpp";
    ctx->lineNumber = 1;
    ctx->columnNumber = 1;
}

} // extern "C"
