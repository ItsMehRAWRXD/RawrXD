// ==============================================================================
// IDE_Context_Bridge.cpp - Repository Intelligence Integration
// Wires RepositoryIntelligence to IDE project open/close
// Zero dependencies, drop-in working code
// ==============================================================================

#include "../context/RepositoryIntelligence.h"
#include <string>
#include <filesystem>

namespace fs = std::filesystem;
using namespace RawrXD;

// Global repository intelligence instance
static RepositoryIntelligence* g_RepoIntel = nullptr;
static std::string g_CurrentProjectPath;

// ==============================================================================
// C API for MASM/IDE interop
// ==============================================================================

extern "C" {

// Initialize repository intelligence on project open
__declspec(dllexport) bool RepoIntel_Initialize(const char* projectPath) {
    if (!projectPath || !*projectPath) return false;
    
    g_RepoIntel = new RepositoryIntelligence();
    if (!g_RepoIntel->Initialize(projectPath)) {
        delete g_RepoIntel;
        g_RepoIntel = nullptr;
        return false;
    }
    
    g_CurrentProjectPath = projectPath;
    return true;
}

// Shutdown repository intelligence
__declspec(dllexport) void RepoIntel_Shutdown() {
    delete g_RepoIntel;
    g_RepoIntel = nullptr;
    g_CurrentProjectPath.clear();
}

// Check if ready
__declspec(dllexport) bool RepoIntel_IsReady() {
    return g_RepoIntel && g_RepoIntel->IsReady();
}

// Get context for completion (called before AI request)
__declspec(dllexport) int RepoIntel_GetContextForCompletion(
    const char* filePath,
    int line,
    int column,
    const char* prefix,
    char* outContext,
    int maxLen
) {
    if (!g_RepoIntel || !g_RepoIntel->IsReady()) return 0;
    
    auto* retriever = g_RepoIntel->GetRetriever();
    if (!retriever) return 0;
    
    ContextResult result = retriever->RetrieveForCompletion(
        prefix ? prefix : "",
        filePath ? filePath : "",
        line,
        2048  // max tokens
    );
    
    int len = (int)result.contextText.length();
    if (len > maxLen - 1) len = maxLen - 1;
    
    memcpy(outContext, result.contextText.c_str(), len);
    outContext[len] = 0;
    
    return len;
}

// Get context for explanation
__declspec(dllexport) int RepoIntel_GetContextForExplanation(
    const char* symbolName,
    char* outContext,
    int maxLen
) {
    if (!g_RepoIntel || !g_RepoIntel->IsReady()) return 0;
    
    auto* retriever = g_RepoIntel->GetRetriever();
    if (!retriever) return 0;
    
    ContextResult result = retriever->RetrieveForExplanation(
        symbolName ? symbolName : "",
        2048
    );
    
    int len = (int)result.contextText.length();
    if (len > maxLen - 1) len = maxLen - 1;
    
    memcpy(outContext, result.contextText.c_str(), len);
    outContext[len] = 0;
    
    return len;
}

// Update file (called on save)
__declspec(dllexport) void RepoIntel_UpdateFile(const char* filePath) {
    if (g_RepoIntel) {
        g_RepoIntel->UpdateFile(filePath);
    }
}

// Get status string
__declspec(dllexport) const char* RepoIntel_GetStatus() {
    static thread_local char buffer[256];
    if (!g_RepoIntel) {
        strcpy_s(buffer, "Not initialized");
        return buffer;
    }
    
    std::string status = g_RepoIntel->GetStatus();
    strcpy_s(buffer, status.c_str());
    return buffer;
}

// Get symbol count
__declspec(dllexport) int RepoIntel_GetSymbolCount() {
    if (!g_RepoIntel) return 0;
    return (int)g_RepoIntel->GetIndexedSymbolCount();
}

} // extern "C"
