// ============================================================================
// shared_context.h - Global Context Management
// Thread-safe singleton for cross-component state sharing
// ============================================================================

#ifndef SHAREDCONTEXT_H
#define SHAREDCONTEXT_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstdint>

// ============================================================================
// Session Information
// ============================================================================
struct SessionInfo {
    uint32_t id;
    std::string name;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    bool active;
    uint64_t requestCount;
    uint64_t errorCount;
    uint64_t tokensGenerated;
};

// ============================================================================
// Editor Information
// ============================================================================
struct EditorInfo {
    std::string id;
    std::string filePath;
    std::chrono::steady_clock::time_point openTime;
    bool isModified;
};

// ============================================================================
// File Information
// ============================================================================
struct FileInfo {
    std::string path;
    std::string language;
    std::chrono::steady_clock::time_point openTime;
};

// ============================================================================
// Global Context
// ============================================================================
class GlobalContext {
public:
    // Singleton access
    static GlobalContext& Get();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Session Management
    uint32_t CreateSession(const std::string& name);
    void EndSession(uint32_t sessionId);
    bool IsSessionActive(uint32_t sessionId) const;
    void IncrementSessionRequests(uint32_t sessionId);
    void IncrementSessionErrors(uint32_t sessionId);
    void AddSessionTokens(uint32_t sessionId, size_t tokens);
    
    // Editor Management
    void RegisterEditor(const std::string& editorId, const std::string& filePath);
    void UnregisterEditor(const std::string& editorId);
    void MarkEditorModified(const std::string& editorId, bool modified);
    size_t GetActiveEditorCount() const;
    
    // File Management
    void RegisterFile(const std::string& filePath, const std::string& language);
    void UnregisterFile(const std::string& filePath);
    size_t GetActiveFileCount() const;
    
    // Memory Tracking
    void UpdateMemoryStats();
    size_t GetCurrentMemoryMB() const;
    size_t GetPeakMemoryMB() const;
    
    // Metrics
    void IncrementRequestCount();
    void IncrementErrorCount();
    uint64_t GetTotalRequests() const;
    uint64_t GetTotalErrors() const;

private:
    GlobalContext();
    ~GlobalContext();
    
    // Prevent copying
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;

private:
    mutable std::mutex mutex_;
    std::atomic<bool> initialized_;
    
    // Session tracking
    std::vector<SessionInfo> sessions_;
    std::atomic<uint32_t> nextSessionId_;
    
    // Editor tracking
    std::map<std::string, EditorInfo> activeEditors_;
    
    // File tracking
    std::map<std::string, FileInfo> activeFiles_;
    
    // Metrics
    std::atomic<uint64_t> totalRequests_;
    std::atomic<uint64_t> totalErrors_;
    
    // Memory tracking
    std::atomic<size_t> peakMemoryMB_;
    std::atomic<size_t> currentMemoryMB_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

__declspec(dllexport) bool RawrXD_InitGlobalContext();
__declspec(dllexport) void RawrXD_ShutdownGlobalContext();
__declspec(dllexport) uint32_t RawrXD_CreateSession(const char* name);
__declspec(dllexport) void RawrXD_EndSession(uint32_t sessionId);
__declspec(dllexport) void RawrXD_IncrementRequests();
__declspec(dllexport) void RawrXD_IncrementErrors();
__declspec(dllexport) uint64_t RawrXD_GetTotalRequests();
__declspec(dllexport) uint64_t RawrXD_GetTotalErrors();

} // extern "C"

#endif // SHAREDCONTEXT_H
