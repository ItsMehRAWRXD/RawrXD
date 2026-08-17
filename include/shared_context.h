#pragma once

// Global Context - Singleton for application-wide state management
// Thread-safe, no Qt dependencies

#include <string>
#include <vector>
#include <set>
#include <map>
#include <deque>
#include <atomic>
#include <chrono>
#include <windows.h>

class GlobalContext {
public:
    // Singleton access
    static GlobalContext& Get();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Session management
    std::string GetSessionId() const;
    std::chrono::steady_clock::time_point GetSessionStartTime() const;
    uint64_t GetUptimeSeconds() const;
    
    // Editor management
    void RegisterEditor(void* editorHandle, const std::string& filePath);
    void UnregisterEditor(void* editorHandle);
    std::string GetEditorFile(void* editorHandle) const;
    std::vector<void*> GetActiveEditors() const;
    
    // File management
    void OpenFile(const std::string& filePath);
    void CloseFile(const std::string& filePath);
    bool IsFileOpen(const std::string& filePath) const;
    std::vector<std::string> GetOpenFiles() const;
    std::vector<std::string> GetRecentFiles() const;
    
    // Memory tracking
    void UpdateMemoryStats();
    size_t GetCurrentMemoryUsage() const;
    size_t GetPeakMemoryUsage() const;
    
    // Request tracking
    void IncrementRequestCount();
    uint64_t GetTotalRequests() const;
    
    // Error tracking
    void IncrementErrorCount();
    uint64_t GetErrorCount() const;

private:
    GlobalContext();
    ~GlobalContext();
    GlobalContext(const GlobalContext&) = delete;
    GlobalContext& operator=(const GlobalContext&) = delete;
    
    std::string GenerateSessionId();
    
    // Thread safety
    mutable CRITICAL_SECTION m_cs;
    
    // State
    bool m_initialized;
    std::string m_sessionId;
    std::chrono::steady_clock::time_point m_sessionStartTime;
    
    // Editor tracking
    std::map<void*, std::string> m_activeEditors;
    
    // File tracking
    std::set<std::string> m_openFiles;
    std::deque<std::string> m_recentFiles;
    
    // Memory tracking
    std::atomic<size_t> m_currentMemoryBytes;
    std::atomic<size_t> m_peakMemoryBytes;
    
    // Request tracking
    std::atomic<uint64_t> m_totalRequestsProcessed;
    std::atomic<uint64_t> m_errorCount;
};
