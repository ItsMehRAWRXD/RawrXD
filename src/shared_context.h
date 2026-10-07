#pragma once
#include <memory>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <chrono>

// Forward declarations to avoid pulling in heavy dependencies
class MemoryCore;
class HotPatcher;
class VSIXLoader;

struct SessionInfo {
    std::string id;
    std::string targetPath;
    std::chrono::steady_clock::time_point startTime;
    uint64_t iterationsCompleted{0};
    uint64_t findingsTotal{0};
    uint64_t changesApplied{0};
    bool converged{false};
};

struct EditorState {
    std::string activeFilePath;
    std::string activeFileContent;
    int cursorLine{0};
    int cursorColumn{0};
    bool modified{false};
};

struct MemoryMetrics {
    size_t totalAllocated{0};
    size_t peakAllocated{0};
    size_t contextTokens{0};
    size_t maxContextTokens{16384};
};

struct GlobalContext {
    // Core subsystems (opaque pointers to avoid header dependencies)
    void* memory;        // MemoryCore*
    void* patcher;        // HotPatcher*
    void* vsix_loader;    // VSIXLoader*

    std::atomic<uint64_t> requestCount{0};
    std::atomic<uint64_t> errorCount{0};
    std::atomic<bool> engineRunning{false};
    std::atomic<bool> cancelRequested{false};

    SessionInfo currentSession;
    EditorState editorState;
    MemoryMetrics memoryMetrics;

    static GlobalContext& Get();

    void beginSession(const std::string& targetPath) {
        std::lock_guard<std::mutex> lock(m_mutex);
        currentSession.id = "session_" + std::to_string(++m_sessionCounter);
        currentSession.targetPath = targetPath;
        currentSession.startTime = std::chrono::steady_clock::now();
        currentSession.iterationsCompleted = 0;
        currentSession.findingsTotal = 0;
        currentSession.changesApplied = 0;
        currentSession.converged = false;
        engineRunning.store(true);
        cancelRequested.store(false);
    }

    void endSession(bool converged) {
        std::lock_guard<std::mutex> lock(m_mutex);
        currentSession.converged = converged;
        engineRunning.store(false);
    }

    void updateProgress(uint64_t iterations, uint64_t findings, uint64_t changes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        currentSession.iterationsCompleted = iterations;
        currentSession.findingsTotal = findings;
        currentSession.changesApplied = changes;
    }

    void updateEditorState(const std::string& path, const std::string& content,
                           int line, int col, bool modified) {
        std::lock_guard<std::mutex> lock(m_mutex);
        editorState.activeFilePath = path;
        editorState.activeFileContent = content;
        editorState.cursorLine = line;
        editorState.cursorColumn = col;
        editorState.modified = modified;
    }

    void updateMemoryMetrics(size_t allocated, size_t contextTokens) {
        std::lock_guard<std::mutex> lock(m_mutex);
        memoryMetrics.totalAllocated = allocated;
        if (allocated > memoryMetrics.peakAllocated) memoryMetrics.peakAllocated = allocated;
        memoryMetrics.contextTokens = contextTokens;
    }

    void incrementRequestCount() { requestCount.fetch_add(1, std::memory_order_relaxed); }
    void incrementErrorCount() { errorCount.fetch_add(1, std::memory_order_relaxed); }
    void requestCancel() { cancelRequested.store(true); }
    bool isCancelRequested() const { return cancelRequested.load(std::memory_order_relaxed); }
    bool isEngineRunning() const { return engineRunning.load(std::memory_order_relaxed); }

    uint64_t getSessionDurationMs() const {
        if (!engineRunning.load()) return 0;
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - currentSession.startTime).count());
    }

    std::string getStatusString() const {
        return "session=" + currentSession.id +
               " iterations=" + std::to_string(currentSession.iterationsCompleted) +
               " findings=" + std::to_string(currentSession.findingsTotal) +
               " changes=" + std::to_string(currentSession.changesApplied) +
               " requests=" + std::to_string(requestCount.load()) +
               " errors=" + std::to_string(errorCount.load());
    }

private:
    mutable std::mutex m_mutex;
    static std::atomic<uint64_t> m_sessionCounter;
};
