// VoiceAssistantWorker.hpp - Thread-safe voice processing dispatcher
// Offloads voice assistant processing to background threads to prevent UI blocking
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "../core/voice_assistant_manager.hpp"  // For IntentType enum

// Forward declaration
class VoiceAssistantManager;

// Custom window message for voice response completion
#ifndef WM_USER_VOICE_RESPONSE_READY
#define WM_USER_VOICE_RESPONSE_READY (WM_USER + 0x601)
#endif

// Cancellation token for aborting long-running voice operations
struct VoiceCancellationToken {
    std::atomic<bool> cancelled{false};
    void cancel() { cancelled.store(true, std::memory_order_relaxed); }
    bool is_cancelled() const { return cancelled.load(std::memory_order_relaxed); }
};

// Voice task context passed to worker thread
struct VoiceTask {
    std::wstring input;
    HWND hNotifyWnd;
    std::shared_ptr<VoiceCancellationToken> cancelToken;
    std::string assistantType;
    std::string sessionId;
    // Phase 3: RAG Semantic Query fields
    IntentType intentType;      // Intent classification for routing
    std::string filePath;       // Current file context for RAG
    int lineNumber;           // Current line for RAG context
    bool isSemanticQuery;       // Quick flag for RAG vs Action
    
    VoiceTask() : hNotifyWnd(nullptr), intentType(IntentType::UNKNOWN), 
                  lineNumber(0), isSemanticQuery(false) {}
};

// Voice Assistant Worker - Thread-safe dispatcher
class VoiceAssistantWorker {
public:
    VoiceAssistantWorker();
    ~VoiceAssistantWorker();
    
    // Initialize with voice assistant manager instance
    void Initialize(VoiceAssistantManager* manager);
    
    // Submit voice processing task (non-blocking, returns immediately)
    // Returns task ID that can be used for cancellation
    unsigned int SubmitTask(const std::wstring& input, 
                           HWND hNotifyWnd,
                           const std::string& assistantType = "hybrid",
                           const std::string& sessionId = "");
    
    // Phase 3: Submit semantic query task (RAG pipeline)
    // Routes to query_codebase for semantic code understanding
    unsigned int SubmitSemanticQuery(const std::wstring& input,
                                      HWND hNotifyWnd,
                                      IntentType intent,
                                      const std::string& filePath = "",
                                      int lineNumber = 0,
                                      const std::string& sessionId = "");
    
    // Cancel a pending or running task
    void CancelTask(unsigned int taskId);
    
    // Cancel all pending tasks
    void CancelAllTasks();
    
    // Check if worker is initialized
    bool IsInitialized() const { return m_manager != nullptr; }
    
    // Get active task count
    size_t GetActiveTaskCount() const;
    
    // Shutdown worker and wait for pending tasks
    void Shutdown();

private:
    VoiceAssistantManager* m_manager;
    std::atomic<unsigned int> m_nextTaskId{1};
    std::unordered_map<unsigned int, std::shared_ptr<VoiceCancellationToken>> m_activeTokens;
    mutable std::mutex m_tokensMutex;
    std::atomic<bool> m_shuttingDown{false};
    
    // Thread procedure
    static unsigned __stdcall ProcessingThread(void* pArguments);
    
    // Internal task execution
    void ExecuteTask(VoiceTask* task);
};

// Global worker instance (initialized by Win32IDE)
extern std::unique_ptr<VoiceAssistantWorker> g_voiceAssistantWorker;
