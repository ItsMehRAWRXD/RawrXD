// VoiceAssistantWorker.cpp - Thread-safe voice processing dispatcher
// Offloads voice assistant processing to background threads
// ============================================================================

#include "VoiceAssistantWorker.hpp"
#include "../core/voice_assistant_manager.hpp"
#include "IDE_Telemetry.hpp"
#include <process.h>
#include <sstream>

// Enable telemetry for voice assistant profiling
#define RAWRXD_ENABLE_TELEMETRY

// Global worker instance
std::unique_ptr<VoiceAssistantWorker> g_voiceAssistantWorker;

// ============================================================================
// VoiceAssistantWorker Implementation
// ============================================================================

VoiceAssistantWorker::VoiceAssistantWorker()
    : m_manager(nullptr)
{
}

VoiceAssistantWorker::~VoiceAssistantWorker() {
    Shutdown();
}

void VoiceAssistantWorker::Initialize(VoiceAssistantManager* manager) {
    m_manager = manager;
}

unsigned int VoiceAssistantWorker::SubmitTask(const std::wstring& input,
                                               HWND hNotifyWnd,
                                               const std::string& assistantType,
                                               const std::string& sessionId) {
    PERF_SCOPE("VoiceWorker.SubmitTask");
    
    if (!m_manager || m_shuttingDown.load()) {
        return 0;
    }
    
    unsigned int taskId = m_nextTaskId.fetch_add(1);
    
    // Track active task count as queue depth metric
    size_t activeCount = GetActiveTaskCount();
    PERF_GAUGE("VoiceWorker.ActiveTasks", activeCount);
    
    // Create cancellation token
    auto cancelToken = std::make_shared<VoiceCancellationToken>();
    {
        std::lock_guard<std::mutex> lock(m_tokensMutex);
        m_activeTokens[taskId] = cancelToken;
    }
    
    // Allocate task structure
    VoiceTask* task = new VoiceTask();
    task->input = input;
    task->hNotifyWnd = hNotifyWnd;
    task->cancelToken = cancelToken;
    task->assistantType = assistantType;
    task->sessionId = sessionId;
    
    // Launch background thread
    uintptr_t threadHandle = _beginthreadex(nullptr, 0, &ProcessingThread, task, 0, nullptr);
    if (threadHandle == 0) {
        // Thread creation failed
        delete task;
        {
            std::lock_guard<std::mutex> lock(m_tokensMutex);
            m_activeTokens.erase(taskId);
        }
        return 0;
    }
    
    // Close thread handle (we don't need to wait)
    CloseHandle(reinterpret_cast<HANDLE>(threadHandle));
    
    return taskId;
}

// Phase 3: Submit semantic query task (RAG pipeline)
unsigned int VoiceAssistantWorker::SubmitSemanticQuery(const std::wstring& input,
                                                        HWND hNotifyWnd,
                                                        IntentType intent,
                                                        const std::string& filePath,
                                                        int lineNumber,
                                                        const std::string& sessionId) {
    PERF_SCOPE("VoiceWorker.SubmitSemanticQuery");
    
    if (!m_manager || m_shuttingDown.load()) {
        return 0;
    }
    
    unsigned int taskId = m_nextTaskId.fetch_add(1);
    
    // Create cancellation token
    auto cancelToken = std::make_shared<VoiceCancellationToken>();
    {
        std::lock_guard<std::mutex> lock(m_tokensMutex);
        m_activeTokens[taskId] = cancelToken;
    }
    
    // Allocate task structure with semantic query context
    VoiceTask* task = new VoiceTask();
    task->input = input;
    task->hNotifyWnd = hNotifyWnd;
    task->cancelToken = cancelToken;
    task->assistantType = "hybrid";  // Semantic queries always use hybrid
    task->sessionId = sessionId;
    task->intentType = intent;
    task->filePath = filePath;
    task->lineNumber = lineNumber;
    task->isSemanticQuery = true;
    
    // Launch background thread
    uintptr_t threadHandle = _beginthreadex(nullptr, 0, &ProcessingThread, task, 0, nullptr);
    if (threadHandle == 0) {
        delete task;
        {
            std::lock_guard<std::mutex> lock(m_tokensMutex);
            m_activeTokens.erase(taskId);
        }
        return 0;
    }
    
    CloseHandle(reinterpret_cast<HANDLE>(threadHandle));
    return taskId;
}

void VoiceAssistantWorker::CancelTask(unsigned int taskId) {
    std::lock_guard<std::mutex> lock(m_tokensMutex);
    auto it = m_activeTokens.find(taskId);
    if (it != m_activeTokens.end()) {
        it->second->cancel();
    }
}

void VoiceAssistantWorker::CancelAllTasks() {
    std::lock_guard<std::mutex> lock(m_tokensMutex);
    for (auto& pair : m_activeTokens) {
        pair.second->cancel();
    }
}

size_t VoiceAssistantWorker::GetActiveTaskCount() const {
    std::lock_guard<std::mutex> lock(m_tokensMutex);
    return m_activeTokens.size();
}

void VoiceAssistantWorker::Shutdown() {
    m_shuttingDown.store(true);
    CancelAllTasks();
    
    // Give threads time to complete (max 5 seconds)
    for (int i = 0; i < 50; ++i) {
        {
            std::lock_guard<std::mutex> lock(m_tokensMutex);
            if (m_activeTokens.empty()) break;
        }
        Sleep(100);
    }
    
    {
        std::lock_guard<std::mutex> lock(m_tokensMutex);
        m_activeTokens.clear();
    }
}

// ============================================================================
// Thread Procedure
// ============================================================================

unsigned __stdcall VoiceAssistantWorker::ProcessingThread(void* pArguments) {
    VoiceTask* task = static_cast<VoiceTask*>(pArguments);
    if (!task) {
        _endthreadex(1);
        return 1;
    }
    
    // Get the worker instance from global
    VoiceAssistantWorker* worker = g_voiceAssistantWorker.get();
    if (worker) {
        worker->ExecuteTask(task);
    }
    
    _endthreadex(0);
    return 0;
}

void VoiceAssistantWorker::ExecuteTask(VoiceTask* task) {
    if (!task || !m_manager) {
        delete task;
        return;
    }
    
    PERF_SCOPE("VoiceWorker.ExecuteTask");
    
    // Convert wide input to UTF-8 for processing
    std::string utf8Input;
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, task->input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded > 0) {
        utf8Input.resize(sizeNeeded - 1);
        WideCharToMultiByte(CP_UTF8, 0, task->input.c_str(), -1, &utf8Input[0], sizeNeeded, nullptr, nullptr);
    }
    
    // Check cancellation before processing
    if (task->cancelToken && task->cancelToken->is_cancelled()) {
        PostMessage(task->hNotifyWnd, WM_USER_VOICE_RESPONSE_READY, 
                    static_cast<WPARAM>(-1), reinterpret_cast<LPARAM>(nullptr));
        delete task;
        return;
    }
    
    nlohmann::json result;
    
    // Phase 3: Bifurcated Command Processing
    // Check if this is a semantic query (RAG) or legacy IDE action
    if (task->intentType == IntentType::CODE_EXPLAIN_SYMBOL ||
        task->intentType == IntentType::CODE_FIND_REFERENCES ||
        task->intentType == IntentType::CODE_GET_DEPENDENCIES ||
        task->intentType == IntentType::CODE_SUGGEST_FIX ||
        task->intentType == IntentType::CODE_ARCHITECTURE_QUERY) {
        
        // Route to RAG Pipeline
        PERF_SCOPE("VoiceWorker.RAG_Query");
        try {
            result = m_manager->query_codebase(utf8Input, task->filePath, task->lineNumber);
            result["success"] = true;
            result["response_type"] = "semantic";  // Mark as semantic result
            result["intent"] = VoiceAssistantUtils::intent_to_string(task->intentType);
        } catch (const std::exception& e) {
            result["success"] = false;
            result["error"] = e.what();
            result["response_type"] = "error";
        }
    } else {
        // Legacy IDE Action Handling
        PERF_SCOPE("VoiceWorker.Legacy_Action");
        try {
            result = m_manager->process_voice_input(utf8Input, task->assistantType, task->sessionId);
            result["success"] = true;
            result["response_type"] = "action";  // Mark as action result
        } catch (const std::exception& e) {
            result["success"] = false;
            result["error"] = e.what();
            result["response_type"] = "error";
        }
    }
    
    // Check cancellation after processing
    if (task->cancelToken && task->cancelToken->is_cancelled()) {
        PostMessage(task->hNotifyWnd, WM_USER_VOICE_RESPONSE_READY, 
                    static_cast<WPARAM>(-1), reinterpret_cast<LPARAM>(nullptr));
        delete task;
        return;
    }
    
    // Preserve original input and context for UI correlation
    result["user_input"] = utf8Input;
    result["file_path"] = task->filePath;
    result["line_number"] = task->lineNumber;
    
    // Serialize result to string for message passing
    std::string* responseData = new std::string(result.dump());
    
    // Notify UI thread with response
    PostMessage(task->hNotifyWnd, WM_USER_VOICE_RESPONSE_READY, 
                static_cast<WPARAM>(0), reinterpret_cast<LPARAM>(responseData));
    
    // Clean up task
    delete task;
}
