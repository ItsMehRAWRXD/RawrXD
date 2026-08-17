// ============================================================================
// native_agent.cpp — Native Agent Implementation
// ============================================================================
#include "native_agent.hpp"
#include <sstream>
#include <fstream>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <queue>
#include <condition_variable>

namespace RawrXD {

// Thread-safe request queue
struct AgentRequest {
    std::string prompt;
    std::string context;
    std::function<void(const std::string&)> callback;
    std::chrono::steady_clock::time_point timestamp;
    uint64_t requestId;
};

static std::mutex g_requestMutex;
static std::condition_variable g_requestCV;
static std::queue<AgentRequest> g_requestQueue;
static std::atomic<bool> g_agentRunning{false};
static std::atomic<uint64_t> g_requestCounter{0};
static std::thread g_workerThread;

NativeAgent::NativeAgent(CPUInferenceEngine* engine)
    : m_engine(engine)
    , m_deepThink(false)
    , m_deepResearch(false)
    , m_noRefusal(false)
    , m_autoCorrect(false)
    , m_maxMode(false)
    , m_languageContext("cpp")
    , m_initialized(false)
    , m_requestCount(0)
{
}

NativeAgent::~NativeAgent() {
    Shutdown();
}

bool NativeAgent::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return true;
    }
    
    // Initialize the inference engine if available
    if (m_engine) {
        if (!m_engine->Initialize()) {
            return false;
        }
    }
    
    // Start worker thread
    g_agentRunning.store(true);
    g_workerThread = std::thread(&NativeAgent::WorkerLoop, this);
    
    m_initialized = true;
    return true;
}

void NativeAgent::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) {
            return;
        }
        m_initialized = false;
    }
    
    // Signal worker thread to stop
    g_agentRunning.store(false);
    g_requestCV.notify_all();
    
    // Wait for worker thread
    if (g_workerThread.joinable()) {
        g_workerThread.join();
    }
    
    // Shutdown engine
    if (m_engine) {
        m_engine->Shutdown();
    }
}

bool NativeAgent::IsInitialized() const {
    return m_initialized;
}

uint64_t NativeAgent::SubmitRequest(const std::string& prompt, 
                                    const std::string& context,
                                    std::function<void(const std::string&)> callback) {
    if (!m_initialized) {
        return 0;
    }
    
    AgentRequest request;
    request.prompt = prompt;
    request.context = context;
    request.callback = callback;
    request.timestamp = std::chrono::steady_clock::now();
    request.requestId = ++g_requestCounter;
    
    {
        std::lock_guard<std::mutex> lock(g_requestMutex);
        g_requestQueue.push(request);
    }
    
    g_requestCV.notify_one();
    m_requestCount.fetch_add(1);
    
    return request.requestId;
}

bool NativeAgent::CancelRequest(uint64_t requestId) {
    std::lock_guard<std::mutex> lock(g_requestMutex);
    
    // Note: Can't easily remove from queue, so we'd need a cancellation flag
    // For now, return false to indicate request may still be processed
    return false;
}

void NativeAgent::SetDeepThink(bool enabled) {
    m_deepThink.store(enabled);
}

void NativeAgent::SetDeepResearch(bool enabled) {
    m_deepResearch.store(enabled);
}

void NativeAgent::SetNoRefusal(bool enabled) {
    m_noRefusal.store(enabled);
}

void NativeAgent::SetAutoCorrect(bool enabled) {
    m_autoCorrect.store(enabled);
}

void NativeAgent::SetMaxMode(bool enabled) {
    m_maxMode.store(enabled);
}

void NativeAgent::SetLanguageContext(const std::string& language) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_languageContext = language;
}

std::string NativeAgent::GetLanguageContext() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_languageContext;
}

AgentCapabilities NativeAgent::GetCapabilities() const {
    AgentCapabilities caps;
    caps.deepThink = m_deepThink.load();
    caps.deepResearch = m_deepResearch.load();
    caps.noRefusal = m_noRefusal.load();
    caps.autoCorrect = m_autoCorrect.load();
    caps.maxMode = m_maxMode.load();
    caps.hasInferenceEngine = (m_engine != nullptr);
    return caps;
}

AgentStatus NativeAgent::GetStatus() const {
    AgentStatus status;
    status.initialized = m_initialized;
    status.requestCount = m_requestCount.load();
    status.pendingRequests = GetPendingRequestCount();
    return status;
}

size_t NativeAgent::GetPendingRequestCount() const {
    std::lock_guard<std::mutex> lock(g_requestMutex);
    return g_requestQueue.size();
}

void NativeAgent::WorkerLoop() {
    while (g_agentRunning.load()) {
        AgentRequest request;
        
        {
            std::unique_lock<std::mutex> lock(g_requestMutex);
            g_requestCV.wait(lock, [] { return !g_requestQueue.empty() || !g_agentRunning.load(); });
            
            if (!g_agentRunning.load()) {
                break;
            }
            
            if (g_requestQueue.empty()) {
                continue;
            }
            
            request = g_requestQueue.front();
            g_requestQueue.pop();
        }
        
        // Process the request
        std::string response = ProcessRequestInternal(request);
        
        // Call callback if provided
        if (request.callback) {
            request.callback(response);
        }
    }
}

std::string NativeAgent::ProcessRequestInternal(const AgentRequest& request) {
    // Build the full prompt with context
    std::stringstream fullPrompt;
    
    if (!request.context.empty()) {
        fullPrompt << "Context: " << request.context << "\n\n";
    }
    
    fullPrompt << request.prompt;
    
    // Add mode modifiers
    if (m_deepThink.load()) {
        fullPrompt << "\n[Deep Think: Enabled]";
    }
    if (m_deepResearch.load()) {
        fullPrompt << "\n[Deep Research: Enabled]";
    }
    if (m_noRefusal.load()) {
        fullPrompt << "\n[No Refusal: Enabled]";
    }
    
    // Process through inference engine if available
    if (m_engine && m_engine->IsReady()) {
        return m_engine->Generate(fullPrompt.str());
    }
    
    // Fallback: return a placeholder response
    return "NativeAgent: Request processed (inference engine not available)";
}

} // namespace RawrXD
