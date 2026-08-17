// ============================================================================
// native_agent.hpp — Native Agent Interface
// ============================================================================
#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <mutex>

namespace RawrXD {

// Forward declaration
class CPUInferenceEngine;

// Agent capabilities structure
struct AgentCapabilities {
    bool deepThink;
    bool deepResearch;
    bool noRefusal;
    bool autoCorrect;
    bool maxMode;
    bool hasInferenceEngine;
};

// Agent status structure
struct AgentStatus {
    bool initialized;
    uint64_t requestCount;
    size_t pendingRequests;
};

// Agent request structure
struct AgentRequest;

// NativeAgent class - AI agent with local inference capabilities
class NativeAgent {
public:
    explicit NativeAgent(CPUInferenceEngine* engine = nullptr);
    ~NativeAgent();
    
    // Non-copyable
    NativeAgent(const NativeAgent&) = delete;
    NativeAgent& operator=(const NativeAgent&) = delete;
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Request handling
    uint64_t SubmitRequest(const std::string& prompt, 
                          const std::string& context = "",
                          std::function<void(const std::string&)> callback = nullptr);
    bool CancelRequest(uint64_t requestId);
    
    // Configuration
    void SetDeepThink(bool enabled);
    void SetDeepResearch(bool enabled);
    void SetNoRefusal(bool enabled);
    void SetAutoCorrect(bool enabled);
    void SetMaxMode(bool enabled);
    void SetLanguageContext(const std::string& language);
    std::string GetLanguageContext() const;
    
    // Status
    AgentCapabilities GetCapabilities() const;
    AgentStatus GetStatus() const;
    size_t GetPendingRequestCount() const;
    
private:
    void WorkerLoop();
    std::string ProcessRequestInternal(const AgentRequest& request);
    
    CPUInferenceEngine* m_engine;
    
    // Configuration flags
    std::atomic<bool> m_deepThink;
    std::atomic<bool> m_deepResearch;
    std::atomic<bool> m_noRefusal;
    std::atomic<bool> m_autoCorrect;
    std::atomic<bool> m_maxMode;
    
    // State
    std::string m_languageContext;
    mutable std::mutex m_mutex;
    bool m_initialized;
    std::atomic<uint64_t> m_requestCount;
};

// CPU Inference Engine interface (placeholder)
class CPUInferenceEngine {
public:
    virtual ~CPUInferenceEngine() = default;
    virtual bool Initialize() { return true; }
    virtual void Shutdown() {}
    virtual bool IsReady() const { return false; }
    virtual std::string Generate(const std::string& prompt) { return ""; }
};

} // namespace RawrXD
