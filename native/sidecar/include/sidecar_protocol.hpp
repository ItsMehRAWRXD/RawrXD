/**
 * RawrXD Native Sidecar Protocol
 * C++23 implementation for Win32 named pipe communication
 * 
 * This runs the agent orchestration loop outside of Node.js,
 * directly on the GPU with minimal overhead.
 */

#pragma once

#include <windows.h>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <json/json.hpp>

namespace rawrxd::sidecar {

using json = nlohmann::json;

// Message types matching TypeScript protocol
enum class MessageType : uint8_t {
    REQUEST = 0,
    RESPONSE = 1,
    EVENT = 2,
    ERROR = 3
};

// Agent actions
enum class AgentAction : uint8_t {
    PLAN = 0,
    EXECUTE = 1,
    STOP = 2,
    STATUS = 3,
    RAG_INDEX = 4,      // Index workspace for search
    RAG_SEARCH = 5,     // Semantic search
    RAG_CONTEXT = 6,  // Get context for agent
    SPEC_GENERATE = 7,  // Speculative coding - generate branches
    SPEC_TEST = 8,      // Speculative coding - test branches
    SPEC_APPLY = 9     // Speculative coding - apply winner
    SPEC_GENERATE = 7,  // Speculative coding - generate branches
    SPEC_TEST = 8,      // Speculative coding - test branches
    SPEC_APPLY = 9     // Speculative coding - apply winner
};

// Agent event types
enum class EventType : uint8_t {
    LOG = 0,
    STEP_START = 1,
    STEP_COMPLETE = 2,
    STEP_FAILED = 3,
    TASK_COMPLETE = 4
};

// Message header for binary protocol
#pragma pack(push, 1)
struct MessageHeader {
    uint32_t magic;      // 0x52415752 ('RAWR')
    uint32_t length;     // Payload length
    uint8_t version;     // Protocol version
    MessageType type;
    uint64_t timestamp;
    char id[32];         // Message ID
};
#pragma pack(pop)

// Context for agent requests
struct AgentContext {
    std::string filePath;
    std::string selection;
    std::string languageId;
    
    json toJson() const {
        return json{
            {"filePath", filePath},
            {"selection", selection},
            {"languageId", languageId}
        };
    }
    
    static AgentContext fromJson(const json& j) {
        AgentContext ctx;
        ctx.filePath = j.value("filePath", "");
        ctx.selection = j.value("selection", "");
        ctx.languageId = j.value("languageId", "");
        return ctx;
    }
};

// Agent request from extension
struct AgentRequest {
    AgentAction action;
    std::string goal;
    std::string taskId;
    AgentContext context;
    std::string query;           // For RAG search
    std::string workspacePath;   // For RAG index
    size_t maxResults{10};       // For RAG search
    size_t maxTokens{2048};      // For RAG context
    
    json toJson() const {
        json j{
            {"action", static_cast<int>(action)},
            {"goal", goal},
            {"taskId", taskId},
            {"context", context.toJson()},
            {"query", query},
            {"workspacePath", workspacePath},
            {"maxResults", maxResults},
            {"maxTokens", maxTokens}
        };
        return j;
    }
    
    static AgentRequest fromJson(const json& j) {
        AgentRequest req;
        req.action = static_cast<AgentAction>(j.value("action", 0));
        req.goal = j.value("goal", "");
        req.taskId = j.value("taskId", "");
        if (j.contains("context")) {
            req.context = AgentContext::fromJson(j["context"]);
        }
        req.query = j.value("query", "");
        req.workspacePath = j.value("workspacePath", "");
        req.maxResults = j.value("maxResults", 10);
        req.maxTokens = j.value("maxTokens", 2048);
        return req;
    }
};

// Agent response to extension
struct AgentResponse {
    std::string status;
    std::string taskId;
    json result;
    std::string error;
    
    json toJson() const {
        json j{
            {"status", status},
            {"taskId", taskId}
        };
        if (!result.is_null()) j["result"] = result;
        if (!error.empty()) j["error"] = error;
        return j;
    }
};

// Agent event for streaming updates
struct AgentEvent {
    EventType type;
    std::string taskId;
    std::string stepId;
    std::string message;
    json data;
    
    json toJson() const {
        return json{
            {"type", static_cast<int>(type)},
            {"taskId", taskId},
            {"stepId", stepId},
            {"message", message},
            {"data", data}
        };
    }
};

// Named Pipe Server for sidecar
class SidecarPipeServer {
public:
    using MessageHandler = std::function<void(const std::string& id, const json& payload)>;
    
    explicit SidecarPipeServer(std::string_view pipeName);
    ~SidecarPipeServer();
    
    // Non-copyable
    SidecarPipeServer(const SidecarPipeServer&) = delete;
    SidecarPipeServer& operator=(const SidecarPipeServer&) = delete;
    
    // Movable
    SidecarPipeServer(SidecarPipeServer&&) noexcept;
    SidecarPipeServer& operator=(SidecarPipeServer&&) noexcept;
    
    bool initialize();
    void shutdown();
    
    // Send message to extension
    bool sendResponse(std::string_view id, const json& payload);
    bool sendEvent(const AgentEvent& event);
    bool sendError(std::string_view id, std::string_view error);
    
    // Set handler for incoming requests
    void onRequest(MessageHandler handler);
    
    // Run message loop (blocking)
    void run();
    
    // Check if connected
    bool isConnected() const { return m_connected; }
    
private:
    std::string m_pipeName;
    HANDLE m_pipe{INVALID_HANDLE_VALUE};
    HANDLE m_stopEvent{nullptr};
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_running{false};
    MessageHandler m_requestHandler;
    
    bool createPipe();
    void handleClient();
    bool readMessage(std::string& outId, json& outPayload);
    bool writeMessage(MessageType type, std::string_view id, const json& payload);
};

// Sidecar orchestrator - runs agent logic natively
class SidecarOrchestrator {
public:
    SidecarOrchestrator();
    ~SidecarOrchestrator();
    
    bool initialize();
    void shutdown();
    
    // Agent actions
    json handlePlan(const AgentRequest& request);
    json handleExecute(const AgentRequest& request);
    json handleStop(const AgentRequest& request);
    json handleStatus(const AgentRequest& request);
    
    // RAG actions
    json handleRAGIndex(const AgentRequest& request);
    json handleRAGSearch(const AgentRequest& request);
    json handleRAGContext(const AgentRequest& request);
    
    // Speculative Coding actions
    json handleSpecGenerate(const AgentRequest& request);
    json handleSpecTest(const AgentRequest& request);
    json handleSpecApply(const AgentRequest& request);
    
    // Speculative Coding actions
    json handleSpecGenerate(const AgentRequest& request);
    json handleSpecTest(const AgentRequest& request);
    json handleSpecApply(const AgentRequest& request);
    
    // Event streaming
    using EventCallback = std::function<void(const AgentEvent&)>;
    void setEventCallback(EventCallback callback);
    
    // Run main loop
    void run();
    
private:
    std::unique_ptr<SidecarPipeServer> m_pipeServer;
    std::unique_ptr<rag::SovereignContextEngine> m_rag;
    std::unique_ptr<speculative::SpeculativeCodingEngine> m_specEngine;
    EventCallback m_eventCallback;
    std::atomic<bool> m_running{false};
    
    // Task management
    struct ActiveTask {
        std::string id;
        std::string goal;
        std::atomic<bool> cancelled{false};
    };
    std::unordered_map<std::string, std::unique_ptr<ActiveTask>> m_tasks;
    std::mutex m_tasksMutex;
    
    void emitEvent(const AgentEvent& event);
    void executeTask(ActiveTask* task);
};

} // namespace rawrxd::sidecar
