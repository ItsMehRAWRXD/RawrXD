/**
 * RawrXD Native Sidecar Implementation
 * C++23 Win32 named pipe server for agent orchestration
 */

#include "sidecar_protocol.hpp"
#include "sovereign_context.hpp"
#include "speculative_coding.hpp"
#include <iostream>
#include <thread>
#include <chrono>

namespace rawrxd::sidecar {

// Magic number for protocol validation
constexpr uint32_t PROTOCOL_MAGIC = 0x52415752; // 'RAWR'
constexpr uint8_t PROTOCOL_VERSION = 1;

SidecarPipeServer::SidecarPipeServer(std::string_view pipeName) 
    : m_pipeName(pipeName.empty() ? "\\\\.\\pipe\\RawrXD_Agent_Sidecar" : pipeName) {
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

SidecarPipeServer::~SidecarPipeServer() {
    shutdown();
    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
    }
}

SidecarPipeServer::SidecarPipeServer(SidecarPipeServer&& other) noexcept
    : m_pipeName(std::move(other.m_pipeName))
    , m_pipe(other.m_pipe)
    , m_stopEvent(other.m_stopEvent)
    , m_connected(other.m_connected.load())
    , m_running(other.m_running.load())
    , m_requestHandler(std::move(other.m_requestHandler)) {
    other.m_pipe = INVALID_HANDLE_VALUE;
    other.m_stopEvent = nullptr;
}

SidecarPipeServer& SidecarPipeServer::operator=(SidecarPipeServer&& other) noexcept {
    if (this != &other) {
        shutdown();
        m_pipeName = std::move(other.m_pipeName);
        m_pipe = other.m_pipe;
        m_stopEvent = other.m_stopEvent;
        m_connected = other.m_connected.load();
        m_running = other.m_running.load();
        m_requestHandler = std::move(other.m_requestHandler);
        other.m_pipe = INVALID_HANDLE_VALUE;
        other.m_stopEvent = nullptr;
    }
    return *this;
}

bool SidecarPipeServer::initialize() {
    std::cout << "[RawrXD Sidecar] Initializing named pipe server..." << std::endl;
    return createPipe();
}

void SidecarPipeServer::shutdown() {
    m_running = false;
    SetEvent(m_stopEvent);
    
    if (m_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(m_pipe);
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
    
    m_connected = false;
}

bool SidecarPipeServer::createPipe() {
    m_pipe = CreateNamedPipeA(
        m_pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, // Max instances
        65536, // Out buffer
        65536, // In buffer
        0, // Default timeout
        nullptr // Security attributes
    );
    
    if (m_pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "[RawrXD Sidecar] Failed to create pipe: " << GetLastError() << std::endl;
        return false;
    }
    
    std::cout << "[RawrXD Sidecar] Pipe created: " << m_pipeName << std::endl;
    return true;
}

void SidecarPipeServer::run() {
    m_running = true;
    std::cout << "[RawrXD Sidecar] Waiting for VSCode extension connection..." << std::endl;
    
    while (m_running) {
        // Wait for client connection
        BOOL connected = ConnectNamedPipe(m_pipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::cerr << "[RawrXD Sidecar] Connection failed: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        m_connected = true;
        std::cout << "[RawrXD Sidecar] VSCode extension connected" << std::endl;
        
        // Handle client
        handleClient();
        
        // Disconnect
        DisconnectNamedPipe(m_pipe);
        m_connected = false;
    }
}

void SidecarPipeServer::handleClient() {
    while (m_connected && m_running) {
        std::string id;
        json payload;
        
        if (!readMessage(id, payload)) {
            break;
        }
        
        if (m_requestHandler) {
            m_requestHandler(id, payload);
        }
    }
}

bool SidecarPipeServer::readMessage(std::string& outId, json& outPayload) {
    MessageHeader header;
    DWORD bytesRead;
    
    // Read header
    BOOL success = ReadFile(m_pipe, &header, sizeof(header), &bytesRead, nullptr);
    if (!success || bytesRead != sizeof(header)) {
        return false;
    }
    
    // Validate header
    if (header.magic != PROTOCOL_MAGIC) {
        std::cerr << "[RawrXD Sidecar] Invalid magic number" << std::endl;
        return false;
    }
    
    if (header.version != PROTOCOL_VERSION) {
        std::cerr << "[RawrXD Sidecar] Protocol version mismatch" << std::endl;
        return false;
    }
    
    // Read payload
    std::vector<char> payloadBuffer(header.length + 1, '\0');
    success = ReadFile(m_pipe, payloadBuffer.data(), header.length, &bytesRead, nullptr);
    if (!success || bytesRead != header.length) {
        return false;
    }
    
    // Parse JSON
    try {
        outPayload = json::parse(payloadBuffer.data());
        outId = header.id;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[RawrXD Sidecar] JSON parse error: " << e.what() << std::endl;
        return false;
    }
}

bool SidecarPipeServer::writeMessage(MessageType type, std::string_view id, const json& payload) {
    if (!m_connected) return false;
    
    MessageHeader header;
    header.magic = PROTOCOL_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = type;
    header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    // Copy ID (truncate if needed)
    std::fill_n(header.id, sizeof(header.id), '\0');
    std::copy_n(id.data(), std::min(id.size(), sizeof(header.id) - 1), header.id);
    
    // Serialize payload
    std::string payloadStr = payload.dump();
    header.length = static_cast<uint32_t>(payloadStr.length());
    
    // Write header
    DWORD bytesWritten;
    BOOL success = WriteFile(m_pipe, &header, sizeof(header), &bytesWritten, nullptr);
    if (!success || bytesWritten != sizeof(header)) {
        return false;
    }
    
    // Write payload
    success = WriteFile(m_pipe, payloadStr.data(), header.length, &bytesWritten, nullptr);
    return success && bytesWritten == header.length;
}

bool SidecarPipeServer::sendResponse(std::string_view id, const json& payload) {
    return writeMessage(MessageType::RESPONSE, id, payload);
}

bool SidecarPipeServer::sendEvent(const AgentEvent& event) {
    return writeMessage(MessageType::EVENT, "event", event.toJson());
}

bool SidecarPipeServer::sendError(std::string_view id, std::string_view error) {
    json payload = {{"error", std::string(error)}};
    return writeMessage(MessageType::ERROR, id, payload);
}

void SidecarPipeServer::onRequest(MessageHandler handler) {
    m_requestHandler = std::move(handler);
}

// SidecarOrchestrator implementation
SidecarOrchestrator::SidecarOrchestrator() = default;
SidecarOrchestrator::~SidecarOrchestrator() = default;

bool SidecarOrchestrator::initialize() {
    std::cout << "[RawrXD Sidecar] Initializing orchestrator..." << std::endl;
    
    m_pipeServer = std::make_unique<SidecarPipeServer>();
    
    if (!m_pipeServer->initialize()) {
        std::cerr << "[RawrXD Sidecar] Failed to initialize pipe server" << std::endl;
        return false;
    }
    
    // Initialize RAG engine
    std::cout << "[RawrXD Sidecar] Initializing RAG engine..." << std::endl;
    m_rag = std::make_unique<rag::SovereignContextEngine>(
        std::filesystem::temp_directory_path() / "rawrxd_rag"
    );
    
    if (!m_rag->initialize()) {
        std::cerr << "[RawrXD Sidecar] Failed to initialize RAG engine" << std::endl;
        // Continue without RAG
    } else {
        std::cout << "[RawrXD Sidecar] RAG engine initialized" << std::endl;
    }
    
    // Initialize Speculative Coding Engine
    std::cout << "[RawrXD Sidecar] Initializing Speculative Coding Engine..." << std::endl;
    m_specEngine = std::make_unique<speculative::SpeculativeCodingEngine>();
    
    // Set up callbacks
    m_specEngine->setGenerationCallback([this](std::string_view prompt, std::string_view context, 
                                              float temperature, size_t maxTokens) -> std::string {
        // TODO: Integrate with actual LLM
        return "// Generated code placeholder\n";
    });
    
    std::cout << "[RawrXD Sidecar] Speculative Coding Engine initialized" << std::endl;
    
    // Set up request handler
    m_pipeServer->onRequest([this](const std::string& id, const json& payload) {
        this->handleRequest(id, payload);
    });
    
    return true;
}

void SidecarOrchestrator::shutdown() {
    m_running = false;
    if (m_pipeServer) {
        m_pipeServer->shutdown();
    }
}

void SidecarOrchestrator::run() {
    m_running = true;
    std::cout << "[RawrXD Sidecar] Orchestrator running" << std::endl;
    
    if (m_pipeServer) {
        m_pipeServer->run();
    }
}

void SidecarOrchestrator::handleRequest(const std::string& id, const json& payload) {
    try {
        AgentRequest request = AgentRequest::fromJson(payload);
        json response;
        
        switch (request.action) {
            case AgentAction::PLAN:
                response = handlePlan(request);
                break;
            case AgentAction::EXECUTE:
                response = handleExecute(request);
                break;
            case AgentAction::STOP:
                response = handleStop(request);
                break;
            case AgentAction::STATUS:
                response = handleStatus(request);
                break;
            case AgentAction::RAG_INDEX:
                response = handleRAGIndex(request);
                break;
            case AgentAction::RAG_SEARCH:
                response = handleRAGSearch(request);
                break;
            case AgentAction::RAG_CONTEXT:
                response = handleRAGContext(request);
                break;
            default:
                response = {{"error", "Unknown action"}};
        }
        
        if (m_pipeServer) {
            m_pipeServer->sendResponse(id, response);
        }
    } catch (const std::exception& e) {
        std::cerr << "[RawrXD Sidecar] Request handler error: " << e.what() << std::endl;
        if (m_pipeServer) {
            m_pipeServer->sendError(id, e.what());
        }
    }
}

json SidecarOrchestrator::handlePlan(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] Planning task: " <> request.goal << std::endl;
    
    // Emit planning event
    emitEvent(AgentEvent{
        EventType::LOG,
        request.taskId,
        "",
        "Analyzing and planning...",
        {}
    });
    
    // Create plan based on goal
    json plan = {
        {"reasoning", "Native planning from sidecar"},
        {"tasks", json::array()}
    };
    
    // Simple task generation based on keywords
    std::string goalLower = request.goal;
    std::transform(goalLower.begin(), goalLower.end(), goalLower.begin(), ::tolower);
    
    if (goalLower.find("fix") != std::string::npos) {
        plan["tasks"].push_back({
            {"id", "task-1"},
            {"description", "Diagnose errors"},
            {"steps", json::array({
                {{"id", "s1"}, {"description", "Check build errors"}, {"type", "command"}},
                {{"id", "s2"}, {"description", "Analyze error patterns"}, {"type", "plan"}}
            })}
        });
        plan["tasks"].push_back({
            {"id", "task-2"},
            {"description", "Apply fixes"},
            {"steps", json::array({
                {{"id", "s3"}, {"description", "Generate patches"}, {"type", "edit"}},
                {{"id", "s4"}, {"description", "Apply edits"}, {"type", "edit"}}
            })}
        });
    } else {
        plan["tasks"].push_back({
            {"id", "task-1"},
            {"description", request.goal},
            {"steps", json::array({
                {{"id", "s1"}, {"description", "Analyze codebase"}, {"type", "plan"}},
                {{"id", "s2"}, {"description", "Execute changes"}, {"type", "edit"}},
                {{"id", "s3"}, {"description", "Verify result"}, {"type", "verify"}}
            })}
        });
    }
    
    return {{"status", "success"}, {"plan", plan}};
}

json SidecarOrchestrator::handleExecute(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] Executing task: " <> request.taskId << std::endl;
    
    // Create active task
    auto task = std::make_unique<ActiveTask>();
    task->id = request.taskId;
    task->goal = request.goal;
    
    {
        std::lock_guard<std::mutex> lock(m_tasksMutex);
        m_tasks[request.taskId] = std::move(task);
    }
    
    // Execute in background thread
    std::thread([this, taskId = request.taskId]() {
        auto it = m_tasks.find(taskId);
        if (it != m_tasks.end()) {
            this->executeTask(it->second.get());
        }
    }).detach();
    
    return {{"status", "started"}, {"taskId", request.taskId}};
}

json SidecarOrchestrator::handleStop(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] Stopping task: " <> request.taskId << std::endl;
    
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    auto it = m_tasks.find(request.taskId);
    if (it != m_tasks.end()) {
        it->second->cancelled = true;
        m_tasks.erase(it);
        return {{"status", "stopped"}, {"taskId", request.taskId}};
    }
    
    return {{"status", "error"}, {"message", "Task not found"}};
}

json SidecarOrchestrator::handleStatus(const AgentRequest& request) {
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    
    json tasks = json::array();
    for (const auto& [id, task] : m_tasks) {
        tasks.push_back({
            {"id", task->id},
            {"goal", task->goal},
            {"cancelled", task->cancelled.load()}
        });
    }
    
    return {{"status", "success"}, {"tasks", tasks}, {"activeCount", m_tasks.size()}};
}

// RAG Handlers
json SidecarOrchestrator::handleRAGIndex(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] RAG Index: " << request.workspacePath << std::endl;
    
    if (!m_rag) {
        return {{"status", "error"}, {"message", "RAG not initialized"}};
    }
    
    try {
        m_rag->indexWorkspace(request.workspacePath);
        m_rag->saveIndex();
        
        auto stats = m_rag->getStats();
        return {
            {"status", "success"},
            {"documentsIndexed", stats.documentCount},
            {"indexSizeMB", stats.indexSizeMB}
        };
    } catch (const std::exception& e) {
        return {{"status", "error"}, {"message", e.what()}};
    }
}

json SidecarOrchestrator::handleRAGSearch(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] RAG Search: " << request.query << std::endl;
    
    if (!m_rag) {
        return {{"status", "error"}, {"message", "RAG not initialized"}};
    }
    
    try {
        auto results = m_rag->search(request.query, request.maxResults);
        
        json resultsJson = json::array();
        for (const auto& result : results) {
            resultsJson.push_back({
                {"docId", result.docId},
                {"score", result.score},
                {"document", {
                    {"id", result.document.id},
                    {"filePath", result.document.filePath},
                    {"lineStart", result.document.lineStart},
                    {"lineEnd", result.document.lineEnd},
                    {"content", result.document.content}
                }}
            });
        }
        
        return {
            {"status", "success"},
            {"results", resultsJson},
            {"count", results.size()}
        };
    } catch (const std::exception& e) {
        return {{"status", "error"}, {"message", e.what()}};
    }
}

json SidecarOrchestrator::handleRAGContext(const AgentRequest& request) {
    std::cout << "[RawrXD Sidecar] RAG Context for: " << request.query << std::endl;
    
    if (!m_rag) {
        return {{"status", "error"}, {"message", "RAG not initialized"}};
    }
    
    try {
        std::string context = m_rag->getAgentContext(
            request.query,
            request.context.filePath,
            request.maxTokens
        );
        
        return {
            {"status", "success"},
            {"context", context},
            {"tokens", context.size() / 4}  // Rough estimate
        };
    } catch (const std::exception& e) {
        return {{"status", "error"}, {"message", e.what()}};
    }
}

void SidecarOrchestrator::executeTask(ActiveTask* task) {
    emitEvent(AgentEvent{
        EventType::STEP_START,
        task->id,
        "step-1",
        "Starting execution",
        {}
    });
    
    // Simulate work
    for (int i = 0; i < 5 && !task->cancelled; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        emitEvent(AgentEvent{
            EventType::LOG,
            task->id,
            "",
            "Processing step " + std::to_string(i + 1) + "/5",
            {{"progress", (i + 1) * 20}}
        });
    }
    
    if (!task->cancelled) {
        emitEvent(AgentEvent{
            EventType::TASK_COMPLETE,
            task->id,
            "",
            "Task completed successfully",
            {}
        });
    }
    
    // Remove from active tasks
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    m_tasks.erase(task->id);
}

void SidecarOrchestrator::emitEvent(const AgentEvent& event) {
    if (m_eventCallback) {
        m_eventCallback(event);
    }
    
    if (m_pipeServer) {
        m_pipeServer->sendEvent(event);
    }
}

void SidecarOrchestrator::setEventCallback(EventCallback callback) {
    m_eventCallback = std::move(callback);
}

} // namespace rawrxd::sidecar

// Entry point
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  RawrXD Native Sidecar v1.0" << std::endl;
    std::cout << "  C++23 / Win32 / Zero Node.js" << std::endl;
    std::cout << "========================================" << std::endl;
    
    rawrxd::sidecar::SidecarOrchestrator orchestrator;
    
    if (!orchestrator.initialize()) {
        std::cerr << "[RawrXD Sidecar] Initialization failed" << std::endl;
        return 1;
    }
    
    orchestrator.run();
    
    return 0;
}
