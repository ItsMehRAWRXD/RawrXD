//=============================================================================
// GhostText_MCP_Bridge.cpp
// RawrXD IDE - GhostText to MCP Integration Bridge Implementation
//=============================================================================

#include "GhostText_MCP_Bridge.h"
#include "GhostTextIntegration_Wiring.h"
#include "../mcp/MCP_Transport_Native.h"
#include <windows.h>
#include <future>
#include <queue>
#include <mutex>

namespace RawrXD {
namespace IDE {

//=============================================================================
// Private Implementation
//=============================================================================

class GhostTextMCPBridge::Impl {
public:
    HMCPTransport m_hTransport = nullptr;
    GhostTextEngine* m_pEngine = nullptr;
    
    std::wstring m_serverUrl;
    std::wstring m_authToken;
    
    std::vector<MCPTool> m_availableTools;
    std::mutex m_toolsMutex;
    
    std::atomic<bool> m_isStreaming{false};
    std::atomic<bool> m_isConnected{false};
    
    // Callbacks
    std::function<void(bool)> m_onConnectionStateChanged;
    std::function<void(const std::vector<MCPTool>&)> m_onToolsChanged;
    std::function<void(const std::string&)> m_onError;
    std::function<void(const std::string&)> m_onStreamingToken;
    
    // Async task queue
    std::queue<std::packaged_task<void()>> m_taskQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    std::thread m_workerThread;
    std::atomic<bool> m_stopWorker{false};
    
    Impl() {
        m_workerThread = std::thread(&Impl::WorkerLoop, this);
    }
    
    ~Impl() {
        m_stopWorker = true;
        m_queueCV.notify_all();
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
        
        if (m_hTransport) {
            MCP_Transport_Destroy(m_hTransport);
        }
    }
    
    void WorkerLoop() {
        while (!m_stopWorker) {
            std::packaged_task<void()> task;
            {
                std::unique_lock<std::mutex> lock(m_queueMutex);
                m_queueCV.wait(lock, [this] { 
                    return !m_taskQueue.empty() || m_stopWorker; 
                });
                
                if (m_stopWorker) break;
                
                task = std::move(m_taskQueue.front());
                m_taskQueue.pop();
            }
            task();
        }
    }
    
    void EnqueueTask(std::packaged_task<void()>&& task) {
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_taskQueue.push(std::move(task));
        }
        m_queueCV.notify_one();
    }
    
    // Static callbacks
    static void CALLBACK OnConnect(void* pUserData, const wchar_t* pUrl) {
        auto* pImpl = static_cast<Impl*>(pUserData);
        pImpl->m_isConnected = true;
        if (pImpl->m_onConnectionStateChanged) {
            pImpl->m_onConnectionStateChanged(true);
        }
        
        // Discover tools after connection
        pImpl->DiscoverToolsInternal();
    }
    
    static void CALLBACK OnDisconnect(void* pUserData, DWORD dwReason) {
        auto* pImpl = static_cast<Impl*>(pUserData);
        pImpl->m_isConnected = false;
        if (pImpl->m_onConnectionStateChanged) {
            pImpl->m_onConnectionStateChanged(false);
        }
    }
    
    static BOOL CALLBACK OnError(void* pUserData, DWORD dwError, 
                                   const char* pMsg, DWORD dwLen) {
        auto* pImpl = static_cast<Impl*>(pUserData);
        if (pImpl->m_onError) {
            pImpl->m_onError(std::string(pMsg, dwLen));
        }
        return FALSE;  // Don't auto-reconnect
    }
    
    static BOOL CALLBACK OnMessage(void* pUserData, const char* pMessage,
                                   DWORD dwLength, DWORD dwId) {
        // Handle JSON-RPC responses
        auto* pImpl = static_cast<Impl*>(pUserData);
        // TODO: Route to pending request handlers
        return TRUE;
    }
    
    static BOOL CALLBACK OnSSE(void* pUserData, const wchar_t* pType,
                                  const wchar_t* pId, const char* pData,
                                  DWORD dwLen, DWORD dwRetry) {
        auto* pImpl = static_cast<Impl*>(pUserData);
        
        std::string eventType(pType);
        std::string data(pData, dwLen);
        
        if (eventType == "message" && pImpl->m_onStreamingToken) {
            // Parse SSE data for completion tokens
            // Format: data: {"text": "token"}
            try {
                auto json = nlohmann::json::parse(data);
                if (json.contains("text")) {
                    pImpl->m_onStreamingToken(json["text"].get<std::string>());
                }
            } catch (...) {
                // Raw token
                pImpl->m_onStreamingToken(data);
            }
        }
        
        return TRUE;
    }
    
    void DiscoverToolsInternal() {
        if (!m_hTransport) return;
        
        // Build JSON-RPC request for tools/list
        nlohmann::json request = {
            {"jsonrpc", "2.0"},
            {"method", "tools/list"},
            {"params", {}},
            {"id", 1}
        };
        
        std::string requestBody = request.dump();
        char* pResponse = nullptr;
        DWORD responseLen = 0;
        
        if (MCP_Transport_SendRequest(m_hTransport, requestBody.c_str(),
                                       requestBody.length(), &pResponse,
                                       &responseLen, 30000)) {
            try {
                auto response = nlohmann::json::parse(pResponse, 
                                                        pResponse + responseLen);
                if (response.contains("result") && 
                    response["result"].contains("tools")) {
                    std::lock_guard<std::mutex> lock(m_toolsMutex);
                    m_availableTools.clear();
                    
                    for (const auto& tool : response["result"]["tools"]) {
                        MCPTool mcpTool;
                        mcpTool.name = tool.value("name", "");
                        mcpTool.description = tool.value("description", "");
                        if (tool.contains("inputSchema")) {
                            mcpTool.inputSchema = tool["inputSchema"];
                        }
                        mcpTool.isAvailable = true;
                        m_availableTools.push_back(mcpTool);
                    }
                    
                    if (m_onToolsChanged) {
                        m_onToolsChanged(m_availableTools);
                    }
                }
            } catch (...) {
                // Parse error
            }
            
            HANDLE hHeap = GetProcessHeap();
            HeapFree(hHeap, 0, pResponse);
        }
    }
};

//=============================================================================
// GhostTextMCPBridge Implementation
//=============================================================================

GhostTextMCPBridge::GhostTextMCPBridge()
    : m_pImpl(std::make_unique<Impl>())
{
}

GhostTextMCPBridge::~GhostTextMCPBridge() = default;

GhostTextMCPBridge::GhostTextMCPBridge(GhostTextMCPBridge&&) noexcept = default;
GhostTextMCPBridge& GhostTextMCPBridge::operator=(GhostTextMCPBridge&&) noexcept = default;

bool GhostTextMCPBridge::Initialize(const std::wstring& serverUrl,
                                     const std::wstring& authToken)
{
    m_pImpl->m_serverUrl = serverUrl;
    m_pImpl->m_authToken = authToken;
    
    // Create transport
    m_pImpl->m_hTransport = MCP_Transport_Create(serverUrl.c_str(), m_pImpl.get());
    if (!m_pImpl->m_hTransport) {
        return false;
    }
    
    // Register callbacks
    MCP_Transport_SetCallback(m_pImpl->m_hTransport, MCP_CALLBACK_CONNECT,
                               Impl::OnConnect);
    MCP_Transport_SetCallback(m_pImpl->m_hTransport, MCP_CALLBACK_DISCONNECT,
                               Impl::OnDisconnect);
    MCP_Transport_SetCallback(m_pImpl->m_hTransport, MCP_CALLBACK_ERROR,
                               Impl::OnError);
    MCP_Transport_SetCallback(m_pImpl->m_hTransport, MCP_CALLBACK_MESSAGE,
                               Impl::OnMessage);
    MCP_Transport_SetCallback(m_pImpl->m_hTransport, MCP_CALLBACK_SSE,
                               Impl::OnSSE);
    
    // Enable SSE
    MCP_Transport_EnableSSE(m_pImpl->m_hTransport, TRUE);
    
    // Connect
    return MCP_Transport_Connect(m_pImpl->m_hTransport) != FALSE;
}

void GhostTextMCPBridge::Shutdown()
{
    if (m_pImpl->m_hTransport) {
        MCP_Transport_Disconnect(m_pImpl->m_hTransport);
    }
}

bool GhostTextMCPBridge::IsConnected() const
{
    return m_pImpl->m_isConnected.load();
}

void GhostTextMCPBridge::AttachToEngine(GhostTextEngine* pEngine)
{
    m_pImpl->m_pEngine = pEngine;
}

void GhostTextMCPBridge::DetachFromEngine()
{
    m_pImpl->m_pEngine = nullptr;
}

GhostTextEngine* GhostTextMCPBridge::GetAttachedEngine() const
{
    return m_pImpl->m_pEngine;
}

std::vector<MCPTool> GhostTextMCPBridge::DiscoverTools()
{
    std::lock_guard<std::mutex> lock(m_pImpl->m_toolsMutex);
    return m_pImpl->m_availableTools;
}

MCPToolResult GhostTextMCPBridge::CallTool(const std::string& toolName,
                                            const nlohmann::json& arguments,
                                            DWORD timeoutMs)
{
    MCPToolResult result;
    
    if (!m_pImpl->m_hTransport || !m_pImpl->m_isConnected) {
        result.errorMessage = "Not connected to MCP server";
        return result;
    }
    
    // Build JSON-RPC request
    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "tools/call"},
        {"params", {
            {"name", toolName},
            {"arguments", arguments}
        }},
        {"id", 1}
    };
    
    std::string requestBody = request.dump();
    char* pResponse = nullptr;
    DWORD responseLen = 0;
    
    auto startTime = GetTickCount64();
    
    if (MCP_Transport_SendRequest(m_pImpl->m_hTransport, requestBody.c_str(),
                                   requestBody.length(), &pResponse,
                                   &responseLen, timeoutMs)) {
        result.executionTimeMs = static_cast<DWORD>(GetTickCount64() - startTime);
        
        try {
            auto response = nlohmann::json::parse(pResponse, pResponse + responseLen);
            
            if (response.contains("error")) {
                result.success = false;
                result.errorMessage = response["error"].dump();
            } else if (response.contains("result")) {
                result.success = true;
                result.result = response["result"];
            }
        } catch (const std::exception& e) {
            result.errorMessage = std::string("Parse error: ") + e.what();
        }
        
        HANDLE hHeap = GetProcessHeap();
        HeapFree(hHeap, 0, pResponse);
    } else {
        result.errorMessage = "Request failed or timed out";
    }
    
    return result;
}

void GhostTextMCPBridge::CallToolAsync(const std::string& toolName,
                                        const nlohmann::json& arguments,
                                        std::function<void(const MCPToolResult&)> callback)
{
    std::packaged_task<void()> task([this, toolName, arguments, callback]() {
        auto result = CallTool(toolName, arguments);
        callback(result);
    });
    
    m_pImpl->EnqueueTask(std::move(task));
}

nlohmann::json GhostTextMCPBridge::EnhanceContext(const std::wstring& documentPath,
                                                   int cursorLine,
                                                   int cursorColumn)
{
    nlohmann::json context;
    
    // Add document info
    context["document"] = {
        {"path", std::string(documentPath.begin(), documentPath.end())},
        {"cursor", {{"line", cursorLine}, {"column", cursorColumn}}}
    };
    
    // Call MCP tools to gather additional context
    // Example: Get symbol definitions, file contents, etc.
    auto tools = DiscoverTools();
    
    for (const auto& tool : tools) {
        if (tool.name == "get_symbol_definitions" ||
            tool.name == "get_file_contents") {
            // Call tool to enhance context
            nlohmann::json args = {
                {"path", std::string(documentPath.begin(), documentPath.end())},
                {"line", cursorLine}
            };
            
            auto result = CallTool(tool.name, args, 5000);
            if (result.success) {
                context[tool.name] = result.result;
            }
        }
    }
    
    return context;
}

std::optional<GhostTextSuggestion> GhostTextMCPBridge::RequestCompletion(
    const std::string& prefix,
    const std::string& suffix,
    const nlohmann::json& context)
{
    if (!m_pImpl->m_hTransport || !m_pImpl->m_isConnected) {
        return std::nullopt;
    }
    
    // Build completion request
    nlohmann::json request = {
        {"jsonrpc", "2.0"},
        {"method", "completion/complete"},
        {"params", {
            {"prefix", prefix},
            {"suffix", suffix},
            {"context", context}
        }},
        {"id", 1}
    };
    
    std::string requestBody = request.dump();
    char* pResponse = nullptr;
    DWORD responseLen = 0;
    
    if (MCP_Transport_SendRequest(m_pImpl->m_hTransport, requestBody.c_str(),
                                   requestBody.length(), &pResponse,
                                   &responseLen, 30000)) {
        try {
            auto response = nlohmann::json::parse(pResponse, pResponse + responseLen);
            
            if (response.contains("result") && 
                response["result"].contains("completion")) {
                GhostTextSuggestion suggestion;
                suggestion.text = response["result"]["completion"].get<std::string>();
                
                if (response["result"].contains("confidence")) {
                    suggestion.confidence = response["result"]["confidence"].get<float>();
                }
                
                HANDLE hHeap = GetProcessHeap();
                HeapFree(hHeap, 0, pResponse);
                
                return suggestion;
            }
        } catch (...) {
            // Parse error
        }
        
        HANDLE hHeap = GetProcessHeap();
        HeapFree(hHeap, 0, pResponse);
    }
    
    return std::nullopt;
}

bool GhostTextMCPBridge::StartStreamingCompletion(const std::string& prefix,
                                                   const std::string& suffix,
                                                   std::function<void(const std::string&)> onToken)
{
    if (!m_pImpl->m_hTransport || !m_pImpl->m_isConnected) {
        return false;
    }
    
    if (m_pImpl->m_isStreaming.exchange(true)) {
        return false;  // Already streaming
    }
    
    m_pImpl->m_onStreamingToken = onToken;
    
    // Subscribe to SSE endpoint
    return MCP_Transport_SubscribeSSE(m_pImpl->m_hTransport, L"/v1/completion/stream") != FALSE;
}

void GhostTextMCPBridge::StopStreaming()
{
    if (m_pImpl->m_isStreaming.exchange(false)) {
        MCP_Transport_UnsubscribeSSE(m_pImpl->m_hTransport);
    }
    m_pImpl->m_onStreamingToken = nullptr;
}

bool GhostTextMCPBridge::IsStreaming() const
{
    return m_pImpl->m_isStreaming.load();
}

void GhostTextMCPBridge::SetOnConnectionStateChanged(
    std::function<void(bool)> handler)
{
    m_pImpl->m_onConnectionStateChanged = std::move(handler);
}

void GhostTextMCPBridge::SetOnToolsChanged(
    std::function<void(const std::vector<MCPTool>&)> handler)
{
    m_pImpl->m_onToolsChanged = std::move(handler);
}

void GhostTextMCPBridge::SetOnError(std::function<void(const std::string&)> handler)
{
    m_pImpl->m_onError = std::move(handler);
}

} // namespace IDE
} // namespace RawrXD
