// ============================================================================
// mcp_bridge.cpp - MCP Bridge Implementation (RawrXD Standard)
// Transport adapter between HTTP Gateway and MCP Runtime
// No business logic. No model loading. No inference.
// ============================================================================

#include "mcp_bridge.hpp"
#include "../../Ship/Logger.hpp"
#include <nlohmann/json.hpp>

namespace RawrXD::Deep2 {

using json = nlohmann::json;

// ============================================================================
// Constructor / Destructor
// ============================================================================
McpBridge::McpBridge() {
    Logger::info("McpBridge created");
}

McpBridge::~McpBridge() {
    if (m_initialized) {
        Shutdown();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================
bool McpBridge::Initialize() {
    if (m_initialized) {
        return true;
    }

    Logger::info("Initializing MCP Bridge...");

    // TODO: Connect to actual MCP runtime
    // For now, simulate successful initialization

    m_initialized = true;
    Logger::info("MCP Bridge initialized");
    return true;
}

void McpBridge::Shutdown() {
    Logger::info("Shutting down MCP Bridge...");
    m_initialized = false;
}

// ============================================================================
// Request Forwarding
// ============================================================================
std::expected<std::string, McpBridgeError> McpBridge::ForwardRequest(
    const std::string& jsonRequest) {
    
    if (!m_initialized) {
        Logger::error("MCP Bridge not initialized");
        return std::unexpected(McpBridgeError::NotConnected);
    }

    Logger::debug("Forwarding MCP request: {}", jsonRequest.substr(0, 200));

    // Parse request
    try {
        json request = json::parse(jsonRequest);
        
        std::string method = request.value("method", "");
        int id = request.value("id", 0);
        
        // Route to appropriate handler
        if (method == "tools/list") {
            return ListTools();
        } else if (method == "tools/call") {
            if (request.contains("params")) {
                auto& params = request["params"];
                std::string toolName = params.value("name", "");
                std::string toolParams = params.contains("arguments") 
                    ? params["arguments"].dump() : "{}";
                return CallTool(toolName, toolParams);
            }
        } else if (method == "inference/chat" || method == "inference/generate") {
            // Forward to inference runtime
            return SendToMcpRuntime(jsonRequest);
        }
        
        // Unknown method
        json error;
        error["jsonrpc"] = "2.0";
        error["id"] = id;
        error["error"]["code"] = -32601;
        error["error"]["message"] = "Method not found";
        return error.dump();
        
    } catch (const std::exception& e) {
        Logger::error("Failed to parse MCP request: {}", e.what());
        return std::unexpected(McpBridgeError::SerializationFailed);
    }
}

// ============================================================================
// Direct MCP Methods
// ============================================================================
std::expected<std::string, McpBridgeError> McpBridge::CallTool(
    const std::string& toolName, 
    const std::string& params) {
    
    Logger::info("Calling MCP tool: {} with params: {}", toolName, params);
    
    // Build JSON-RPC request
    int id = m_nextRequestId++;
    std::string request = BuildJsonRpcRequest(
        "tools/call",
        std::format(R"({{"name":"{}","arguments":{}}}")", toolName, params),
        id
    );
    
    return SendToMcpRuntime(request);
}

std::expected<std::string, McpBridgeError> McpBridge::ListTools() {
    Logger::debug("Listing MCP tools");
    
    // Return available tools
    json response;
    response["jsonrpc"] = "2.0";
    response["id"] = 1;
    
    json tools = json::array();
    
    // Inference tool
    json inferenceTool;
    inferenceTool["name"] = "deep2_inference";
    inferenceTool["description"] = "Run inference with Deep2 Sovereign Runtime";
    inferenceTool["inputSchema"]["type"] = "object";
    inferenceTool["inputSchema"]["properties"]["prompt"]["type"] = "string";
    inferenceTool["inputSchema"]["properties"]["max_tokens"]["type"] = "integer";
    inferenceTool["inputSchema"]["required"] = json::array({"prompt"});
    tools.push_back(inferenceTool);
    
    // Model info tool
    json modelTool;
    modelTool["name"] = "deep2_model_info";
    modelTool["description"] = "Get information about loaded models";
    modelTool["inputSchema"]["type"] = "object";
    tools.push_back(modelTool);
    
    // GPU status tool
    json gpuTool;
    gpuTool["name"] = "deep2_gpu_status";
    gpuTool["description"] = "Get GPU utilization and memory status";
    gpuTool["inputSchema"]["type"] = "object";
    tools.push_back(gpuTool);
    
    response["result"]["tools"] = tools;
    
    return response.dump(2);
}

std::expected<std::string, McpBridgeError> McpBridge::GetToolSchema(
    const std::string& toolName) {
    
    Logger::debug("Getting tool schema for: {}", toolName);
    
    json response;
    response["jsonrpc"] = "2.0";
    response["id"] = 1;
    
    if (toolName == "deep2_inference") {
        response["result"]["schema"]["type"] = "object";
        response["result"]["schema"]["properties"]["prompt"]["type"] = "string";
        response["result"]["schema"]["properties"]["max_tokens"]["type"] = "integer";
        response["result"]["schema"]["properties"]["temperature"]["type"] = "number";
    } else {
        response["error"]["code"] = -32602;
        response["error"]["message"] = "Tool not found";
    }
    
    return response.dump(2);
}

// ============================================================================
// Status
// ============================================================================
bool McpBridge::IsConnected() const {
    return m_initialized;
}

std::string McpBridge::GetStatus() const {
    json j;
    j["connected"] = IsConnected();
    j["initialized"] = m_initialized;
    return j.dump();
}

// ============================================================================
// Internal Helpers
// ============================================================================
std::expected<std::string, McpBridgeError> McpBridge::SendToMcpRuntime(
    const std::string& request) {
    
    // TODO: Actually send to MCP runtime
    // For now, simulate response
    
    try {
        json req = json::parse(request);
        std::string method = req.value("method", "");
        int id = req.value("id", 0);
        
        json response;
        response["jsonrpc"] = "2.0";
        response["id"] = id;
        
        if (method == "inference/chat" || method == "inference/generate") {
            // Simulate inference response
            auto& params = req["params"];
            std::string prompt = params.value("prompt", "");
            
            response["result"]["text"] = "This is a simulated response from Deep2 Sovereign Runtime.";
            response["result"]["tokens_generated"] = 10;
            response["result"]["model"] = "deep2-native";
            response["result"]["backend"] = "Vulkan";
            
        } else if (method == "tools/call") {
            auto& params = req["params"];
            std::string toolName = params.value("name", "");
            
            response["result"]["content"] = std::format("Tool {} executed successfully", toolName);
            
        } else {
            response["result"] = json::object();
        }
        
        return response.dump(2);
        
    } catch (const std::exception& e) {
        Logger::error("Failed to process MCP request: {}", e.what());
        return std::unexpected(McpBridgeError::InvalidResponse);
    }
}

std::string McpBridge::BuildJsonRpcRequest(const std::string& method,
                                          const std::string& params, 
                                          int id) {
    json request;
    request["jsonrpc"] = "2.0";
    request["method"] = method;
    request["id"] = id;
    
    if (!params.empty()) {
        request["params"] = json::parse(params);
    }
    
    return request.dump();
}

McpResponse McpBridge::ParseJsonRpcResponse(const std::string& response) {
    McpResponse result;
    
    try {
        json j = json::parse(response);
        result.jsonrpc = j.value("jsonrpc", "2.0");
        result.id = j.value("id", 0);
        
        if (j.contains("result")) {
            result.result = j["result"].dump();
        }
        
        if (j.contains("error")) {
            result.error = j["error"].dump();
        }
        
    } catch (...) {
        result.error = "{\"code\":-32700,\"message\":\"Parse error\"}";
    }
    
    return result;
}

// ============================================================================
// C API Implementation
// ============================================================================
extern "C" {

void* McpBridge_Create() {
    return new McpBridge();
}

void McpBridge_Destroy(void* bridge) {
    delete static_cast<McpBridge*>(bridge);
}

int McpBridge_Initialize(void* bridge) {
    if (!bridge) return 0;
    return static_cast<McpBridge*>(bridge)->Initialize() ? 1 : 0;
}

const char* McpBridge_ForwardRequest(void* bridge, const char* request) {
    if (!bridge || !request) return "";
    
    static std::string response;
    auto result = static_cast<McpBridge*>(bridge)->ForwardRequest(request);
    
    if (result.has_value()) {
        response = result.value();
    } else {
        json error;
        error["jsonrpc"] = "2.0";
        error["error"]["code"] = -32603;
        error["error"]["message"] = "Internal error";
        response = error.dump();
    }
    
    return response.c_str();
}

int McpBridge_IsConnected(void* bridge) {
    if (!bridge) return 0;
    return static_cast<McpBridge*>(bridge)->IsConnected() ? 1 : 0;
}

} // extern "C"

} // namespace RawrXD::Deep2
