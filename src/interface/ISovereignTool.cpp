/**
 * ISovereignTool.cpp
 *
 * Phase D.2 Batch 3/5: External Tool Contract Layer
 */

#include "ISovereignTool.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <fstream>

namespace Interface {

// ============================================================================
// ToolParam Implementation
// ============================================================================

std::string ToolParam::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"name\":\"" << name << "\",";
    json << "\"type\":\"" << type << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"required\":" << (required ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// ToolResult Implementation
// ============================================================================

std::string ToolResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"toolId\":\"" << toolId << "\",";
    json << "\"operation\":\"" << operation << "\",";
    json << "\"executionTimeMs\":" << executionTimeMs;
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

void ToolResult::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Tool: " << std::left << std::setw(52) << toolId << "  ║\n";
    std::cout << "║  Operation: " << std::setw(48) << operation << "  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Status: " << std::setw(51) << (success ? "SUCCESS" : "FAILED") << " ║\n";
    std::cout << "║  Time:   " << std::setw(10) << executionTimeMs << " ms" 
              << std::string(40, ' ') << "║\n";
    
    if (!errorMessage.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Error:  " << std::setw(52) << errorMessage << " ║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// ToolContext Implementation
// ============================================================================

std::string ToolContext::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"state\":\"" << state.phase << "\",";
    json << "\"metadata\":{}";
    json << "}";
    return json.str();
}

// ============================================================================
// ToolMetadata Implementation
// ============================================================================

std::string ToolMetadata::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"toolId\":\"" << toolId << "\",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"version\":\"" << version << "\",";
    json << "\"author\":\"" << author << "\",";
    json << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ",";
    json << "\"parameters\":[";
    for (size_t i = 0; i < parameters.size(); ++i) {
        if (i > 0) json << ",";
        json << parameters[i].ToJson();
    }
    json << "],";
    json << "\"tags\":[";
    for (size_t i = 0; i < tags.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << tags[i] << "\"";
    }
    json << "]";
    json << "}";
    return json.str();
}

// ============================================================================
// ToolExecutionResponse Implementation
// ============================================================================

std::string ToolExecutionResponse::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"requestId\":\"" << requestId << "\",";
    json << "\"accepted\":" << (accepted ? "true" : "false") << ",";
    json << "\"status\":\"" << status << "\",";
    json << "\"result\":" << result.ToJson() << ",";
    json << "\"queuedAtMs\":" << queuedAtMs << ",";
    json << "\"startedAtMs\":" << startedAtMs << ",";
    json << "\"completedAtMs\":" << completedAtMs;
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

// ============================================================================
// ToolRegistryConfig Implementation
// ============================================================================

std::string ToolRegistryConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxConcurrentTools\":" << maxConcurrentTools << ",";
    json << "\"defaultTimeoutMs\":" << defaultTimeoutMs << ",";
    json << "\"enableSandbox\":" << (enableSandbox ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// SovereignToolRegistry Implementation
// ============================================================================

SovereignToolRegistry::SovereignToolRegistry() = default;
SovereignToolRegistry::~SovereignToolRegistry() {
    CleanupExecutions();
}

bool SovereignToolRegistry::Initialize(const ToolRegistryConfig& config) {
    config_ = config;
    initialized_ = true;
    
    std::cout << "[SovereignToolRegistry] Initialized\n";
    std::cout << "  Max concurrent tools: " << config.maxConcurrentTools << "\n";
    std::cout << "  Default timeout: " << config.defaultTimeoutMs << " ms\n";
    std::cout << "  Sandbox: " << (config.enableSandbox ? "enabled" : "disabled") << "\n";
    
    return true;
}

bool SovereignToolRegistry::RegisterTool(const ToolRegistration& registration) {
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    
    if (registrations_.find(registration.toolId) != registrations_.end()) {
        std::cerr << "[SovereignToolRegistry] Tool already registered: " << registration.toolId << "\n";
        return false;
    }
    
    registrations_[registration.toolId] = registration;
    std::cout << "[SovereignToolRegistry] Registered tool: " << registration.toolId << "\n";
    
    return true;
}

bool SovereignToolRegistry::UnregisterTool(const std::string& toolId) {
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    
    auto it = registrations_.find(toolId);
    if (it == registrations_.end()) {
        return false;
    }
    
    registrations_.erase(it);
    std::cout << "[SovereignToolRegistry] Unregistered tool: " << toolId << "\n";
    
    return true;
}

std::shared_ptr<ISovereignTool> SovereignToolRegistry::CreateTool(
    const std::string& toolId,
    const std::map<std::string, ToolParamValue>& config) {
    
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    
    auto it = registrations_.find(toolId);
    if (it == registrations_.end()) {
        std::cerr << "[SovereignToolRegistry] Tool not found: " << toolId << "\n";
        return nullptr;
    }
    
    auto tool = it->second.factory();
    if (!tool->Initialize(config)) {
        std::cerr << "[SovereignToolRegistry] Failed to initialize tool: " << toolId << "\n";
        return nullptr;
    }
    
    {
        std::lock_guard<std::mutex> instLock(instancesMutex_);
        instances_[toolId] = tool;
    }
    
    return tool;
}

ToolExecutionResponse SovereignToolRegistry::Execute(const ToolExecutionRequest& request,
                                                     const ToolContext& context) {
    ToolExecutionResponse response;
    response.requestId = request.requestId.empty() ? GenerateRequestId() : request.requestId;
    response.queuedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Validate request
    std::string error;
    if (!ValidateRequest(request, error)) {
        response.accepted = false;
        response.status = "failed";
        response.errorMessage = error;
        return response;
    }
    
    // Check if tool is blocked
    if (std::find(config_.blockedToolIds.begin(), config_.blockedToolIds.end(), request.toolId) 
        != config_.blockedToolIds.end()) {
        response.accepted = false;
        response.status = "failed";
        response.errorMessage = "Tool is blocked: " + request.toolId;
        return response;
    }
    
    // Get or create tool instance
    std::shared_ptr<ISovereignTool> tool;
    {
        std::lock_guard<std::mutex> lock(instancesMutex_);
        auto it = instances_.find(request.toolId);
        if (it != instances_.end()) {
            tool = it->second;
        }
    }
    
    if (!tool) {
        tool = CreateTool(request.toolId, {});
        if (!tool) {
            response.accepted = false;
            response.status = "failed";
            response.errorMessage = "Failed to create tool instance: " + request.toolId;
            return response;
        }
    }
    
    // Check if operation is supported
    if (!tool->SupportsOperation(request.operation)) {
        response.accepted = false;
        response.status = "failed";
        response.errorMessage = "Operation not supported: " + request.operation;
        return response;
    }
    
    // Execute
    response.accepted = true;
    response.status = "running";
    response.startedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    auto result = tool->Execute(request.operation, request.parameters, context);
    
    response.result = result;
    response.status = result.success ? "completed" : "failed";
    response.completedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return response;
}

std::future<ToolExecutionResponse> SovereignToolRegistry::ExecuteAsync(
    const ToolExecutionRequest& request,
    const ToolContext& context) {
    
    auto promise = std::make_shared<std::promise<ToolExecutionResponse>>();
    auto future = promise->get_future();
    
    auto execution = std::make_shared<ActiveExecution>();
    execution->request = request;
    execution->promise = promise;
    
    {
        std::lock_guard<std::mutex> lock(executionsMutex_);
        executions_[request.requestId] = execution;
    }
    
    execution->executionThread = std::thread([this, execution, context]() {
        auto response = Execute(execution->request, context);
        execution->response = response;
        execution->promise->set_value(response);
    });
    execution->executionThread.detach();
    
    return future;
}

bool SovereignToolRegistry::CancelExecution(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    
    auto it = executions_.find(requestId);
    if (it == executions_.end()) {
        return false;
    }
    
    it->second->cancelled.store(true);
    return true;
}

ToolExecutionResponse SovereignToolRegistry::GetExecutionStatus(const std::string& requestId) const {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    
    auto it = executions_.find(requestId);
    if (it == executions_.end()) {
        ToolExecutionResponse response;
        response.requestId = requestId;
        response.status = "unknown";
        response.errorMessage = "Execution not found: " + requestId;
        return response;
    }
    
    return it->second->response;
}

std::vector<ToolMetadata> SovereignToolRegistry::ListTools() const {
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    
    std::vector<ToolMetadata> tools;
    for (const auto& [toolId, registration] : registrations_) {
        tools.push_back(registration.metadata);
    }
    
    return tools;
}

std::optional<ToolMetadata> SovereignToolRegistry::GetToolMetadata(const std::string& toolId) const {
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    
    auto it = registrations_.find(toolId);
    if (it != registrations_.end()) {
        return it->second.metadata;
    }
    
    return std::nullopt;
}

bool SovereignToolRegistry::IsToolRegistered(const std::string& toolId) const {
    std::lock_guard<std::mutex> lock(registrationsMutex_);
    return registrations_.find(toolId) != registrations_.end();
}

std::string SovereignToolRegistry::GetToolHealth(const std::string& toolId) const {
    std::lock_guard<std::mutex> lock(instancesMutex_);
    
    auto it = instances_.find(toolId);
    if (it != instances_.end()) {
        return it->second->GetHealthStatus();
    }
    
    return "not_loaded";
}

void SovereignToolRegistry::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN TOOL REGISTRY STATUS                               ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:      " << std::setw(10) << (initialized_ ? "YES" : "NO") 
              << std::string(36, ' ') << "║\n";
    
    {
        std::lock_guard<std::mutex> lock(registrationsMutex_);
        std::cout << "║  Registered Tools: " << std::setw(9) << registrations_.size() 
                  << std::string(36, ' ') << "║\n";
    }
    
    {
        std::lock_guard<std::mutex> lock(instancesMutex_);
        std::cout << "║  Active Instances: " << std::setw(9) << instances_.size() 
                  << std::string(36, ' ') << "║\n";
    }
    
    {
        std::lock_guard<std::mutex> lock(executionsMutex_);
        std::cout << "║  Active Executions: " << std::setw(8) << executions_.size() 
                  << std::string(36, ' ') << "║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

std::string SovereignToolRegistry::GenerateRequestId() {
    return "req_" + std::to_string(executionCounter_.fetch_add(1));
}

bool SovereignToolRegistry::ValidateRequest(const ToolExecutionRequest& request, 
                                            std::string& error) const {
    if (request.toolId.empty()) {
        error = "Tool ID is required";
        return false;
    }
    
    if (request.operation.empty()) {
        error = "Operation is required";
        return false;
    }
    
    if (request.timeoutMs <= 0) {
        error = "Timeout must be positive";
        return false;
    }
    
    return true;
}

void SovereignToolRegistry::CleanupExecutions() {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    executions_.clear();
}

// ============================================================================
// StateQueryTool Implementation
// ============================================================================

StateQueryTool::StateQueryTool() = default;
StateQueryTool::~StateQueryTool() = default;

ToolMetadata StateQueryTool::GetMetadata() const {
    ToolMetadata metadata;
    metadata.toolId = "state_query";
    metadata.name = "State Query Tool";
    metadata.description = "Query runtime state and metrics";
    metadata.version = "1.0.0";
    metadata.author = "Sovereign Runtime";
    metadata.capabilities = ToolCapability::READ_STATE | ToolCapability::ASYNC_EXEC;
    
    metadata.parameters = {
        {"query", "string", "Query string", false, std::string("*")},
        {"format", "string", "Output format (json, text)", false, std::string("json")}
    };
    
    metadata.tags = {"state", "query", "introspection"};
    
    return metadata;
}

bool StateQueryTool::Initialize(const std::map<std::string, ToolParamValue>& config) {
    initialized_ = true;
    std::cout << "[StateQueryTool] Initialized\n";
    return true;
}

void StateQueryTool::Shutdown() {
    initialized_ = false;
    std::cout << "[StateQueryTool] Shutdown\n";
}

ToolResult StateQueryTool::Execute(const std::string& operation,
                                    const std::map<std::string, ToolParamValue>& params,
                                    const ToolContext& context) {
    ToolResult result;
    result.toolId = "state_query";
    result.operation = operation;
    
    auto startTime = std::chrono::steady_clock::now();
    
    if (operation == "query") {
        result = HandleQuery(params, context);
    } else if (operation == "snapshot") {
        result = HandleSnapshot(params, context);
    } else {
        result.success = false;
        result.errorMessage = "Unknown operation: " + operation;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    return result;
}

bool StateQueryTool::SupportsOperation(const std::string& operation) const {
    return operation == "query" || operation == "snapshot";
}

std::string StateQueryTool::GetOperationDocs(const std::string& operation) const {
    if (operation == "query") {
        return "Query runtime state";
    } else if (operation == "snapshot") {
        return "Create state snapshot";
    }
    return "Unknown operation";
}

ToolResult StateQueryTool::HandleQuery(const std::map<std::string, ToolParamValue>& params,
                                       const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["phase"] = context.state.phase;
    data["mode"] = Core::ExecutionModeToString(context.state.mode);
    data["healthy"] = context.state.IsHealthy();
    data["stability"] = context.state.stability;
    data["convergence"] = context.state.convergence;
    
    result.data = data;
    return result;
}

ToolResult StateQueryTool::HandleSnapshot(const std::map<std::string, ToolParamValue>& params,
                                          const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> snapshot;
    snapshot["timestamp"] = static_cast<int>(context.state.timestampMs);
    snapshot["version"] = context.state.version;
    snapshot["active_subsystems"] = static_cast<int>(context.state.activeSubsystems);
    
    result.data = snapshot;
    return result;
}

// ============================================================================
// GraphMutationTool Implementation
// ============================================================================

GraphMutationTool::GraphMutationTool() = default;
GraphMutationTool::~GraphMutationTool() = default;

ToolMetadata GraphMutationTool::GetMetadata() const {
    ToolMetadata metadata;
    metadata.toolId = "graph_mutation";
    metadata.name = "Graph Mutation Tool";
    metadata.description = "Mutate execution graph";
    metadata.version = "1.0.0";
    metadata.author = "Sovereign Runtime";
    metadata.capabilities = ToolCapability::WRITE_STATE | ToolCapability::ASYNC_EXEC | 
                            ToolCapability::CANCELABLE;
    
    metadata.parameters = {
        {"node_id", "string", "Node identifier", true},
        {"node_type", "string", "Node type", false, std::string("generic")},
        {"edge_from", "string", "Source node", false, std::string("")},
        {"edge_to", "string", "Target node", false, std::string("")}
    };
    
    metadata.tags = {"graph", "mutation", "nodes", "edges"};
    
    return metadata;
}

bool GraphMutationTool::Initialize(const std::map<std::string, ToolParamValue>& config) {
    initialized_ = true;
    std::cout << "[GraphMutationTool] Initialized\n";
    return true;
}

void GraphMutationTool::Shutdown() {
    initialized_ = false;
    std::cout << "[GraphMutationTool] Shutdown\n";
}

ToolResult GraphMutationTool::Execute(const std::string& operation,
                                      const std::map<std::string, ToolParamValue>& params,
                                      const ToolContext& context) {
    ToolResult result;
    result.toolId = "graph_mutation";
    result.operation = operation;
    
    auto startTime = std::chrono::steady_clock::now();
    
    if (operation == "add_node") {
        result = HandleAddNode(params, context);
    } else if (operation == "remove_node") {
        result = HandleRemoveNode(params, context);
    } else if (operation == "add_edge") {
        result = HandleAddEdge(params, context);
    } else {
        result.success = false;
        result.errorMessage = "Unknown operation: " + operation;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    return result;
}

bool GraphMutationTool::SupportsOperation(const std::string& operation) const {
    return operation == "add_node" || operation == "remove_node" || operation == "add_edge";
}

std::string GraphMutationTool::GetOperationDocs(const std::string& operation) const {
    if (operation == "add_node") {
        return "Add a node to the graph";
    } else if (operation == "remove_node") {
        return "Remove a node from the graph";
    } else if (operation == "add_edge") {
        return "Add an edge between nodes";
    }
    return "Unknown operation";
}

ToolResult GraphMutationTool::HandleAddNode(const std::map<std::string, ToolParamValue>& params,
                                            const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["action"] = std::string("add_node");
    data["status"] = std::string("success");
    
    result.data = data;
    return result;
}

ToolResult GraphMutationTool::HandleRemoveNode(const std::map<std::string, ToolParamValue>& params,
                                               const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["action"] = std::string("remove_node");
    data["status"] = std::string("success");
    
    result.data = data;
    return result;
}

ToolResult GraphMutationTool::HandleAddEdge(const std::map<std::string, ToolParamValue>& params,
                                            const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["action"] = std::string("add_edge");
    data["status"] = std::string("success");
    
    result.data = data;
    return result;
}

// ============================================================================
// CheckpointTool Implementation
// ============================================================================

CheckpointTool::CheckpointTool() = default;
CheckpointTool::~CheckpointTool() = default;

ToolMetadata CheckpointTool::GetMetadata() const {
    ToolMetadata metadata;
    metadata.toolId = "checkpoint";
    metadata.name = "Checkpoint Tool";
    metadata.description = "Create and restore checkpoints";
    metadata.version = "1.0.0";
    metadata.author = "Sovereign Runtime";
    metadata.capabilities = ToolCapability::READ_STATE | ToolCapability::WRITE_STATE | 
                            ToolCapability::ASYNC_EXEC | ToolCapability::RETRYABLE;
    
    metadata.parameters = {
        {"checkpoint_id", "string", "Checkpoint identifier", false, std::string("")},
        {"include_graph", "bool", "Include graph state", false, true},
        {"include_swarm", "bool", "Include swarm state", false, true}
    };
    
    metadata.tags = {"checkpoint", "persistence", "backup"};
    
    return metadata;
}

bool CheckpointTool::Initialize(const std::map<std::string, ToolParamValue>& config) {
    initialized_ = true;
    
    auto it = config.find("checkpoint_dir");
    if (it != config.end() && std::holds_alternative<std::string>(it->second)) {
        checkpointDir_ = std::get<std::string>(it->second);
    }
    
    std::cout << "[CheckpointTool] Initialized (dir: " << checkpointDir_ << ")\n";
    return true;
}

void CheckpointTool::Shutdown() {
    initialized_ = false;
    std::cout << "[CheckpointTool] Shutdown\n";
}

ToolResult CheckpointTool::Execute(const std::string& operation,
                                   const std::map<std::string, ToolParamValue>& params,
                                   const ToolContext& context) {
    ToolResult result;
    result.toolId = "checkpoint";
    result.operation = operation;
    
    auto startTime = std::chrono::steady_clock::now();
    
    if (operation == "create") {
        result = HandleCreate(params, context);
    } else if (operation == "restore") {
        result = HandleRestore(params, context);
    } else if (operation == "list") {
        result = HandleList(params, context);
    } else if (operation == "delete") {
        result = HandleDelete(params, context);
    } else {
        result.success = false;
        result.errorMessage = "Unknown operation: " + operation;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    return result;
}

bool CheckpointTool::SupportsOperation(const std::string& operation) const {
    return operation == "create" || operation == "restore" || 
           operation == "list" || operation == "delete";
}

std::string CheckpointTool::GetOperationDocs(const std::string& operation) const {
    if (operation == "create") {
        return "Create a checkpoint";
    } else if (operation == "restore") {
        return "Restore from a checkpoint";
    } else if (operation == "list") {
        return "List available checkpoints";
    } else if (operation == "delete") {
        return "Delete a checkpoint";
    }
    return "Unknown operation";
}

ToolResult CheckpointTool::HandleCreate(const std::map<std::string, ToolParamValue>& params,
                                        const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::string checkpointId = "chk_" + std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    
    std::map<std::string, ToolParamValue> data;
    data["checkpoint_id"] = checkpointId;
    data["status"] = std::string("created");
    data["timestamp"] = static_cast<int>(context.state.timestampMs);
    
    result.data = data;
    return result;
}

ToolResult CheckpointTool::HandleRestore(const std::map<std::string, ToolParamValue>& params,
                                        const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["status"] = std::string("restored");
    
    result.data = data;
    return result;
}

ToolResult CheckpointTool::HandleList(const std::map<std::string, ToolParamValue>& params,
                                      const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::vector<ToolParamValue> checkpoints;
    
    std::map<std::string, ToolParamValue> chk1;
    chk1["id"] = std::string("chk_001");
    chk1["timestamp"] = 1234567890;
    checkpoints.push_back(chk1);
    
    std::map<std::string, ToolParamValue> chk2;
    chk2["id"] = std::string("chk_002");
    chk2["timestamp"] = 1234567900;
    checkpoints.push_back(chk2);
    
    result.data = checkpoints;
    return result;
}

ToolResult CheckpointTool::HandleDelete(const std::map<std::string, ToolParamValue>& params,
                                        const ToolContext& context) {
    ToolResult result;
    result.success = true;
    
    std::map<std::string, ToolParamValue> data;
    data["status"] = std::string("deleted");
    
    result.data = data;
    return result;
}

// ============================================================================
// CLI Implementation
// ============================================================================

void SovereignToolRegistryCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     SOVEREIGN TOOL REGISTRY - Phase D.2                           ║\n";
    std::cout << "║     External Tool Contract Layer                                   ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SovereignToolRegistryCLI::PrintUsage() {
    std::cout << "Usage: sovereign-tool-registry [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --list               List registered tools\n";
    std::cout << "  --help               Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  sovereign-tool-registry --list\n";
    std::cout << "  sovereign-tool-registry --interactive\n";
}

void SovereignToolRegistryCLI::PrintToolList(const std::vector<ToolMetadata>& tools) {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  REGISTERED TOOLS                                                ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    for (const auto& tool : tools) {
        std::cout << "║  " << std::left << std::setw(20) << tool.toolId 
                  << " " << std::setw(38) << tool.name << " ║\n";
        std::cout << "║  " << std::setw(58) << tool.description << " ║\n";
        std::cout << "║  Version: " << std::setw(49) << tool.version << " ║\n";
        std::cout << "╟────────────────────────────────────────────────────────────────╢\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

ToolRegistryConfig SovereignToolRegistryCLI::ParseArgs(int argc, char* argv[]) {
    ToolRegistryConfig config;
    return config;
}

void SovereignToolRegistryCLI::InteractiveMode(SovereignToolRegistry& registry) {
    std::cout << "\nInteractive Tool Registry Mode\n";
    std::cout << "Type 'help' for commands, 'quit' to exit\n\n";
    
    std::string command;
    while (true) {
        std::cout << "tool> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        }
        
        if (command == "help") {
            std::cout << "\nCommands:\n";
            std::cout << "  list          - List registered tools\n";
            std::cout << "  status        - Show registry status\n";
            std::cout << "  execute       - Execute a tool\n";
            std::cout << "  quit          - Exit\n\n";
            continue;
        }
        
        if (command == "list") {
            auto tools = registry.ListTools();
            PrintToolList(tools);
            continue;
        }
        
        if (command == "status") {
            registry.PrintStatus();
            continue;
        }
        
        if (command.empty()) {
            continue;
        }
        
        std::cout << "Unknown command: " << command << "\n";
    }
}

int SovereignToolRegistryCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    ToolRegistryConfig config = ParseArgs(argc, argv);
    
    SovereignToolRegistry registry;
    if (!registry.Initialize(config)) {
        std::cerr << "Failed to initialize tool registry\n";
        return 1;
    }
    
    // Register built-in tools
    registry.RegisterTool({
        "state_query",
        []() { return std::make_unique<StateQueryTool>(); },
        StateQueryTool().GetMetadata(),
        false
    });
    
    registry.RegisterTool({
        "graph_mutation",
        []() { return std::make_unique<GraphMutationTool>(); },
        GraphMutationTool().GetMetadata(),
        false
    });
    
    registry.RegisterTool({
        "checkpoint",
        []() { return std::make_unique<CheckpointTool>(); },
        CheckpointTool().GetMetadata(),
        false
    });
    
    // Check for --list
    if (argc > 1 && std::string(argv[1]) == "--list") {
        auto tools = registry.ListTools();
        PrintToolList(tools);
        return 0;
    }
    
    // Check for --interactive
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(registry);
        return 0;
    }
    
    // No command provided, enter interactive mode
    InteractiveMode(registry);
    return 0;
}

} // namespace Interface
