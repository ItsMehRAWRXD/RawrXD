// ============================================================================
// ToolExecutor.cpp - Production Tool Execution Engine
// ============================================================================
// Integrates all 5 agentic tools with AgenticSupervisor
// Features: JSON-RPC interface, async execution, result caching, undo support
// ============================================================================

#include "ToolExecutor.h"
#include "FileTools.h"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace RawrXD {
namespace Agentic {
namespace Tools {

// ============================================================================
// ToolExecutor Implementation
// ============================================================================

ToolExecutor::ToolExecutor() : nextExecutionId_(1) {
    // Register built-in tools
    RegisterBuiltInTools();
}

ToolExecutor::~ToolExecutor() {
    // Cleanup any pending executions
    std::lock_guard<std::mutex> lock(executionsMutex_);
    for (auto& pair : executions_) {
        if (pair.second.state == ExecutionState::RUNNING) {
            pair.second.state = ExecutionState::CANCELLED;
        }
    }
}

void ToolExecutor::Initialize(const ToolConfig& config) {
    config_ = config;
    
    // Initialize security with allowed directories
    if (!config.allowedDirectories.empty()) {
        InitializeSecurity(config.allowedDirectories);
    }
    
    // Clear caches
    std::lock_guard<std::mutex> lock(cacheMutex_);
    resultCache_.clear();
}

uint64_t ToolExecutor::Execute(const std::string& toolName, 
                               const std::unordered_map<std::string, std::string>& params) {
    uint64_t execId = nextExecutionId_++;
    
    ExecutionContext ctx;
    ctx.id = execId;
    ctx.toolName = toolName;
    ctx.params = params;
    ctx.state = ExecutionState::PENDING;
    ctx.startTime = std::chrono::steady_clock::now();
    
    // Check cache for read-only operations
    if (config_.enableCache && IsCacheable(toolName)) {
        std::string cacheKey = BuildCacheKey(toolName, params);
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = resultCache_.find(cacheKey);
        if (it != resultCache_.end()) {
            ctx.state = ExecutionState::COMPLETED;
            ctx.result = it->second;
            ctx.endTime = std::chrono::steady_clock::now();
            
            std::lock_guard<std::mutex> execLock(executionsMutex_);
            executions_[execId] = std::move(ctx);
            return execId;
        }
    }
    
    // Store execution context
    {
        std::lock_guard<std::mutex> lock(executionsMutex_);
        executions_[execId] = std::move(ctx);
    }
    
    // Execute synchronously (can be made async with thread pool)
    ExecuteInternal(execId);
    
    return execId;
}

bool ToolExecutor::ExecuteAsync(const std::string& toolName,
                                const std::unordered_map<std::string, std::string>& params,
                                CompletionCallback callback) {
    uint64_t execId = Execute(toolName, params);
    
    if (callback) {
        std::lock_guard<std::mutex> lock(executionsMutex_);
        auto it = executions_.find(execId);
        if (it != executions_.end()) {
            it->second.callback = callback;
            
            // If already completed, call callback immediately
            if (it->second.state == ExecutionState::COMPLETED ||
                it->second.state == ExecutionState::FAILED) {
                callback(execId, it->second.result);
            }
        }
    }
    
    return true;
}

ExecutionState ToolExecutor::GetState(uint64_t executionId) const {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it != executions_.end()) {
        return it->second.state;
    }
    return ExecutionState::UNKNOWN;
}

ToolResult ToolExecutor::GetResult(uint64_t executionId) const {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it != executions_.end()) {
        return it->second.result;
    }
    
    ToolResult error;
    error.success = false;
    error.error = "Execution not found: " + std::to_string(executionId);
    return error;
}

bool ToolExecutor::Cancel(uint64_t executionId) {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it != executions_.end() && it->second.state == ExecutionState::RUNNING) {
        it->second.state = ExecutionState::CANCELLED;
        return true;
    }
    return false;
}

std::string ToolExecutor::GetExecutionReport(uint64_t executionId) const {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it == executions_.end()) {
        return "{}";
    }
    
    const ExecutionContext& ctx = it->second;
    
    std::ostringstream json;
    json << "{";
    json << "\"id\":" << ctx.id << ",";
    json << "\"tool\":\"" << EscapeJson(ctx.toolName) << "\",";
    json << "\"state\":" << static_cast<int>(ctx.state) << ",";
    json << "\"success\":" << (ctx.result.success ? "true" : "false") << ",";
    json << "\"error\":\"" << EscapeJson(ctx.result.error) << "\",";
    json << "\"data\":{";
    
    bool first = true;
    for (const auto& pair : ctx.result.data) {
        if (!first) json << ",";
        first = false;
        json << "\"" << EscapeJson(pair.first) << "\":\"" << EscapeJson(pair.second) << "\"";
    }
    json << "},";
    
    // Calculate duration
    auto endTime = (ctx.state == ExecutionState::RUNNING) ? 
                   std::chrono::steady_clock::now() : ctx.endTime;
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - ctx.startTime).count();
    json << "\"duration_ms\":" << duration;
    json << "}";
    
    return json.str();
}

// ============================================================================
// JSON-RPC Interface
// ============================================================================

std::string ToolExecutor::HandleJsonRpc(const std::string& request) {
    // Parse JSON request
    std::unordered_map<std::string, std::string> params;
    std::string method;
    int id = 0;
    
    if (!ParseJsonRpc(request, method, params, id)) {
        return BuildJsonRpcError(-32700, "Parse error", id);
    }
    
    // Execute tool
    uint64_t execId = Execute(method, params);
    
    // Wait for completion (with timeout)
    int waitMs = 0;
    while (GetState(execId) == ExecutionState::RUNNING && waitMs < 30000) {
        Sleep(10);
        waitMs += 10;
    }
    
    // Get result
    ToolResult result = GetResult(execId);
    
    // Build JSON-RPC response
    return BuildJsonRpcResponse(result, id);
}

// ============================================================================
// Undo Support
// ============================================================================

bool ToolExecutor::CanUndo(uint64_t executionId) const {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it == executions_.end()) return false;
    
    // Only file writes can be undone
    return (it->second.toolName == "write_file" || 
            it->second.toolName == "delete_file") &&
           !it->second.backupPath.empty() &&
           FileExists(it->second.backupPath);
}

bool ToolExecutor::Undo(uint64_t executionId) {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it == executions_.end()) return false;
    
    ExecutionContext& ctx = it->second;
    if (ctx.backupPath.empty() || !FileExists(ctx.backupPath)) {
        return false;
    }
    
    // Get original file path from params
    auto pathIt = ctx.params.find("path");
    if (pathIt == ctx.params.end()) return false;
    
    // Restore from backup
    if (MoveFileExA(ctx.backupPath.c_str(), pathIt->second.c_str(), 
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        ctx.state = ExecutionState::UNDONE;
        return true;
    }
    
    return false;
}

// ============================================================================
// Internal Implementation
// ============================================================================

void ToolExecutor::RegisterBuiltInTools() {
    // Tools are registered implicitly by name in ExecuteInternal
}

void ToolExecutor::ExecuteInternal(uint64_t executionId) {
    std::lock_guard<std::mutex> lock(executionsMutex_);
    auto it = executions_.find(executionId);
    if (it == executions_.end()) return;
    
    ExecutionContext& ctx = it->second;
    ctx.state = ExecutionState::RUNNING;
    
    // Dispatch to appropriate tool
    ToolResult result;
    
    if (ctx.toolName == "read_file") {
        result = ExecuteReadFile(ctx.params);
    } else if (ctx.toolName == "write_file") {
        result = ExecuteWriteFile(ctx.params, ctx.backupPath);
    } else if (ctx.toolName == "list_dir") {
        result = ExecuteListDir(ctx.params);
    } else if (ctx.toolName == "search_code") {
        result = ExecuteSearchCode(ctx.params);
    } else if (ctx.toolName == "run_command") {
        result = ExecuteRunCommand(ctx.params);
    } else {
        result.success = false;
        result.error = "Unknown tool: " + ctx.toolName;
    }
    
    ctx.result = result;
    ctx.state = result.success ? ExecutionState::COMPLETED : ExecutionState::FAILED;
    ctx.endTime = std::chrono::steady_clock::now();
    
    // Cache result if successful and cacheable
    if (result.success && config_.enableCache && IsCacheable(ctx.toolName)) {
        std::string cacheKey = BuildCacheKey(ctx.toolName, ctx.params);
        std::lock_guard<std::mutex> cacheLock(cacheMutex_);
        resultCache_[cacheKey] = result;
    }
    
    // Call callback if registered
    if (ctx.callback) {
        ctx.callback(executionId, result);
    }
}

ToolResult ToolExecutor::ExecuteReadFile(
    const std::unordered_map<std::string, std::string>& params) {
    
    ReadFileParams p;
    auto it = params.find("path");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: path";
        return r;
    }
    p.path = it->second;
    
    it = params.find("offset");
    if (it != params.end()) p.offset = std::stoll(it->second);
    
    it = params.find("limit");
    if (it != params.end()) p.limit = std::stoll(it->second);
    
    return ReadFile(p);
}

ToolResult ToolExecutor::ExecuteWriteFile(
    const std::unordered_map<std::string, std::string>& params,
    std::string& backupPath) {
    
    WriteFileParams p;
    auto it = params.find("path");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: path";
        return r;
    }
    p.path = it->second;
    
    it = params.find("content");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: content";
        return r;
    }
    p.content = it->second;
    
    it = params.find("append");
    if (it != params.end()) p.append = (it->second == "true");
    
    it = params.find("backup");
    if (it != params.end()) p.createBackup = (it->second == "true");
    
    // Create backup path before execution
    if (p.createBackup && FileExists(p.path)) {
        backupPath = GetBackupPath(p.path);
    }
    
    return WriteFile(p);
}

ToolResult ToolExecutor::ExecuteListDir(
    const std::unordered_map<std::string, std::string>& params) {
    
    ListDirParams p;
    auto it = params.find("path");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: path";
        return r;
    }
    p.path = it->second;
    
    it = params.find("pattern");
    if (it != params.end()) p.pattern = it->second;
    
    it = params.find("limit");
    if (it != params.end()) p.limit = std::stoi(it->second);
    
    it = params.find("recursive");
    if (it != params.end()) p.recursive = (it->second == "true");
    
    return ListDir(p);
}

ToolResult ToolExecutor::ExecuteSearchCode(
    const std::unordered_map<std::string, std::string>& params) {
    
    SearchCodeParams p;
    auto it = params.find("path");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: path";
        return r;
    }
    p.path = it->second;
    
    it = params.find("query");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: query";
        return r;
    }
    p.query = it->second;
    
    it = params.find("file_pattern");
    if (it != params.end()) p.filePattern = it->second;
    else p.filePattern = "*.cpp";
    
    it = params.find("case_sensitive");
    if (it != params.end()) p.caseSensitive = (it->second == "true");
    
    it = params.find("limit");
    if (it != params.end()) p.limit = std::stoi(it->second);
    
    return SearchCode(p);
}

ToolResult ToolExecutor::ExecuteRunCommand(
    const std::unordered_map<std::string, std::string>& params) {
    
    RunCommandParams p;
    auto it = params.find("command");
    if (it == params.end()) {
        ToolResult r;
        r.success = false;
        r.error = "Missing required parameter: command";
        return r;
    }
    p.command = it->second;
    
    it = params.find("working_dir");
    if (it != params.end()) p.workingDir = it->second;
    
    it = params.find("timeout");
    if (it != params.end()) p.timeoutMs = std::stoul(it->second);
    
    return RunCommand(p);
}

// ============================================================================
// Cache Management
// ============================================================================

bool ToolExecutor::IsCacheable(const std::string& toolName) const {
    // Only read-only operations are cacheable
    return toolName == "read_file" || 
           toolName == "list_dir" || 
           toolName == "search_code";
}

std::string ToolExecutor::BuildCacheKey(
    const std::string& toolName,
    const std::unordered_map<std::string, std::string>& params) const {
    
    std::string key = toolName + ":";
    for (const auto& pair : params) {
        key += pair.first + "=" + pair.second + ";";
    }
    return key;
}

void ToolExecutor::ClearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    resultCache_.clear();
}

// ============================================================================
// JSON-RPC Helpers
// ============================================================================

bool ToolExecutor::ParseJsonRpc(const std::string& json,
                                std::string& method,
                                std::unordered_map<std::string, std::string>& params,
                                int& id) {
    // Simple JSON parser for tool requests
    // Extract method
    size_t methodPos = json.find("\"method\":");
    if (methodPos == std::string::npos) return false;
    
    size_t methodStart = json.find('"', methodPos + 9);
    if (methodStart == std::string::npos) return false;
    
    size_t methodEnd = json.find('"', methodStart + 1);
    if (methodEnd == std::string::npos) return false;
    
    method = json.substr(methodStart + 1, methodEnd - methodStart - 1);
    
    // Extract id
    size_t idPos = json.find("\"id\":");
    if (idPos != std::string::npos) {
        size_t idStart = idPos + 5;
        while (idStart < json.size() && (json[idStart] == ' ' || json[idStart] == '\t')) idStart++;
        id = std::stoi(json.substr(idStart, json.find_first_of(",}", idStart) - idStart));
    }
    
    // Extract params (simplified - assumes flat object)
    size_t paramsPos = json.find("\"params\":");
    if (paramsPos != std::string::npos) {
        size_t objStart = json.find('{', paramsPos);
        if (objStart != std::string::npos) {
            size_t objEnd = json.find_last_of('}');
            std::string paramsStr = json.substr(objStart + 1, objEnd - objStart - 1);
            
            // Parse key-value pairs
            size_t pos = 0;
            while (pos < paramsStr.size()) {
                // Find key
                size_t keyStart = paramsStr.find('"', pos);
                if (keyStart == std::string::npos) break;
                size_t keyEnd = paramsStr.find('"', keyStart + 1);
                if (keyEnd == std::string::npos) break;
                std::string key = paramsStr.substr(keyStart + 1, keyEnd - keyStart - 1);
                
                // Find value
                size_t valStart = paramsStr.find(':', keyEnd) + 1;
                while (valStart < paramsStr.size() && 
                       (paramsStr[valStart] == ' ' || paramsStr[valStart] == '\t')) valStart++;
                
                std::string value;
                if (paramsStr[valStart] == '"') {
                    size_t valEnd = paramsStr.find('"', valStart + 1);
                    value = paramsStr.substr(valStart + 1, valEnd - valStart - 1);
                    pos = valEnd + 1;
                } else {
                    size_t valEnd = paramsStr.find_first_of(",}", valStart);
                    value = paramsStr.substr(valStart, valEnd - valStart);
                    // Trim whitespace
                    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) 
                        value.pop_back();
                    pos = valEnd;
                }
                
                params[key] = value;
                
                // Skip comma
                if (pos < paramsStr.size() && paramsStr[pos] == ',') pos++;
            }
        }
    }
    
    return true;
}

std::string ToolExecutor::BuildJsonRpcResponse(const ToolResult& result, int id) {
    std::ostringstream json;
    json << "{";
    json << "\"jsonrpc\":\"2.0\",";
    json << "\"id\":" << id << ",";
    
    if (result.success) {
        json << "\"result\":{";
        bool first = true;
        for (const auto& pair : result.data) {
            if (!first) json << ",";
            first = false;
            json << "\"" << EscapeJson(pair.first) << "\":\"" << EscapeJson(pair.second) << "\"";
        }
        json << "}";
    } else {
        json << "\"error\":{";
        json << "\"code\":-32000,";
        json << "\"message\":\"" << EscapeJson(result.error) << "\"";
        json << "}";
    }
    
    json << "}";
    return json.str();
}

std::string ToolExecutor::BuildJsonRpcError(int code, const std::string& message, int id) {
    std::ostringstream json;
    json << "{";
    json << "\"jsonrpc\":\"2.0\",";
    json << "\"id\":" << id << ",";
    json << "\"error\":{";
    json << "\"code\":" << code << ",";
    json << "\"message\":\"" << EscapeJson(message) << "\"";
    json << "}";
    json << "}";
    return json.str();
}

std::string ToolExecutor::EscapeJson(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    escaped << c;
                } else {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
        }
    }
    return escaped.str();
}

// ============================================================================
// C API for Integration
// ============================================================================

static ToolExecutor* g_executor = nullptr;

extern "C" {

void* ToolExecutor_Create() {
    return new ToolExecutor();
}

void ToolExecutor_Destroy(void* executor) {
    delete static_cast<ToolExecutor*>(executor);
}

void ToolExecutor_Initialize(void* executor, const char** allowedDirs, int dirCount) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    ToolConfig config;
    for (int i = 0; i < dirCount; i++) {
        config.allowedDirectories.push_back(allowedDirs[i]);
    }
    exec->Initialize(config);
}

uint64_t ToolExecutor_Execute(void* executor, const char* toolName, 
                               const char** paramKeys, const char** paramValues, 
                               int paramCount) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    std::unordered_map<std::string, std::string> params;
    for (int i = 0; i < paramCount; i++) {
        params[paramKeys[i]] = paramValues[i];
    }
    return exec->Execute(toolName, params);
}

int ToolExecutor_GetState(void* executor, uint64_t executionId) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    return static_cast<int>(exec->GetState(executionId));
}

int ToolExecutor_GetResult(void* executor, uint64_t executionId,
                            char* outputBuffer, int bufferSize) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    ToolResult result = exec->GetResult(executionId);
    
    std::string json = "{";
    json += "\"success\":" + std::string(result.success ? "true" : "false") + ",";
    json += "\"error\":\"" + ToolExecutor::EscapeJsonStatic(result.error) + "\",";
    json += "\"data\":{";
    bool first = true;
    for (const auto& pair : result.data) {
        if (!first) json += ",";
        first = false;
        json += "\"" + ToolExecutor::EscapeJsonStatic(pair.first) + "\":\"" + 
                ToolExecutor::EscapeJsonStatic(pair.second) + "\"";
    }
    json += "}}";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(outputBuffer, json.c_str(), copySize);
    outputBuffer[copySize] = '\0';
    
    return copySize;
}

const char* ToolExecutor_GetExecutionReport(void* executor, uint64_t executionId) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    static std::string report;
    report = exec->GetExecutionReport(executionId);
    return report.c_str();
}

const char* ToolExecutor_HandleJsonRpc(void* executor, const char* request) {
    auto* exec = static_cast<ToolExecutor*>(executor);
    static std::string response;
    response = exec->HandleJsonRpc(request);
    return response.c_str();
}

} // extern "C"

// Static helper for C API
std::string ToolExecutor::EscapeJsonStatic(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    escaped << c;
                } else {
                    escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
        }
    }
    return escaped.str();
}

} // namespace Tools
} // namespace Agentic
} // namespace RawrXD
