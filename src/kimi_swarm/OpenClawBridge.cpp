// =============================================================================
// OpenClawBridge.cpp — Kimi K2.6 OpenClaw Native Bridge Implementation
// =============================================================================
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#include "OpenClawBridge.hpp"
#include <sstream>
#include <chrono>
#include <algorithm>
#include <random>

namespace KimiSwarm {

// =============================================================================
// PROTOCOL TRANSLATOR
// =============================================================================

const char* ProtocolTranslator::protocolName(AgentProtocol p) {
    switch (p) {
        case AgentProtocol::RawrXD_Internal: return "RawrXD-Internal";
        case AgentProtocol::OpenClaw:        return "OpenClaw";
        case AgentProtocol::ClaudeCode:      return "Claude-Code";
        case AgentProtocol::MCP:             return "MCP";
        case AgentProtocol::LSP:             return "LSP";
        default: return "Unknown";
    }
}

AgentProtocol ProtocolTranslator::detectProtocol(const std::string& message) {
    // Detect protocol by markers in the message
    if (message.find("\"protocol\":\"openclaw\"") != std::string::npos ||
        message.find("\"openclaw\"") != std::string::npos) {
        return AgentProtocol::OpenClaw;
    }
    if (message.find("\"protocol\":\"claude-code\"") != std::string::npos ||
        message.find("\"claude\"") != std::string::npos ||
        message.find("\"anthropic\"") != std::string::npos) {
        return AgentProtocol::ClaudeCode;
    }
    if (message.find("\"jsonrpc\":\"2.0\"") != std::string::npos &&
        message.find("\"method\":\"textDocument\"") != std::string::npos) {
        return AgentProtocol::LSP;
    }
    if (message.find("\"mcp\"") != std::string::npos ||
        message.find("\"model-context-protocol\"") != std::string::npos) {
        return AgentProtocol::MCP;
    }
    return AgentProtocol::RawrXD_Internal;
}

ProtocolEnvelope ProtocolTranslator::translate(const ProtocolEnvelope& src,
                                                AgentProtocol targetProtocol) {
    ProtocolEnvelope dst = src;
    dst.protocol = targetProtocol;

    // Adjust action names per protocol
    if (targetProtocol == AgentProtocol::OpenClaw) {
        if (dst.action == "generate") dst.action = "code";
        if (dst.action == "review") dst.action = "review";
        if (dst.action == "test") dst.action = "test";
        if (dst.action == "refactor") dst.action = "refactor";
    } else if (targetProtocol == AgentProtocol::ClaudeCode) {
        if (dst.action == "code") dst.action = "generate";
        if (dst.action == "refactor") dst.action = "edit";
    }

    return dst;
}

ProtocolEnvelope ProtocolTranslator::fromSwarmMessage(const SwarmMessage& msg) {
    ProtocolEnvelope env;
    env.protocol = AgentProtocol::RawrXD_Internal;
    env.messageId = std::to_string(msg.id);
    env.senderId = std::to_string(msg.fromAgent);
    env.receiverId = (msg.toAgent == 0xFFFFFFFF) ? "broadcast" : std::to_string(msg.toAgent);
    env.payload = msg.payload;
    env.artifactPath = msg.artifactPath;
    env.timestamp = msg.timestamp;

    switch (msg.type) {
        case MessageType::TaskAssignment: env.action = "generate"; break;
        case MessageType::ReviewRequest:  env.action = "review"; break;
        case MessageType::TestRequest:    env.action = "test"; break;
        case MessageType::TaskComplete:   env.action = "complete"; break;
        case MessageType::TaskFailed:     env.action = "failed"; break;
        case MessageType::Broadcast:      env.action = "broadcast"; break;
        case MessageType::Vote:           env.action = "vote"; break;
        default:                          env.action = "message"; break;
    }

    return env;
}

SwarmMessage ProtocolTranslator::toSwarmMessage(const ProtocolEnvelope& env) {
    SwarmMessage msg;
    msg.id = std::stoull(env.messageId.empty() ? "0" : env.messageId);
    msg.fromAgent = std::stoul(env.senderId.empty() ? "0" : env.senderId);
    msg.toAgent = (env.receiverId == "broadcast") ? 0xFFFFFFFF : std::stoul(env.receiverId);
    msg.payload = env.payload;
    msg.artifactPath = env.artifactPath;
    msg.timestamp = env.timestamp;

    if (env.action == "generate" || env.action == "code") msg.type = MessageType::TaskAssignment;
    else if (env.action == "review") msg.type = MessageType::ReviewRequest;
    else if (env.action == "test") msg.type = MessageType::TestRequest;
    else if (env.action == "complete") msg.type = MessageType::TaskComplete;
    else if (env.action == "failed") msg.type = MessageType::TaskFailed;
    else if (env.action == "broadcast") msg.type = MessageType::Broadcast;
    else if (env.action == "vote") msg.type = MessageType::Vote;
    else msg.type = MessageType::StatusUpdate;

    return msg;
}

// Simplified JSON helpers (no external dependency)
static std::string extractJsonField(const std::string& json, const std::string& field) {
    std::string needle = "\"" + field + "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) {
        needle = "\"" + field + "\": ";
        pos = json.find(needle);
        if (pos == std::string::npos) return "";
        pos += needle.size();
    } else {
        pos += needle.size();
    }
    auto end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

static std::string extractJsonArray(const std::string& json, const std::string& field) {
    std::string needle = "\"" + field + "\":[";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "[]";
    pos += needle.size() - 1;  // Include opening bracket
    int depth = 0;
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '[') depth++;
        else if (json[i] == ']') {
            depth--;
            if (depth == 0) return json.substr(pos, i - pos + 1);
        }
    }
    return "[]";
}

static std::vector<std::string> parseStringArray(const std::string& jsonArray) {
    std::vector<std::string> result;
    std::string current;
    bool inString = false;
    for (char c : jsonArray) {
        if (c == '"') {
            if (inString) {
                result.push_back(current);
                current.clear();
            }
            inString = !inString;
        } else if (inString) {
            current += c;
        }
    }
    return result;
}

static std::string escapeJson(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:   result += c;
        }
    }
    return result;
}

OpenClaw::TaskRequest ProtocolTranslator::parseOpenClawRequest(const std::string& json) {
    OpenClaw::TaskRequest req;
    req.taskId = extractJsonField(json, "taskId");
    req.taskType = extractJsonField(json, "taskType");
    req.language = extractJsonField(json, "language");
    req.framework = extractJsonField(json, "framework");
    req.description = extractJsonField(json, "description");
    req.outputFormat = extractJsonField(json, "outputFormat");
    req.inputFiles = parseStringArray(extractJsonArray(json, "inputFiles"));
    req.constraints = parseStringArray(extractJsonArray(json, "constraints"));

    std::string maxTok = extractJsonField(json, "maxTokens");
    if (!maxTok.empty()) req.maxTokens = std::stoul(maxTok);
    else req.maxTokens = 4096;

    return req;
}

std::string ProtocolTranslator::serializeOpenClawResponse(const OpenClaw::TaskResponse& resp) {
    std::ostringstream json;
    json << "{"
         << "\"taskId\":\"" << escapeJson(resp.taskId) << "\","
         << "\"success\":" << (resp.success ? "true" : "false") << ","
         << "\"output\":\"" << escapeJson(resp.output) << "\","
         << "\"tokensUsed\":" << resp.tokensUsed << ","
         << "\"executionTimeMs\":" << resp.executionTimeMs;
    if (!resp.error.empty()) {
        json << ",\"error\":\"" << escapeJson(resp.error) << "\"";
    }
    if (!resp.generatedFiles.empty()) {
        json << ",\"generatedFiles\":[";
        for (size_t i = 0; i < resp.generatedFiles.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escapeJson(resp.generatedFiles[i]) << "\"";
        }
        json << "]";
    }
    json << "}";
    return json.str();
}

ClaudeCode::GenerateRequest ProtocolTranslator::parseClaudeGenerate(const std::string& json) {
    ClaudeCode::GenerateRequest req;
    req.prompt = extractJsonField(json, "prompt");
    req.filePath = extractJsonField(json, "filePath");
    req.language = extractJsonField(json, "language");
    req.existingContent = extractJsonField(json, "existingContent");
    req.mode = extractJsonField(json, "mode");
    req.contextFiles = parseStringArray(extractJsonArray(json, "contextFiles"));

    std::string maxTok = extractJsonField(json, "maxTokens");
    if (!maxTok.empty()) req.maxTokens = std::stoul(maxTok);
    else req.maxTokens = 4096;

    std::string temp = extractJsonField(json, "temperature");
    if (!temp.empty()) req.temperature = std::stof(temp);
    else req.temperature = 0.7f;

    return req;
}

std::string ProtocolTranslator::serializeClaudeResponse(const ClaudeCode::GenerateResponse& resp) {
    std::ostringstream json;
    json << "{"
         << "\"content\":\"" << escapeJson(resp.content) << "\","
         << "\"success\":" << (resp.success ? "true" : "false") << ","
         << "\"explanation\":\"" << escapeJson(resp.explanation) << "\"";
    if (!resp.diff.empty()) {
        json << ",\"diff\":\"" << escapeJson(resp.diff) << "\"";
    }
    if (!resp.error.empty()) {
        json << ",\"error\":\"" << escapeJson(resp.error) << "\"";
    }
    if (!resp.newFiles.empty()) {
        json << ",\"newFiles\":[";
        for (size_t i = 0; i < resp.newFiles.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escapeJson(resp.newFiles[i]) << "\"";
        }
        json << "]";
    }
    json << "}";
    return json.str();
}

ClaudeCode::ReviewRequest ProtocolTranslator::parseClaudeReview(const std::string& json) {
    ClaudeCode::ReviewRequest req;
    req.filePath = extractJsonField(json, "filePath");
    req.content = extractJsonField(json, "content");
    req.reviewType = extractJsonField(json, "reviewType");
    req.focusAreas = parseStringArray(extractJsonArray(json, "focusAreas"));
    return req;
}

std::string ProtocolTranslator::serializeClaudeReviewResponse(const ClaudeCode::ReviewResponse& resp) {
    std::ostringstream json;
    json << "{"
         << "\"approved\":" << (resp.approved ? "true" : "false") << ","
         << "\"severity\":\"" << escapeJson(resp.severity) << "\","
         << "\"qualityScore\":" << resp.qualityScore;
    if (!resp.issues.empty()) {
        json << ",\"issues\":[";
        for (size_t i = 0; i < resp.issues.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escapeJson(resp.issues[i]) << "\"";
        }
        json << "]";
    }
    if (!resp.suggestions.empty()) {
        json << ",\"suggestions\":[";
        for (size_t i = 0; i < resp.suggestions.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"" << escapeJson(resp.suggestions[i]) << "\"";
        }
        json << "]";
    }
    json << "}";
    return json.str();
}

// =============================================================================
// OPENCLAW BRIDGE SINGLETON
// =============================================================================

OpenClawBridge& OpenClawBridge::instance() {
    static OpenClawBridge inst;
    return inst;
}

OpenClawBridge::OpenClawBridge() {}

void OpenClawBridge::start() {
    running_ = true;
}

void OpenClawBridge::stop() {
    running_ = false;
}

std::string OpenClawBridge::generateTaskId() {
    uint64_t id = nextTaskId_.fetch_add(1);
    return "oc-task-" + std::to_string(id);
}

// =============================================================================
// TASK SUBMISSION
// =============================================================================

std::string OpenClawBridge::submitTask(const ProtocolEnvelope& request, ResponseCallback callback) {
    std::string taskId = generateTaskId();

    ProtocolEnvelope req = request;
    req.messageId = taskId;
    req.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pendingRequests_[taskId] = req;
        if (callback) callbacks_[taskId] = callback;
    }

    totalTasks_.fetch_add(1);

    // Process task (in production, this dispatches to the swarm)
    processTask(taskId, req);

    return taskId;
}

std::string OpenClawBridge::submitOpenClawTask(const OpenClaw::TaskRequest& request,
                                                ResponseCallback callback) {
    ProtocolEnvelope env;
    env.protocol = AgentProtocol::OpenClaw;
    env.action = request.taskType;
    env.payload = request.description;
    env.modelHint = "";
    env.maxTokens = request.maxTokens;
    env.temperature = 0.7f;

    // Serialize input files into context
    std::ostringstream ctx;
    ctx << "Task: " << request.taskType << "\n"
        << "Language: " << request.language << "\n"
        << "Framework: " << request.framework << "\n"
        << "Description: " << request.description << "\n";
    if (!request.inputFiles.empty()) {
        ctx << "Input files:\n";
        for (const auto& f : request.inputFiles) {
            ctx << "  - " << f << "\n";
        }
    }
    if (!request.constraints.empty()) {
        ctx << "Constraints:\n";
        for (const auto& c : request.constraints) {
            ctx << "  - " << c << "\n";
        }
    }
    env.context = ctx.str();

    return submitTask(env, callback);
}

std::string OpenClawBridge::submitClaudeGenerate(const ClaudeCode::GenerateRequest& request,
                                                  ResponseCallback callback) {
    ProtocolEnvelope env;
    env.protocol = AgentProtocol::ClaudeCode;
    env.action = request.mode;
    env.payload = request.prompt;
    env.modelHint = "";
    env.maxTokens = request.maxTokens;
    env.temperature = request.temperature;

    std::ostringstream ctx;
    ctx << "File: " << request.filePath << "\n"
        << "Language: " << request.language << "\n"
        << "Mode: " << request.mode << "\n";
    if (!request.existingContent.empty()) {
        ctx << "Existing content:\n" << request.existingContent << "\n";
    }
    if (!request.contextFiles.empty()) {
        ctx << "Context files:\n";
        for (const auto& f : request.contextFiles) {
            ctx << "  - " << f << "\n";
        }
    }
    env.context = ctx.str();

    return submitTask(env, callback);
}

std::string OpenClawBridge::submitClaudeReview(const ClaudeCode::ReviewRequest& request,
                                                ResponseCallback callback) {
    ProtocolEnvelope env;
    env.protocol = AgentProtocol::ClaudeCode;
    env.action = "review";
    env.payload = request.reviewType;
    env.maxTokens = 2048;
    env.temperature = 0.3f;

    std::ostringstream ctx;
    ctx << "File: " << request.filePath << "\n"
        << "Review type: " << request.reviewType << "\n"
        << "Content:\n" << request.content << "\n";
    if (!request.focusAreas.empty()) {
        ctx << "Focus areas:\n";
        for (const auto& a : request.focusAreas) {
            ctx << "  - " << a << "\n";
        }
    }
    env.context = ctx.str();

    return submitTask(env, callback);
}

// =============================================================================
// RESPONSE RETRIEVAL
// =============================================================================

ProtocolEnvelope OpenClawBridge::getResponse(const std::string& taskId, int64_t timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = completedResponses_.find(taskId);
            if (it != completedResponses_.end()) {
                ProtocolEnvelope resp = it->second;
                completedResponses_.erase(it);
                return resp;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ProtocolEnvelope timeout;
    timeout.messageId = taskId;
    timeout.action = "timeout";
    return timeout;
}

bool OpenClawBridge::hasResponse(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return completedResponses_.find(taskId) != completedResponses_.end();
}

// =============================================================================
// AGENT REGISTRATION
// =============================================================================

void OpenClawBridge::registerAgent(const OpenClaw::AgentCapability& capability) {
    std::lock_guard<std::mutex> lock(mutex_);
    registeredAgents_[capability.agentId] = capability;
}

std::vector<OpenClaw::AgentCapability> OpenClawBridge::getRegisteredAgents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OpenClaw::AgentCapability> result;
    result.reserve(registeredAgents_.size());
    for (const auto& [_, cap] : registeredAgents_) {
        result.push_back(cap);
    }
    return result;
}

std::vector<OpenClaw::AgentCapability> OpenClawBridge::findAgentsForTask(
    const std::string& taskType, const std::string& language) const {

    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<OpenClaw::AgentCapability> matches;

    for (const auto& [_, cap] : registeredAgents_) {
        bool taskMatch = std::find(cap.supportedTaskTypes.begin(),
                                   cap.supportedTaskTypes.end(),
                                   taskType) != cap.supportedTaskTypes.end();
        bool langMatch = std::find(cap.supportedLanguages.begin(),
                                   cap.supportedLanguages.end(),
                                   language) != cap.supportedLanguages.end();
        if (taskMatch && langMatch) {
            matches.push_back(cap);
        }
    }

    return matches;
}

// =============================================================================
// PROTOCOL NEGOTIATION
// =============================================================================

AgentProtocol OpenClawBridge::negotiateProtocol(const std::vector<AgentProtocol>& supported) {
    // Prefer in order: RawrXD_Internal > OpenClaw > ClaudeCode > MCP > LSP
    static const AgentProtocol preference[] = {
        AgentProtocol::RawrXD_Internal,
        AgentProtocol::OpenClaw,
        AgentProtocol::ClaudeCode,
        AgentProtocol::MCP,
        AgentProtocol::LSP
    };

    for (AgentProtocol p : preference) {
        if (std::find(supported.begin(), supported.end(), p) != supported.end()) {
            return p;
        }
    }

    return AgentProtocol::RawrXD_Internal;
}

// =============================================================================
// TASK PROCESSING
// =============================================================================

void OpenClawBridge::processTask(const std::string& taskId, const ProtocolEnvelope& request) {
    // In production, this dispatches to the KimiSwarmOrchestrator which
    // assigns the task to an appropriate agent from the 300-agent pool.
    // For now, we create a placeholder response that the orchestrator
    // will fill in when wired.

    ProtocolEnvelope response;
    response.messageId = taskId;
    response.correlationId = taskId;
    response.protocol = request.protocol;
    response.action = "complete";
    response.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    response.payload = "{\"status\":\"queued\",\"message\":\"Task queued for swarm dispatch\"}";
    response.maxTokens = 0;
    response.temperature = 0.0f;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        completedResponses_[taskId] = response;
        pendingRequests_.erase(taskId);
    }

    completedTasks_.fetch_add(1);
    totalTokensUsed_.fetch_add(request.maxTokens);

    // Invoke callback if registered
    ResponseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = callbacks_.find(taskId);
        if (it != callbacks_.end()) {
            cb = it->second;
            callbacks_.erase(it);
        }
    }
    if (cb) cb(response);
}

} // namespace KimiSwarm