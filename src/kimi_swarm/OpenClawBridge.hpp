// =============================================================================
// OpenClawBridge.hpp — Kimi K2.6 OpenClaw Native Bridge
// =============================================================================
// Built-in support for OpenClaw and Claude Code protocols.
// All orchestration happens locally using Swarm parallelism, avoiding
// expensive API calls.
//
// The bridge translates between:
//   - OpenClaw protocol (open-source agent communication standard)
//   - Claude Code protocol (Anthropic's code generation protocol)
//   - RawrXD internal SwarmMessage format
//
// This enables the swarm to use any compatible agent protocol while
// keeping all inference local via the Sovereign runtime.
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#pragma once

#include "KimiSwarmRoles.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>

namespace KimiSwarm {

// =============================================================================
// PROTOCOL TYPES
// =============================================================================

enum class AgentProtocol : uint8_t {
    RawrXD_Internal = 0,   // Native RawrXD swarm protocol
    OpenClaw        = 1,   // OpenClaw open standard
    ClaudeCode      = 2,   // Anthropic Claude Code protocol
    MCP             = 3,   // Model Context Protocol
    LSP             = 4    // Language Server Protocol (IDE sync)
};

// =============================================================================
// PROTOCOL MESSAGE ENVELOPE
// =============================================================================

struct ProtocolEnvelope {
    AgentProtocol protocol;
    std::string   messageId;
    std::string   sessionId;
    std::string   senderId;
    std::string   receiverId;     // "broadcast" for all
    std::string   action;         // "generate", "review", "test", "execute"
    std::string   payload;        // JSON payload
    std::string   context;        // Context window content
    std::string   modelHint;      // Preferred model
    uint32_t      maxTokens;      // Output budget
    float         temperature;
    int64_t       timestamp;
    std::string   correlationId;  // For request/response matching
};

// =============================================================================
// OPENCLAW PROTOCOL STRUCTURES
// =============================================================================

namespace OpenClaw {

struct TaskRequest {
    std::string taskId;
    std::string taskType;       // "code", "review", "test", "refactor"
    std::string language;
    std::string framework;
    std::string description;
    std::vector<std::string> inputFiles;
    std::vector<std::string> constraints;
    std::string outputFormat;   // "file", "diff", "inline"
    uint32_t maxTokens;
};

struct TaskResponse {
    std::string taskId;
    bool        success;
    std::string output;
    std::vector<std::string> generatedFiles;
    std::vector<std::string> warnings;
    std::string error;
    uint32_t    tokensUsed;
    int64_t     executionTimeMs;
};

struct AgentCapability {
    std::string agentId;
    std::string name;
    std::vector<std::string> supportedLanguages;
    std::vector<std::string> supportedFrameworks;
    std::vector<std::string> supportedTaskTypes;
    uint32_t maxConcurrentTasks;
    uint32_t maxContextTokens;
};

} // namespace OpenClaw

// =============================================================================
// CLAUDE CODE PROTOCOL STRUCTURES
// =============================================================================

namespace ClaudeCode {

struct GenerateRequest {
    std::string prompt;
    std::string filePath;
    std::string language;
    std::string existingContent;  // For edit/refactor
    std::string mode;             // "create", "edit", "review", "test"
    std::vector<std::string> contextFiles;
    uint32_t maxTokens;
    float     temperature;
};

struct GenerateResponse {
    std::string content;
    std::string diff;             // If editing existing
    std::vector<std::string> newFiles;
    std::string explanation;
    bool        success;
    std::string error;
};

struct ReviewRequest {
    std::string filePath;
    std::string content;
    std::string reviewType;       // "security", "clean-code", "performance"
    std::vector<std::string> focusAreas;
};

struct ReviewResponse {
    std::vector<std::string> issues;
    std::vector<std::string> suggestions;
    std::string severity;         // "critical", "warning", "info"
    float       qualityScore;     // 0.0-1.0
    bool        approved;
};

} // namespace ClaudeCode

// =============================================================================
// PROTOCOL TRANSLATOR
// =============================================================================

class ProtocolTranslator {
public:
    // Convert between protocols
    static ProtocolEnvelope translate(const ProtocolEnvelope& src, AgentProtocol targetProtocol);

    // RawrXD SwarmMessage ↔ ProtocolEnvelope
    static ProtocolEnvelope fromSwarmMessage(const SwarmMessage& msg);
    static SwarmMessage toSwarmMessage(const ProtocolEnvelope& env);

    // OpenClaw specific
    static OpenClaw::TaskRequest parseOpenClawRequest(const std::string& json);
    static std::string serializeOpenClawResponse(const OpenClaw::TaskResponse& resp);

    // Claude Code specific
    static ClaudeCode::GenerateRequest parseClaudeGenerate(const std::string& json);
    static std::string serializeClaudeResponse(const ClaudeCode::GenerateResponse& resp);
    static ClaudeCode::ReviewRequest parseClaudeReview(const std::string& json);
    static std::string serializeClaudeReviewResponse(const ClaudeCode::ReviewResponse& resp);

    // Protocol detection
    static AgentProtocol detectProtocol(const std::string& message);

    // Protocol name
    static const char* protocolName(AgentProtocol p);
};

// =============================================================================
// OPENCLAW BRIDGE — Main interface
// =============================================================================

class OpenClawBridge {
public:
    using ResponseCallback = std::function<void(const ProtocolEnvelope& response)>;

    static OpenClawBridge& instance();

    // ---- Lifecycle ----
    void start();
    void stop();
    bool isRunning() const { return running_.load(); }

    // ---- Task Submission ----
    // Submit a task via any protocol; it gets translated to internal format
    std::string submitTask(const ProtocolEnvelope& request, ResponseCallback callback = nullptr);

    // Submit OpenClaw task directly
    std::string submitOpenClawTask(const OpenClaw::TaskRequest& request,
                                    ResponseCallback callback = nullptr);

    // Submit Claude Code generate request
    std::string submitClaudeGenerate(const ClaudeCode::GenerateRequest& request,
                                      ResponseCallback callback = nullptr);

    // Submit Claude Code review request
    std::string submitClaudeReview(const ClaudeCode::ReviewRequest& request,
                                    ResponseCallback callback = nullptr);

    // ---- Response Retrieval ----
    ProtocolEnvelope getResponse(const std::string& taskId, int64_t timeoutMs = 30000);
    bool hasResponse(const std::string& taskId) const;

    // ---- Agent Registration ----
    void registerAgent(const OpenClaw::AgentCapability& capability);
    std::vector<OpenClaw::AgentCapability> getRegisteredAgents() const;
    std::vector<OpenClaw::AgentCapability> findAgentsForTask(const std::string& taskType,
                                                              const std::string& language) const;

    // ---- Protocol Negotiation ----
    // Negotiate the best protocol to use with a peer
    AgentProtocol negotiateProtocol(const std::vector<AgentProtocol>& supported);

    // ---- Statistics ----
    uint32_t getTotalTasks() const { return totalTasks_.load(); }
    uint32_t getCompletedTasks() const { return completedTasks_.load(); }
    uint32_t getFailedTasks() const { return failedTasks_.load(); }
    uint64_t getTotalTokensUsed() const { return totalTokensUsed_.load(); }

    // ---- Configuration ----
    void setDefaultProtocol(AgentProtocol p) { defaultProtocol_ = p; }
    AgentProtocol getDefaultProtocol() const { return defaultProtocol_; }

    void setMaxConcurrentTasks(uint32_t max) { maxConcurrent_ = max; }
    uint32_t getMaxConcurrentTasks() const { return maxConcurrent_; }

private:
    OpenClawBridge();

    std::atomic<bool> running_{false};
    AgentProtocol defaultProtocol_{AgentProtocol::RawrXD_Internal};
    uint32_t maxConcurrent_{300};  // Match Kimi K2.6 agent count

    std::mutex mutex_;
    std::unordered_map<std::string, ProtocolEnvelope> pendingRequests_;
    std::unordered_map<std::string, ProtocolEnvelope> completedResponses_;
    std::unordered_map<std::string, ResponseCallback> callbacks_;
    std::unordered_map<std::string, OpenClaw::AgentCapability> registeredAgents_;

    std::atomic<uint32_t> totalTasks_{0};
    std::atomic<uint32_t> completedTasks_{0};
    std::atomic<uint32_t> failedTasks_{0};
    std::atomic<uint64_t> totalTokensUsed_{0};
    std::atomic<uint64_t> nextTaskId_{1};

    std::string generateTaskId();
    void processTask(const std::string& taskId, const ProtocolEnvelope& request);
};

} // namespace KimiSwarm