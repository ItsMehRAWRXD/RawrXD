// ============================================================================
// streaming_command_handler.h — Parsed request → Tool Authority → serialized
// ToolResult back into model conversation
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <optional>
#include <functional>

namespace RawrXD {
class StreamingResultChannel;
}

namespace RawrXD::Agentic {
class AgentToolRegistry;

struct HandlerCounters {
    uint64_t requestsBuilt   = 0;
    uint64_t invocationsSent = 0;
    uint64_t resultsReceived = 0;
    uint64_t resultsPushed   = 0;
    uint64_t errors          = 0;
};

// ============================================================================
// StreamingCommandHandler
// ============================================================================
// Accepts a parsed tool request (JSON), builds a ToolRequest, invokes the
// Tool Authority via AgentToolRegistry::invoke(), and serializes the
// ToolResult back into the StreamingResultChannel as conversation context.
// ============================================================================
class StreamingCommandHandler {
public:
    StreamingCommandHandler();
    ~StreamingCommandHandler();

    void setChannel(StreamingResultChannel* channel);
    void setToolRegistry(AgentToolRegistry* registry);

    // Synchronous dispatch (called from bridge or orchestrator thread)
    bool handleCommand(const std::string& jsonPayload);

    HandlerCounters counters() const;
    void resetCounters();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace RawrXD::Agentic
