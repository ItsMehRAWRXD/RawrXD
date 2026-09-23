// ============================================================================
// agentic_model_streamer_bridge.h — Model↔Agent boundary (delta consumption +
// structured tool recognition, routing to Tool Authority)
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <optional>

namespace RawrXD {
class StreamingResultChannel;
}

namespace RawrXD::Agentic {
class AgentToolRegistry;

// Cert counters for bridge telemetry
struct BridgeCounters {
    uint64_t deltasConsumed      = 0;
    uint64_t toolRequestsSeen    = 0;
    uint64_t toolRequestsParsed  = 0;
    uint64_t authorityCalls      = 0;
    uint64_t toolExecutions      = 0;
    uint64_t toolResultsProduced  = 0;
    uint64_t toolResultsSent      = 0;
    uint64_t toolResultsInjected  = 0;
    uint64_t continuationsStarted = 0;
    uint64_t postToolTokens       = 0;
    uint64_t errors              = 0;
    uint64_t parseFailures       = 0;
};

// ============================================================================
// AgenticModelStreamerBridge
// ============================================================================
// Consumes text deltas from StreamingResultChannel, detects structured tool
// requests (e.g., JSON blocks or function-call markers), routes them through
// AgentToolRegistry::invoke(), and writes ToolResult events back into the
// channel so the conversation context remains continuous.
// ============================================================================
class AgenticModelStreamerBridge {
public:
    AgenticModelStreamerBridge();
    ~AgenticModelStreamerBridge();

    // Bind channel and registry (must outlive this object)
    void setChannel(StreamingResultChannel* channel);
    void setToolRegistry(AgentToolRegistry* registry);

    // Spin-up background pump thread (one per stream session)
    void start();
    void stop();  // Signal graceful shutdown; joins pump thread

    // Counters
    BridgeCounters counters() const;
    void resetCounters();

    // Peek whether the pump thread is still running
    bool isRunning() const noexcept;

    // Diagnostic accessors for gate certification
    std::string accumulatedText() const noexcept;
    std::string lastToolRequestRaw() const noexcept;
    std::string lastToolName() const noexcept;
    std::string lastToolResultText() const noexcept;
    void clearAccumulatedText();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace RawrXD::Agentic
