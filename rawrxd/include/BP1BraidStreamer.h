// ============================================================================
// BP1BraidStreamer.h — Orchestration / backpressure / multiplexing around the
// streaming inference + agentic pipeline.
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <chrono>

namespace RawrXD {
class StreamingResultChannel;
namespace Inference {
    struct StreamingInferenceOptions;
    class StreamingInferenceEngine;
}
namespace Agentic {
    class AgenticModelStreamerBridge;
    class StreamingCommandHandler;
}
}

namespace RawrXD::Runtime {

struct BraidCounters {
    uint64_t streamsOpened    = 0;
    uint64_t streamsCompleted = 0;
    uint64_t streamsCancelled = 0;
    uint64_t backpressureHits = 0;
    uint64_t errors           = 0;
};

// ============================================================================
// BP1BraidStreamer
// ============================================================================
// Orchestrator that wires StreamingInferenceEngine, AgenticModelStreamerBridge,
// and StreamingCommandHandler into a single back-pressured, multiplexed stream
// unit. Owns the StreamingResultChannel for the lifetime of a session.
// ============================================================================
class BP1BraidStreamer {
public:
    BP1BraidStreamer();
    ~BP1BraidStreamer();

    // Configure dependencies (all must outlive this object while streaming)
    void setInferenceEngine(Inference::StreamingInferenceEngine* engine);
    void setBridge(Agentic::AgenticModelStreamerBridge* bridge);
    void setCommandHandler(Agentic::StreamingCommandHandler* handler);

    // One-shot convenience: open channel, run generation, pump bridge, close
    bool runSession(const std::string& prompt);
    bool runSession(const std::string& prompt, const Inference::StreamingInferenceOptions& opts);

    // Manual lifecycle
    bool openChannel();
    bool startGeneration(const std::string& prompt);
    bool startGeneration(const std::string& prompt, const Inference::StreamingInferenceOptions& opts);
    bool pumpUntilDone(std::chrono::milliseconds pollInterval = std::chrono::milliseconds(10));
    void closeChannel();
    void requestCancel();

    // Counters
    BraidCounters counters() const;
    void resetCounters();

    // Access the underlying channel (for diagnostics / external draining)
    StreamingResultChannel* channel() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace RawrXD::Runtime
