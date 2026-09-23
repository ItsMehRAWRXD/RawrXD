// ============================================================================
// StreamingResultChannel.h — Typed event transport primitive
// ============================================================================
// Requirements: ORDERED_DELIVERY, THREAD_SAFE, CANCELLATION, FINALIZATION,
// ERROR_PROPAGATION, NO_DROPPED_TOOL_EVENTS.
// ============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <vector>
#include <condition_variable>

namespace RawrXD {

// ----------------------------------------------------------------------------
// Stream event taxonomy
// ----------------------------------------------------------------------------
enum class StreamEventType : uint8_t {
    Token        = 0, // A single model token id
    TextDelta    = 1, // Incremental UTF-8 text
    ToolRequest  = 2, // Structured tool call detected in stream
    ToolResult   = 3, // Structured tool result to feed back
    Error        = 4, // Non-fatal error propagated through stream
    Completed    = 5, // Stream finalization (all work done)
    Cancelled    = 6  // Cooperative cancellation acknowledged
};

// ----------------------------------------------------------------------------
// Event payload
// ----------------------------------------------------------------------------
struct StreamEvent {
    StreamEventType type        = StreamEventType::TextDelta;
    std::string     text;       // UTF-8 payload (token text, tool JSON, error msg)
    uint32_t        tokenId     = 0;
    uint64_t        sequence    = 0; // Strict monotonic ordering

    // Convenience factory methods
    static StreamEvent makeToken(uint32_t id, std::string_view txt, uint64_t seq);
    static StreamEvent makeTextDelta(std::string_view txt, uint64_t seq);
    static StreamEvent makeToolRequest(std::string_view json, uint64_t seq);
    static StreamEvent makeToolResult(std::string_view json, uint64_t seq);
    static StreamEvent makeError(std::string_view msg, uint64_t seq);
    static StreamEvent makeCompleted(uint64_t seq);
    static StreamEvent makeCancelled(uint64_t seq);
};

// ----------------------------------------------------------------------------
// Channel: thread-safe ordered event queue
// ----------------------------------------------------------------------------
class StreamingResultChannel {
public:
    using EventCallback = std::function<bool(const StreamEvent&)>;

    StreamingResultChannel();
    ~StreamingResultChannel();

    // Producer API ------------------------------------------------------------
    // Publish an event. If the channel is closed, returns false and drops.
    bool publish(StreamEvent event);
    bool publishTextDelta(std::string_view text);
    bool publishToken(uint32_t tokenId, std::string_view text);
    bool publishToolRequest(std::string_view json);
    bool publishToolResult(std::string_view json);
    bool publishError(std::string_view message);
    bool publishCompleted();
    bool publishCancelled();

    // Finalization ------------------------------------------------------------
    void close();   // No further publishes accepted; consumers get EOF semantics
    bool isClosed() const noexcept;

    // Cancellation ------------------------------------------------------------
    void requestCancel();
    bool isCancelRequested() const noexcept;

    // Consumer API ------------------------------------------------------------
    // Blocking pop with optional timeout. Returns empty if closed/timeout.
    std::optional<StreamEvent> pop(std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    // Non-blocking peek
    bool tryPop(StreamEvent& out);

    // Iterate remaining events via callback. Returns number drained.
    // Callback returning false stops iteration.
    size_t drain(EventCallback callback);

    // Query state -------------------------------------------------------------
    size_t size() const;
    bool   empty() const;
    uint64_t publishedCount() const noexcept { return publishedCount_.load(std::memory_order_acquire); }
    uint64_t consumedCount() const noexcept { return consumedCount_.load(std::memory_order_acquire); }

    // Cert counters -----------------------------------------------------------
    uint64_t realTokenCount() const noexcept { return realTokenCount_.load(std::memory_order_acquire); }
    uint64_t streamEventCount() const noexcept { return publishedCount_.load(std::memory_order_acquire); }
    uint64_t cancelObservedCount() const noexcept { return cancelObservedCount_.load(std::memory_order_acquire); }

private:
    mutable std::mutex              mu_;
    std::condition_variable         cv_;
    std::queue<StreamEvent>         queue_;
    std::atomic<bool>               closed_{false};
    std::atomic<bool>               cancelRequested_{false};
    std::atomic<uint64_t>           nextSequence_{0};
    std::atomic<uint64_t>           publishedCount_{0};
    std::atomic<uint64_t>           consumedCount_{0};
    std::atomic<uint64_t>           realTokenCount_{0};
    std::atomic<uint64_t>           cancelObservedCount_{0};
};

} // namespace RawrXD
