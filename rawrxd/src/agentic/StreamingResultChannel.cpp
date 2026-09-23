// ============================================================================
// StreamingResultChannel.cpp — Ordered, thread-safe event transport
// ============================================================================
#include "StreamingResultChannel.h"

#include <cassert>
#include <utility>

namespace RawrXD {

// ============================================================================
// StreamEvent factories
// ============================================================================
StreamEvent StreamEvent::makeToken(uint32_t id, std::string_view txt, uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::Token;
    e.tokenId  = id;
    e.text     = txt;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeTextDelta(std::string_view txt, uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::TextDelta;
    e.text     = txt;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeToolRequest(std::string_view json, uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::ToolRequest;
    e.text     = json;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeToolResult(std::string_view json, uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::ToolResult;
    e.text     = json;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeError(std::string_view msg, uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::Error;
    e.text     = msg;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeCompleted(uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::Completed;
    e.sequence = seq;
    return e;
}

StreamEvent StreamEvent::makeCancelled(uint64_t seq) {
    StreamEvent e;
    e.type     = StreamEventType::Cancelled;
    e.sequence = seq;
    return e;
}

// ============================================================================
// StreamingResultChannel
// ============================================================================
StreamingResultChannel::StreamingResultChannel() = default;
StreamingResultChannel::~StreamingResultChannel() = default;

bool StreamingResultChannel::publish(StreamEvent event) {
    if (closed_.load(std::memory_order_acquire)) return false;

    // Assign monotonic sequence
    event.sequence = nextSequence_.fetch_add(1, std::memory_order_acq_rel);

    {
        std::lock_guard<std::mutex> lock(mu_);
        if (closed_.load(std::memory_order_acquire)) return false;
        queue_.push(std::move(event));
    }
    cv_.notify_one();

    publishedCount_.fetch_add(1, std::memory_order_acq_rel);
    if (event.type == StreamEventType::Token) {
        realTokenCount_.fetch_add(1, std::memory_order_acq_rel);
    }
    if (event.type == StreamEventType::Cancelled) {
        cancelObservedCount_.fetch_add(1, std::memory_order_acq_rel);
    }
    return true;
}

bool StreamingResultChannel::publishTextDelta(std::string_view text) {
    return publish(StreamEvent::makeTextDelta(text, 0));
}

bool StreamingResultChannel::publishToken(uint32_t tokenId, std::string_view text) {
    return publish(StreamEvent::makeToken(tokenId, text, 0));
}

bool StreamingResultChannel::publishToolRequest(std::string_view json) {
    return publish(StreamEvent::makeToolRequest(json, 0));
}

bool StreamingResultChannel::publishToolResult(std::string_view json) {
    return publish(StreamEvent::makeToolResult(json, 0));
}

bool StreamingResultChannel::publishError(std::string_view message) {
    return publish(StreamEvent::makeError(message, 0));
}

bool StreamingResultChannel::publishCompleted() {
    return publish(StreamEvent::makeCompleted(0));
}

bool StreamingResultChannel::publishCancelled() {
    return publish(StreamEvent::makeCancelled(0));
}

void StreamingResultChannel::close() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        closed_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
}

bool StreamingResultChannel::isClosed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

void StreamingResultChannel::requestCancel() {
    cancelRequested_.store(true, std::memory_order_release);
    cv_.notify_all();
}

bool StreamingResultChannel::isCancelRequested() const noexcept {
    return cancelRequested_.load(std::memory_order_acquire);
}

std::optional<StreamEvent> StreamingResultChannel::pop(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    if (timeout.count() > 0) {
        cv_.wait_for(lock, timeout, [this] {
            return !queue_.empty() || closed_.load(std::memory_order_acquire) || cancelRequested_.load(std::memory_order_acquire);
        });
    } else {
        cv_.wait(lock, [this] {
            return !queue_.empty() || closed_.load(std::memory_order_acquire) || cancelRequested_.load(std::memory_order_acquire);
        });
    }
    if (queue_.empty()) return std::nullopt;

    StreamEvent e = std::move(queue_.front());
    queue_.pop();
    consumedCount_.fetch_add(1, std::memory_order_acq_rel);
    return e;
}

bool StreamingResultChannel::tryPop(StreamEvent& out) {
    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.empty()) return false;
    out = std::move(queue_.front());
    queue_.pop();
    consumedCount_.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

size_t StreamingResultChannel::drain(EventCallback callback) {
    size_t n = 0;
    std::lock_guard<std::mutex> lock(mu_);
    while (!queue_.empty()) {
        StreamEvent e = std::move(queue_.front());
        queue_.pop();
        consumedCount_.fetch_add(1, std::memory_order_acq_rel);
        ++n;
        bool keepGoing = callback(e);
        if (!keepGoing) break;
    }
    return n;
}

size_t StreamingResultChannel::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.size();
}

bool StreamingResultChannel::empty() const {
    std::lock_guard<std::mutex> lock(mu_);
    return queue_.empty();
}

} // namespace RawrXD
