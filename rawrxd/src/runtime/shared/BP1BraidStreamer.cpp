// ============================================================================
// BP1BraidStreamer.cpp — Orchestration / backpressure / multiplexing
// ============================================================================
#include "BP1BraidStreamer.h"
#include "StreamingResultChannel.h"
#include "streaming_inference_engine.h"
#include "agentic_model_streamer_bridge.h"
#include "streaming_command_handler.h"

#include <atomic>
#include <memory>
#include <thread>
#include <chrono>

namespace RawrXD::Runtime {

using namespace std::chrono_literals;

// ============================================================================
// Implementation
// ============================================================================
class BP1BraidStreamer::Impl {
public:
    Inference::StreamingInferenceEngine* engine_ = nullptr;
    Agentic::AgenticModelStreamerBridge* bridge_ = nullptr;
    Agentic::StreamingCommandHandler* handler_ = nullptr;
    std::unique_ptr<StreamingResultChannel> channel_;

    std::atomic<bool> cancelRequested_{false};

    // Counters
    std::atomic<uint64_t> streamsOpened_{0};
    std::atomic<uint64_t> streamsCompleted_{0};
    std::atomic<uint64_t> streamsCancelled_{0};
    std::atomic<uint64_t> backpressureHits_{0};
    std::atomic<uint64_t> errors_{0};
};

BP1BraidStreamer::BP1BraidStreamer()
    : impl_(std::make_unique<Impl>()) {}

BP1BraidStreamer::~BP1BraidStreamer() = default;

void BP1BraidStreamer::setInferenceEngine(Inference::StreamingInferenceEngine* engine) {
    impl_->engine_ = engine;
}

void BP1BraidStreamer::setBridge(Agentic::AgenticModelStreamerBridge* bridge) {
    impl_->bridge_ = bridge;
}

void BP1BraidStreamer::setCommandHandler(Agentic::StreamingCommandHandler* handler) {
    impl_->handler_ = handler;
}

bool BP1BraidStreamer::openChannel() {
    impl_->channel_ = std::make_unique<StreamingResultChannel>();
    if (impl_->engine_) impl_->engine_->setChannel(impl_->channel_.get());
    if (impl_->bridge_) impl_->bridge_->setChannel(impl_->channel_.get());
    if (impl_->handler_) impl_->handler_->setChannel(impl_->channel_.get());
    impl_->streamsOpened_.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

bool BP1BraidStreamer::startGeneration(const std::string& prompt) {
    return startGeneration(prompt, Inference::StreamingInferenceOptions{});
}

bool BP1BraidStreamer::startGeneration(const std::string& prompt, const Inference::StreamingInferenceOptions& opts) {
    if (!impl_->engine_ || !impl_->channel_) return false;
    impl_->engine_->setChannel(impl_->channel_.get());
    // Bridge consumes channel events in background
    if (impl_->bridge_) impl_->bridge_->start();
    return impl_->engine_->generate(prompt, opts);
}

bool BP1BraidStreamer::pumpUntilDone(std::chrono::milliseconds pollInterval) {
    if (!impl_->channel_) return false;
    // Wait until channel is closed, cancelled, or bridge has finished processing
    while (!impl_->channel_->isClosed() &&
           !impl_->channel_->isCancelRequested()) {
        // If bridge is no longer running, generation is complete and events are drained
        if (impl_->bridge_ && !impl_->bridge_->isRunning()) break;
        // Simple backpressure: if channel grows too large, yield
        constexpr size_t BACKPRESSURE_THRESHOLD = 4096;
        if (impl_->channel_->size() > BACKPRESSURE_THRESHOLD) {
            impl_->backpressureHits_.fetch_add(1, std::memory_order_acq_rel);
            std::this_thread::sleep_for(pollInterval * 2);
        } else {
            std::this_thread::sleep_for(pollInterval);
        }
    }
    // Drain any remaining events so bridge can process them
    if (impl_->bridge_) {
        while (impl_->bridge_->isRunning()) {
            std::this_thread::sleep_for(pollInterval);
        }
    }
    return true;
}

void BP1BraidStreamer::closeChannel() {
    if (impl_->channel_) impl_->channel_->close();
    if (impl_->bridge_) impl_->bridge_->stop();
}

void BP1BraidStreamer::requestCancel() {
    impl_->cancelRequested_.store(true, std::memory_order_release);
    if (impl_->engine_) impl_->engine_->requestCancel();
    if (impl_->channel_) impl_->channel_->requestCancel();
}

bool BP1BraidStreamer::runSession(const std::string& prompt) {
    return runSession(prompt, Inference::StreamingInferenceOptions{});
}

bool BP1BraidStreamer::runSession(const std::string& prompt, const Inference::StreamingInferenceOptions& opts) {
    if (!openChannel()) return false;
    bool ok = startGeneration(prompt, opts);
    // startGeneration is blocking; all events are now in the channel.
    // Close channel so the bridge knows to exit after draining.
    closeChannel();
    // Wait briefly for bridge to finish processing remaining events
    if (impl_->bridge_) {
        while (impl_->bridge_->isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    if (ok) {
        impl_->streamsCompleted_.fetch_add(1, std::memory_order_acq_rel);
    } else if (impl_->cancelRequested_.load(std::memory_order_acquire)) {
        impl_->streamsCancelled_.fetch_add(1, std::memory_order_acq_rel);
    } else {
        impl_->errors_.fetch_add(1, std::memory_order_acq_rel);
    }
    return ok;
}

BraidCounters BP1BraidStreamer::counters() const {
    BraidCounters c;
    c.streamsOpened    = impl_->streamsOpened_.load(std::memory_order_acquire);
    c.streamsCompleted = impl_->streamsCompleted_.load(std::memory_order_acquire);
    c.streamsCancelled = impl_->streamsCancelled_.load(std::memory_order_acquire);
    c.backpressureHits = impl_->backpressureHits_.load(std::memory_order_acquire);
    c.errors           = impl_->errors_.load(std::memory_order_acquire);
    return c;
}

void BP1BraidStreamer::resetCounters() {
    impl_->streamsOpened_.store(0, std::memory_order_release);
    impl_->streamsCompleted_.store(0, std::memory_order_release);
    impl_->streamsCancelled_.store(0, std::memory_order_release);
    impl_->backpressureHits_.store(0, std::memory_order_release);
    impl_->errors_.store(0, std::memory_order_release);
}

StreamingResultChannel* BP1BraidStreamer::channel() const noexcept {
    return impl_->channel_.get();
}

} // namespace RawrXD::Runtime
