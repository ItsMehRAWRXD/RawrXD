// ============================================================================
// streaming_inference_engine.cpp — Adapt Deep2Engine → StreamingResultChannel
// ============================================================================
#include "streaming_inference_engine.h"
#include "StreamingResultChannel.h"
#include "deep2/Deep2Engine.h"


#include <atomic>
#include <string>

namespace RawrXD::Inference {

// ============================================================================
// Implementation
// ============================================================================
class StreamingInferenceEngine::Impl {
public:
    ::Deep2::Deep2Engine* engine_ = nullptr;
    StreamingResultChannel* channel_ = nullptr;
    std::atomic<bool> cancelFlag_{false};

    // Cert counters
    std::atomic<uint64_t> deep2Calls_{0};
    std::atomic<uint64_t> prefillCount_{0};
    std::atomic<uint64_t> decodeSteps_{0};
    std::atomic<uint64_t> realTokenCount_{0};
    std::atomic<uint64_t> streamEventCount_{0};
    std::atomic<uint64_t> cancelObserved_{0};
    std::atomic<uint64_t> errorCount_{0};
};

StreamingInferenceEngine::StreamingInferenceEngine()
    : impl_(std::make_unique<Impl>()) {}

StreamingInferenceEngine::~StreamingInferenceEngine() = default;

void StreamingInferenceEngine::setEngine(::Deep2::Deep2Engine* engine) {
    impl_->engine_ = engine;
}

void StreamingInferenceEngine::setChannel(StreamingResultChannel* channel) {
    impl_->channel_ = channel;
}

void StreamingInferenceEngine::requestCancel() {
    impl_->cancelFlag_.store(true, std::memory_order_release);
    if (impl_->engine_) {
        impl_->engine_->requestCancel();
    }
}

bool StreamingInferenceEngine::generate(const std::string& prompt, const StreamingInferenceOptions& opts) {
    if (!impl_->engine_ || !impl_->channel_) return false;

    impl_->cancelFlag_.store(false, std::memory_order_release);
    impl_->deep2Calls_.fetch_add(1, std::memory_order_acq_rel);

    ::Deep2::GenerationOptions gopts;
    gopts.maxTokens   = static_cast<int>(opts.maxTokens);
    gopts.temperature = opts.temperature;
    gopts.topP        = opts.topP;

    // Prefill phase: tokenize and count
    auto promptTokens = impl_->engine_->tokenize(prompt);
    impl_->prefillCount_.fetch_add(promptTokens.size(), std::memory_order_acq_rel);

    // Reset engine cancel state before generation
    impl_->engine_->clearCancel();

    uint64_t localTokens = 0;

    ::Deep2::GenerationResult result = impl_->engine_->generateStream(
        prompt,
        gopts,
        [this, &localTokens](int32_t tokenId, const std::string& tokenText) -> bool {
            // Cooperative cancel check
            if (impl_->cancelFlag_.load(std::memory_order_acquire)) {
                impl_->cancelObserved_.fetch_add(1, std::memory_order_acq_rel);
                return false; // stop generation
            }

            impl_->decodeSteps_.fetch_add(1, std::memory_order_acq_rel);
            ++localTokens;

            if (impl_->channel_) {
                impl_->channel_->publishToken(static_cast<uint32_t>(tokenId), tokenText);
                impl_->streamEventCount_.fetch_add(1, std::memory_order_acq_rel);
            }
            return true;
        }
    );

    impl_->realTokenCount_.fetch_add(localTokens, std::memory_order_acq_rel);

    if (result.cancelled) {
        impl_->cancelObserved_.fetch_add(1, std::memory_order_acq_rel);
        if (impl_->channel_) impl_->channel_->publishCancelled();
        impl_->streamEventCount_.fetch_add(1, std::memory_order_acq_rel);
        return false;
    }

    // Publish completion
    if (impl_->channel_) {
        impl_->channel_->publishCompleted();
        impl_->streamEventCount_.fetch_add(1, std::memory_order_acq_rel);
    }
    return true;
}

StreamingInferenceCounters StreamingInferenceEngine::counters() const {
    StreamingInferenceCounters c;
    c.deep2Calls       = impl_->deep2Calls_.load(std::memory_order_acquire);
    c.prefillCount     = impl_->prefillCount_.load(std::memory_order_acquire);
    c.decodeSteps      = impl_->decodeSteps_.load(std::memory_order_acquire);
    c.realTokenCount   = impl_->realTokenCount_.load(std::memory_order_acquire);
    c.streamEventCount = impl_->streamEventCount_.load(std::memory_order_acquire);
    c.cancelObserved   = impl_->cancelObserved_.load(std::memory_order_acquire);
    c.errorCount       = impl_->errorCount_.load(std::memory_order_acquire);
    return c;
}

void StreamingInferenceEngine::resetCounters() {
    impl_->deep2Calls_.store(0, std::memory_order_release);
    impl_->prefillCount_.store(0, std::memory_order_release);
    impl_->decodeSteps_.store(0, std::memory_order_release);
    impl_->realTokenCount_.store(0, std::memory_order_release);
    impl_->streamEventCount_.store(0, std::memory_order_release);
    impl_->cancelObserved_.store(0, std::memory_order_release);
    impl_->errorCount_.store(0, std::memory_order_release);
}

} // namespace RawrXD::Inference
