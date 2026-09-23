// ============================================================================
// streaming_inference_engine.h — Bridge Deep2Engine generation → StreamingResultChannel
// ============================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <optional>

namespace RawrXD { class StreamingResultChannel; }
namespace Deep2 { class Deep2Engine; }

namespace RawrXD::Inference {

struct StreamingInferenceOptions {
    size_t maxTokens        = 256;
    float  temperature      = 0.7f;
    float  topP             = 0.9f;
    bool   enableStreaming  = true;
};

// Cert counters exposed for external telemetry
struct StreamingInferenceCounters {
    uint64_t deep2Calls       = 0;
    uint64_t prefillCount     = 0;
    uint64_t decodeSteps      = 0;
    uint64_t realTokenCount   = 0;
    uint64_t streamEventCount = 0;
    uint64_t cancelObserved   = 0;
    uint64_t errorCount       = 0;
};

// ============================================================================
// StreamingInferenceEngine
// ============================================================================
// Adapts Deep2Engine::generateStream() to publish real tokens into a
// StreamingResultChannel. Exposes counters required for autonomous loop
// certification.
// ============================================================================
class StreamingInferenceEngine {
public:
    StreamingInferenceEngine();
    ~StreamingInferenceEngine();

    // Bind the production Deep2 engine and target channel (must outlive calls)
    void setEngine(::Deep2::Deep2Engine* engine);
    void setChannel(StreamingResultChannel* channel);

    // Run streaming generation synchronously on the calling thread.
    // Returns false if cancelled or error propagated.
    bool generate(const std::string& prompt, const StreamingInferenceOptions& opts = {});

    // Cancel an in-flight generation (cooperative, checked per decode step)
    void requestCancel();

    // Counters (read-only, atomic-backed)
    StreamingInferenceCounters counters() const;
    void resetCounters();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace RawrXD::Inference
