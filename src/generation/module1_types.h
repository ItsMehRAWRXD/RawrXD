#pragma once
// =============================================================================
// Module 1: Types & Enums
// No external dependencies. Pure C++14.
// =============================================================================

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

constexpr size_t MAX_PROMPT_LENGTH = 4096;

enum class FinishReason : uint8_t {
    NotFinished    = 0,
    EndId           = 1,   // Model emitted EOS
    Length          = 2,   // Hit maxGenerateLength
    Cancelled       = 3,   // External cancel
    EngineError      = 4,   // Engine-internal failure
    NonEngineError   = 5,   // Input/resource/config/timeout
    StopString       = 6,   // Stop sequence matched
};

enum class ErrorSource : uint8_t {
    None      = 0,
    Engine    = 1,
    NonEngine = 2,
};

struct GenerationResult {
    std::string   text;
    uint32_t      tokensGenerated;
    double        latencyMs;
    double        tokensPerSecond;
    double        timeToFirstTokenMs;
    FinishReason  finishReason;
    ErrorSource   errorSource;
    std::string   errorMessage;
    std::string   errorSourceStr;
    std::string   finishReasonStr;

    GenerationResult()
        : tokensGenerated(0)
        , latencyMs(0.0)
        , tokensPerSecond(0.0)
        , timeToFirstTokenMs(0.0)
        , finishReason(FinishReason::NotFinished)
        , errorSource(ErrorSource::None)
    {}
};

struct GenerateParams {
    std::string  prompt;
    uint32_t     maxGenerateLength;
    uint32_t     maxOutputBytes;
    double       timeoutMs;
    double       temperature;
    float        topP;
    int64_t      topK;
    std::vector<std::string> stopStrings;
    bool         enableThinking;

    GenerateParams()
        : maxGenerateLength(512)
        , maxOutputBytes(1u << 20)  // 1 MB
        , timeoutMs(0.0)
        , temperature(1.0)
        , topP(1.0f)
        , topK(-1)
        , enableThinking(false)
    {}
};

// Callback type aliases — portable, no C++17 features
typedef std::function<void(const char*, uint32_t)> TokenCallback;
typedef std::function<void(const char*)> ErrorCallback;