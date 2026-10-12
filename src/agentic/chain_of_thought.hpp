// ============================================================================
// chain_of_thought.hpp — Chain-of-thought reasoning framework
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <functional>
#include <variant>
#include <optional>
#include <string_view>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Thought types
// ---------------------------------------------------------------------------
enum class ThoughtType : uint8_t {
    Observation    = 0,  // Raw observation from environment
    Analysis       = 1,  // Analysis of observations
    Hypothesis     = 2,  // Hypothesis formation
    Plan           = 3,  // Plan formulation
    Action         = 4,  // Action decision
    Reflection     = 5,  // Post-action reflection
    Correction     = 6,  // Course correction
    Summary        = 7   // Final summary
};

enum class ReasoningDepth : uint8_t {
    Shallow    = 0,  // Single-step reasoning
    Moderate   = 1,  // Multi-step reasoning
    Deep       = 2,  // Deep recursive reasoning
    Exhaustive = 3   // Exhaustive exploration
};

// ---------------------------------------------------------------------------
// Thought unit
// ---------------------------------------------------------------------------
struct Thought {
    uint64_t id = 0;
    ThoughtType type = ThoughtType::Observation;
    std::string content;
    std::string rationale;
    double confidence = 0.0;
    std::chrono::steady_clock::time_point timestamp;
    uint64_t parentId = 0;
    std::vector<uint64_t> children;
    std::string metadata;
    double confidence = 0.0;
};

// ---------------------------------------------------------------------------
// Reasoning chain
// ---------------------------------------------------------------------------
struct ReasoningChain {
    uint64_t id = 0;
    std::string prompt;
    std::vector<uint64_t> thoughtIds;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    bool completed = false;
    std::string finalConclusion;
    double overallConfidence = 0.0;
    size_t totalThoughts = 0;
    size_t maxDepth = 0;
};

// ---------------------------------------------------------------------------
// ChainOfThoughtEngine - orchestrates multi-step reasoning
// ---------------------------------------------------------------------------
class ChainOfThoughtEngine {
public:
    struct Config {
        ReasoningDepth maxDepth = ReasoningDepth::Moderate;
        size_t maxThoughts = 50;
        double minConfidence = 0.5;
        size_t maxBranching = 3;
        std::chrono::milliseconds timeoutMs = std::chrono::seconds(30);
        bool enableBacktracking = true;
        bool enableReflection = true;
        double minConfidenceThreshold = 0.3;
    };

    explicit ChainOfThoughtEngine(const Config& config = {});
    ~ChainOfThoughtEngine();

    // Main entry point
    struct Result {
        bool success = false;
        std::string conclusion;
        std::vector<std::string> thoughtLog;
        double overallConfidence = 0.0;
        size_t thoughtsGenerated = 0;
        std::chrono::milliseconds elapsedTime;
        std::string errorMessage;
    };

    Result reason(const std::string& prompt, const std::string& context = "");

    // Streaming version for incremental results
    struct StepResult {
        std::string thought;
        double confidence;
        bool isFinal = false;
        std::string errorMessage;
    };

    // Streaming interface
    class Session {
    public:
        virtual ~Session() = default;
        virtual bool step(std::string& outThought, double& outConfidence) = 0;
        virtual bool isComplete() const = 0;
        virtual std::string getConclusion() const = 0;
        virtual double getConfidence() const = 0;
    };

    std::unique_ptr<class Session> startSession(const std::string& prompt);

    // Configuration
    void setConfig(const Config& config);
    const Config& getConfig() const { return m_config; }

    // Statistics
    struct Stats {
        size_t totalChains = 0;
        size_t totalThoughts = 0;
        double avgConfidence = 0.0;
        double avgThoughtsPerChain = 0.0;
        std::chrono::milliseconds avgTime;
    };
    Stats getStats() const;
    void resetStats();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    Config m_config;
};

// ---------------------------------------------------------------------------
// Thought formatter utilities
// ---------------------------------------------------------------------------
namespace cot {

enum class Format : uint8_t {
    Raw       = 0,  // Raw thoughts
    Numbered  = 1,  // 1. Thought...
    Structured = 2,  // JSON-like
    Markdown  = 3   // Markdown formatted
};

std::string formatChain(const std::vector<std::string>& thoughts, Format fmt = Format::Numbered);
std::string extractConclusion(const std::vector<std::string>& thoughts);
double calculateChainConfidence(const std::vector<double>& confidences);

} // namespace cot

} // namespace rawrxd