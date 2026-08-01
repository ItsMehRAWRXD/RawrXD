#pragma once
#include <string>
#include <cstdint>

// ============================================================================
// AI Runtime — connects GGUF inference to engine agent behaviors
// ============================================================================

// ---------------------------------------------------------------------------
// Inference session
// ---------------------------------------------------------------------------
struct InferenceConfig {
    std::string modelPath;
    uint32_t    contextSize = 4096;
    uint32_t    batchSize = 512;
    float       temperature = 0.7f;
    float       topP = 0.9f;
    uint32_t    maxTokens = 256;
    bool        useGpu = false;
};

struct InferenceResult {
    std::string text;
    float       tokensPerSecond;
    uint32_t    tokenCount;
    uint64_t    elapsedUs;
};

// ---------------------------------------------------------------------------
// Agent behavior descriptor
// ---------------------------------------------------------------------------
struct AgentBehavior {
    std::string name;
    std::string systemPrompt;
    float       decisionFrequency; // Hz — how often the agent makes decisions
    uint32_t    maxPlanSteps;
};

// ---------------------------------------------------------------------------
// AI Runtime interface
// ---------------------------------------------------------------------------
class IAIRuntime {
public:
    virtual ~IAIRuntime() = default;

    // Lifecycle
    virtual bool Initialize(const InferenceConfig& config) = 0;
    virtual void Shutdown() = 0;

    // Inference
    virtual InferenceResult Generate(const std::string& prompt) = 0;
    virtual bool IsModelLoaded() const = 0;

    // Agent behaviors
    virtual void RegisterBehavior(const AgentBehavior& behavior) = 0;
    virtual std::string ExecuteBehavior(const std::string& behaviorName,
                                        const std::string& context) = 0;

    // Procedural generation
    virtual std::string GenerateSceneDescription(const std::string& seed) = 0;
    virtual std::string GenerateEntityBehavior(const std::string& entityTag) = 0;

    // Metrics
    virtual float GetTokensPerSecond() const = 0;
    virtual uint64_t GetTotalTokensGenerated() const = 0;
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------
IAIRuntime* CreateAIRuntime();
