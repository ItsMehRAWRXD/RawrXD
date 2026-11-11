// ============================================================================
// ModelRouter.hpp — Intelligent Model Selection and Routing
// Routes requests to the appropriate model based on task complexity
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>

namespace RawrXD {
namespace CEO {

using json = nlohmann::json;

// ============================================================================
// Model Configuration
// ============================================================================
struct ModelConfig {
    std::string name;
    std::string path;              // Path to GGUF file
    int contextLength = 8192;
    float quantization = 4.0f;   // Q4, Q8, etc.
    int vramMB = 0;               // VRAM required
    bool supportsTools = false;
    bool supportsFIM = false;      // Fill-in-the-middle
    float latencyMs = 0.0f;        // Average latency
    float qualityScore = 0.0f;     // Benchmark score
};

// ============================================================================
// Routing Decision
// ============================================================================
enum class TaskType {
    Completion,      // Fast inline completion
    Chat,           // General conversation
    CodeGeneration, // Write new code
    CodeReview,     // Review existing code
    Debug,          // Debug failures
    Architecture,   // High-level design
    Embedding       // Vector embeddings
};

struct RoutingDecision {
    std::string modelName;
    TaskType taskType;
    int estimatedTokens;
    float confidence;
    std::string reason;
};

// ============================================================================
// Model Router
// Routes tasks to optimal models based on requirements
// ============================================================================
class ModelRouter {
public:
    ModelRouter();
    ~ModelRouter();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Model Management
    bool RegisterModel(const ModelConfig& config);
    bool UnregisterModel(const std::string& name);
    std::vector<ModelConfig> GetAvailableModels() const;
    ModelConfig GetModel(const std::string& name) const;
    
    // Routing
    RoutingDecision Route(TaskType taskType, 
                         const std::string& query,
                         int preferredContextLength = 0);
    RoutingDecision RouteCompletion(const std::string& prefix,
                                    const std::string& suffix);
    RoutingDecision RouteChat(const std::string& message);
    RoutingDecision RouteCodeGeneration(const std::string& description);
    
    // Execution
    bool LoadModel(const std::string& name);
    void UnloadModel(const std::string& name);
    std::string GetCurrentModel() const { return m_currentModel; }
    
    // VRAM Management
    int GetAvailableVRAM() const { return m_availableVRAM; }
    int GetUsedVRAM() const;
    bool CanFitModel(const ModelConfig& config) const;
    
    // Performance tracking
    void RecordLatency(const std::string& modelName, float latencyMs);
    void RecordQuality(const std::string& modelName, float qualityScore);
    json GetPerformanceStats() const;
    
private:
    TaskType ClassifyTask(const std::string& query);
    int EstimateTokens(const std::string& text);
    float CalculateScore(const ModelConfig& config, 
                        TaskType taskType,
                        int requiredTokens);
    
private:
    std::map<std::string, ModelConfig> m_models;
    std::map<std::string, float> m_latencyHistory;
    std::map<std::string, float> m_qualityHistory;
    
    std::string m_currentModel;
    int m_availableVRAM = 0;  // Will be detected
    mutable std::mutex m_mutex;
};

} // namespace CEO
} // namespace RawrXD
