#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace RawrXD {
namespace IDE {

// Task types for model routing
enum class TaskType {
    CodeCompletion,  // Quick inline suggestions (fast, small model)
    Chat,            // Interactive conversation (reasoning, large model)
    CodeEdit,        // Code transformation (precise, medium model)
    Embedding,       // Semantic search (specialized embedding model)
    Debugging,       // Debugging assistance (analytical, large model)
    Optimization,    // Performance optimization (specialized)
    Security,        // Security analysis (specialized)
    Documentation,   // Doc generation (varied)
};

// Model selection strategy with enhanced capabilities
struct ModelSelection {
    std::string modelName;
    std::string modelUrl;
    float expectedLatency;     // ms
    int contextWindow;         // tokens
    bool supportsStreaming;
    std::vector<TaskType> optimalFor;
    bool isEnsemble = false;   // Multi-model ensemble
    std::vector<std::string> ensembleModels;
    float confidence = 0.8f;   // Selection confidence
    bool isAvailable = true;
    int estimatedLatencyMs = 150;
    bool isABTest = false;     // A/B testing variant
    std::string testVariant;   // A/B test variant identifier
    bool needsReview = false;  // Model needs performance review
};

// Multi-modal model router
class MultiModalModelRouter {
public:
    MultiModalModelRouter();
    ~MultiModalModelRouter() = default;

    // Initialize available models
    bool initialize(const std::string& ollamaEndpoint = "http://localhost:11434");

    // Get optimal model for task
    ModelSelection selectModel(
        TaskType taskType,
        int contextSize = 0,
        bool prioritizeSpeed = false
    );

    // Get optimal model for specific use case
    ModelSelection selectModelForUseCase(
        const std::string& useCase,
        bool prioritizeSpeed = false
    );

    // Get completion model (fast, small, optimized for suggestions)
    ModelSelection getCompletionModel();

    // Get chat model (reasoning, large, interactive)
    ModelSelection getChatModel();

    // Get edit model (precise, medium, good at transformations)
    ModelSelection getEditModel();

    // Get embedding model (semantic search)
    ModelSelection getEmbeddingModel();

    // Get debug model (analytical, good at reasoning about bugs)
    ModelSelection getDebugModel();

    // Get optimization model (specialized for performance)
    ModelSelection getOptimizationModel();

    // Get security model (specialized for vulnerability detection)
    ModelSelection getSecurityModel();

    // Get documentation model
    ModelSelection getDocumentationModel();

    // Enhanced capability-based routing with 7 optimizations
    ModelSelection selectModelWithCapabilities(TaskType task);

    // Register custom model
    void registerModel(
        const std::string& modelName,
        const std::string& modelUrl,
        const std::vector<TaskType>& optimalFor,
        float expectedLatency,
        int contextWindow,
        bool supportsStreaming
    );

    // Set default model for task type
    void setDefaultModel(TaskType taskType, const std::string& modelName);

    // Get all available models
    std::vector<ModelSelection> getAvailableModels();

    // Get models for specific task
    std::vector<ModelSelection> getModelsForTask(TaskType taskType);

    // Configure model preferences
    void setSpeedPriority(float speedWeight);      // 0.0-1.0
    void setQualityPriority(float qualityWeight);  // 0.0-1.0
    void setMemoryLimit(int limitMB);

    // Get routing statistics
    struct RoutingStats {
        int totalRequests;
        std::unordered_map<std::string, int> modelUsage;
        std::unordered_map<std::string, float> avgLatency;
    };
    RoutingStats getStatistics();

private:
    struct ModelInfo {
        std::string name;
        std::string url;
        std::vector<TaskType> optimalFor;
        float expectedLatency;
        int contextWindow;
        bool supportsStreaming;
        int usageCount;
        float totalLatency;
    };

    // Model scoring
    float scoreModel(
        const ModelInfo& model,
        TaskType taskType,
        int contextSize
    );

    // Enhanced routing helper methods (Batch 1 - 7 optimizations)
    std::vector<std::pair<std::string, double>> scoreModelsForTask(TaskType task);
    void filterByCostOptimization(std::vector<std::pair<std::string, double>>& candidates, TaskType task);
    std::string predictLatencyAndSelect(const std::vector<std::pair<std::string, double>>& candidates);
    bool shouldUseEnsemble(TaskType task);
    ModelSelection createEnsembleSelection(const std::string& primaryModel, TaskType task);
    void updatePerformanceMetrics(const std::string& model);
    bool shouldRunABTest(TaskType task);
    ModelSelection selectABTestVariant(const std::string& primaryModel, TaskType task);
    ModelSelection selectWithHealthChecks(const std::string& model, TaskType task);

    // Load models from Ollama
    bool loadModelsFromOllama();

    std::string m_ollamaEndpoint;
    std::unordered_map<std::string, ModelInfo> m_models;
    std::unordered_map<int, std::string> m_defaultModels;  // TaskType -> model name
    float m_speedWeight;
    float m_qualityWeight;
    int m_memoryLimit;

    // Enhanced routing data structures (Batch 1 optimizations)
    struct ModelCapabilities {
        double reasoning = 0.0;    // Logical analysis and problem solving
        double coding = 0.0;       // Code generation and understanding
        double creativity = 0.0;   // Creative tasks and generation
        double speed = 0.0;        // Inference speed score
        double cost = 0.0;         // Cost per token (normalized)
    };

    struct ModelPerformance {
        double avgLatencyMs = 0.0;
        double successRate = 1.0;
        int totalRequests = 0;
        std::chrono::steady_clock::time_point lastUsed;
    };

    std::unordered_map<std::string, ModelCapabilities> m_modelCapabilities;
    std::unordered_map<std::string, ModelPerformance> m_modelPerformance;
    std::unordered_map<std::string, ModelInfo> m_availableModels;

    // Legacy latency tracking (maintained for compatibility)
    int m_completionModelLatency;
    int m_chatModelLatency;
    int m_editModelLatency;
};

} // namespace IDE
} // namespace RawrXD
