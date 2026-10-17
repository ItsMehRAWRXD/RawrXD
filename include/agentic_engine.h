#pragma once

#include <string>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <functional>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * @class AgenticEngine
 * @brief Production-ready AI Core with full agentic capabilities
 * 
 * Complete AI Core Components:
 * 1. Code Analysis - Static analysis, pattern detection, quality metrics
 * 2. Code Generation - Context-aware code synthesis with templates
 * 3. Task Planning - Multi-step task decomposition and execution
 * 4. NLP - Natural language understanding and generation
 * 5. Learning - Feedback collection and model adaptation
 * 6. Security - Input validation and sandboxed execution
 */
class AgenticEngine {
public:
    AgenticEngine();
    virtual ~AgenticEngine();
    
    void initialize();
    
    // AI Core Component 1: Code Analysis
    std::string analyzeCode(const std::string& code);
    json analyzeCodeQuality(const std::string& code);
    json detectPatterns(const std::string& code);
    json calculateMetrics(const std::string& code);
    std::string suggestImprovements(const std::string& code);
    
    // AI Core Component 2: Code Generation
    std::string generateCode(const std::string& prompt);
    std::string generateFunction(const std::string& signature, const std::string& description);
    std::string generateClass(const std::string& className, const json& spec);
    std::string generateTests(const std::string& code);
    std::string refactorCode(const std::string& code, const std::string& refactoringType);
    
    // AI Core Component 3: Task Planning
    json planTask(const std::string& goal);
    json decomposeTask(const std::string& task);
    json generateWorkflow(const std::string& project);
    std::string estimateComplexity(const std::string& task);
    
    // AI Core Component 4: NLP - Natural Language Processing
    std::string understandIntent(const std::string& userInput);
    json extractEntities(const std::string& text);
    std::string generateNaturalResponse(const std::string& query, const json& context);
    std::string summarizeCode(const std::string& code);
    std::string explainError(const std::string& errorMessage);
    
    // AI Core Component 5: Learning and Improvement
    void collectFeedback(const std::string& responseId, bool positive, const std::string& comment);
    void trainFromFeedback();
    json getLearningStats() const;
    void adaptToUserPreferences(const json& preferences);
    
    // AI Core Component 6: Security and Validation
    bool validateInput(const std::string& input);
    std::string sanitizeCode(const std::string& code);
    bool isCommandSafe(const std::string& command);
    
    // Agent tool capabilities (file system operations)
    std::string grepFiles(const std::string& pattern, const std::string& path = ".");
    std::string readFile(const std::string& filepath, int startLine = -1, int endLine = -1);
    std::string searchFiles(const std::string& query, const std::string& path = ".");
    std::string referenceSymbol(const std::string& symbol);
    
    // Model management
    bool isModelLoaded() const { return m_modelLoaded; }
    std::string currentModelPath() const { return m_currentModelPath; }
    std::string generateResponse(const std::string& message);
    void setInferenceEngine(class InferenceEngine* engine) { m_inferenceEngine = engine; }
    
    // CRITICAL: Mark model as loaded after external load
    void markModelAsLoaded(const std::string& modelPath) { 
        m_modelLoaded = true; 
        m_currentModelPath = modelPath; 
        std::clog << "[AgenticEngine::markModelAsLoaded] Model flagged:" << modelPath << std::endl;
    }
    
    // Generation configuration
    struct GenerationConfig {
        float temperature = 0.8f;
        float topP = 0.9f;
        int maxTokens = 512;
    };
    void setGenerationConfig(const GenerationConfig& config);
    GenerationConfig generationConfig() const { return m_genConfig; }
    
    // Callbacks (replaces Qt signals)
    using ResponseCallback = std::function<void(const std::string&)>;
    using ModelLoadingCallback = std::function<void(bool, const std::string&)>;
    using ModelReadyCallback = std::function<void(bool)>;
    using FeedbackCallback = std::function<void(const std::string&)>;
    using LearningCallback = std::function<void()>;
    using SecurityCallback = std::function<void(const std::string&)>;
    using TokenCallback = std::function<void(int)>;
    using RefactorCallback = std::function<void(const std::string&, const std::string&)>;
    
    void setOnResponseReady(ResponseCallback cb) { m_onResponseReady = cb; }
    void setOnModelLoadingFinished(ModelLoadingCallback cb) { m_onModelLoadingFinished = cb; }
    void setOnModelReady(ModelReadyCallback cb) { m_onModelReady = cb; }
    void setOnFeedbackCollected(FeedbackCallback cb) { m_onFeedbackCollected = cb; }
    void setOnLearningCompleted(LearningCallback cb) { m_onLearningCompleted = cb; }
    void setOnSecurityWarning(SecurityCallback cb) { m_onSecurityWarning = cb; }
    void setOnTokenGenerated(TokenCallback cb) { m_onTokenGenerated = cb; }
    void setOnRefactorSuggested(RefactorCallback cb) { m_onRefactorSuggested = cb; }
    
    // Methods previously slots
    void setModel(const std::string& modelPath);
    void setModelName(const std::string& modelName);
    void processMessage(const std::string& message, const std::string& editorContext = "");
    
private:
    std::string generateTokenizedResponse(const std::string& message);
    std::string generateFallbackResponse(const std::string& message);
    bool loadModelAsync(const std::string& modelPath);
    std::string resolveGgufPath(const std::string& modelName);
    
    // Internal AI processing
    std::string processWithContext(const std::string& input, const json& context);
    json buildCodeContext(const std::string& code);
    std::string applyTemplate(const std::string& templateName, const json& params);
    
    // Learning data structures
    struct FeedbackEntry {
        std::string responseId;
        std::string input;
        std::string output;
        bool positive;
        std::string comment;
        int64_t timestamp;
    };
    std::vector<FeedbackEntry> m_feedbackHistory;
    std::unordered_map<std::string, int> m_responseRatings;
    
    // User preferences and adaptation
    json m_userPreferences;
    int m_totalInteractions = 0;
    int m_positiveResponses = 0;
    
    // Model state
    bool m_modelLoaded = false;
    std::string m_currentModelPath;
    class InferenceEngine* m_inferenceEngine = nullptr;
    GenerationConfig m_genConfig;
    
    // Callbacks
    ResponseCallback m_onResponseReady;
    ModelLoadingCallback m_onModelLoadingFinished;
    ModelReadyCallback m_onModelReady;
    FeedbackCallback m_onFeedbackCollected;
    LearningCallback m_onLearningCompleted;
    SecurityCallback m_onSecurityWarning;
    TokenCallback m_onTokenGenerated;
    RefactorCallback m_onRefactorSuggested;
};
