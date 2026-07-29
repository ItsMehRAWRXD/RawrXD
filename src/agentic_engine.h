<<<<<<< HEAD
#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include "inference_engine.h"

// Forward declarations for Keep/Undo functionality
class AgenticFileOperations;
class AgenticErrorHandler;

/**
 * @class AgenticEngine
 * @brief Production-ready AI Core with full agentic capabilities (No Qt)
 */
class AgenticEngine {
public:
    explicit AgenticEngine();
    virtual ~AgenticEngine();
    
    void initialize();
    
    // AI Core Component 1: Code Analysis
    std::string analyzeCode(const std::string& code);
    std::string analyzeCodeQuality(const std::string& code);
    std::string detectPatterns(const std::string& code);
    std::string calculateMetrics(const std::string& code);
    std::string suggestImprovements(const std::string& code);
    
    // AI Core Component 2: Code Generation
    std::string generateCode(const std::string& prompt);
    std::string generateFunction(const std::string& signature, const std::string& description);
    std::string generateClass(const std::string& className, const std::string& spec);
    std::string generateTests(const std::string& code);
    std::string refactorCode(const std::string& code, const std::string& refactoringType);
    
    // AI Core Component 3: Task Planning
    std::string planTask(const std::string& goal);
    std::string decomposeTask(const std::string& task);
    std::string generateWorkflow(const std::string& project);
    std::string estimateComplexity(const std::string& task);
    
    // AI Core Component 4: NLP
    std::string understandIntent(const std::string& userInput);
    std::string extractEntities(const std::string& text);
    std::string generateNaturalResponse(const std::string& query, const std::string& context);
    std::string summarizeCode(const std::string& code);
    std::string explainError(const std::string& errorMessage);
    
    // AI Core Component 5: Learning
    void collectFeedback(const std::string& responseId, bool positive, const std::string& comment);
    void trainFromFeedback();
    std::string getLearningStats() const;
    void adaptToUserPreferences(const std::string& preferences);
    
    // AI Core Component 6: Security
    bool validateInput(const std::string& input);
    std::string sanitizeCode(const std::string& code);
    bool isCommandSafe(const std::string& command);
    
    // Agent tool capabilities
    std::string grepFiles(const std::string& pattern, const std::string& path = ".");
    std::string readFile(const std::string& filepath, int startLine = -1, int endLine = -1);
    std::string writeFile(const std::string& filepath, const std::string& content);
    std::string listDir(const std::string& path);
    std::string searchFiles(const std::string& query, const std::string& path = ".");
    std::string referenceSymbol(const std::string& symbol);
    
    // Command Execution
    std::string executeCommand(const std::string& command, bool isPowerShell = false);
    
    // RE Suite Integration
    std::string runDumpbin(const std::string& filePath, const std::string& mode);
    std::string runCodex(const std::string& filePath);
    std::string runCompiler(const std::string& sourceFile, const std::string& target);

    // Core Inference Integration
    void setInferenceEngine(RawrXD::InferenceEngine* engine) { m_inferenceEngine = engine; }
    RawrXD::InferenceEngine* inferenceEngine() const { return m_inferenceEngine; }


    void setChatProvider(std::function<std::string(const std::string&)> fn) { m_chatProvider = std::move(fn); }
    void clearChatProvider() { m_chatProvider = nullptr; }

    bool isModelLoaded() const {
        if (m_chatProvider) return true;
        return m_inferenceEngine && m_inferenceEngine->IsModelLoaded();
    }
    std::string currentModelPath() const { return m_currentModelPath; }
    bool loadLocalModel(const std::string& modelPath);
    std::string getModelStatus() const;
    void setWorkspaceRoot(const std::string& rootPath);
    std::string getWorkspaceRoot() const { return m_workspaceRoot; }
    
    // Configuration
    struct GenerationConfig {
        float temperature = 0.8f;
        float topP = 0.9f;
        int maxTokens = 2048;
        bool maxMode = false;
        bool deepThinking = false;
        bool deepResearch = false;
        bool noRefusal = false;
        bool autoCorrect = false;
    };

    void updateConfig(const GenerationConfig& config);
    // CLI/Native compat
    std::string chat(const std::string& message);
    std::string processQuery(const std::string& message) { return chat(message); }

    // SubAgent / Chaining / Swarm — thin wrappers for use from the engine
    // The full implementation lives in SubAgentManager; these are convenience
    // entry points for code that only has an AgenticEngine*.
    std::string runSubAgent(const std::string& description, const std::string& prompt);
    std::string executeChain(const std::vector<std::string>& steps, const std::string& initialInput = "");
    std::string executeSwarm(const std::vector<std::string>& prompts,
                              const std::string& mergeStrategy = "concatenate",
                              int maxParallel = 4);
    
private:
    std::string m_currentModelPath;
    std::string m_workspaceRoot;
    RawrXD::InferenceEngine* m_inferenceEngine = nullptr;


    GenerationConfig m_config;
    std::function<std::string(const std::string&)> m_chatProvider;
};
=======
#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>
#include "cpu_inference_engine.h" // Ensures RawrXD::InferenceEngine is visible
#include "universal_model_router.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @class AgenticEngine
 * @brief Production-ready AI Core with full agentic capabilities
 */
class AgenticEngine {
public:
    struct GenerationConfig {
        int maxTokens = 2048;
        float temperature = 0.7f;
        float topP = 0.9f;
        std::vector<std::string> stopSequences;
        bool stream = true;
    };

    AgenticEngine();
    ~AgenticEngine();

    void initialize();
    void shutdown();

    // Core Interaction
    std::string processQuery(const std::string& query);
    void processQueryAsync(const std::string& query, std::function<void(std::string)> callback);
    json planTask(const std::string& goal); // Added for implementation match
    std::string executePlan(const json& plan); // Execute a generated plan
    
    // Configuration
    void updateConfig(const GenerationConfig& config);
    // Fixed: Use RawrXD::InferenceEngine
    void setInferenceEngine(RawrXD::InferenceEngine* engine) { m_inferenceEngine = engine; }
    
    // Context Management
    void clearHistory();
    void appendSystemPrompt(const std::string& prompt);
    void loadContext(const std::string& filepath);
    void saveContext(const std::string& filepath);
    
    // Model Management
    std::vector<std::string> getAvailableModels();
    std::string getCurrentModel();
    
    void setModel(const std::string& modelPath);
    void setModelName(const std::string& modelName);
    void processMessage(const std::string& message, const std::string& editorContext = "");

    // Callbacks (replacing signals)
    std::function<void(const std::string&)> onResponseReady;
    std::function<void(bool)> onModelReady;
    std::function<void(bool, const std::string&)> onModelLoadingFinished;

    // Fixed: Use RawrXD::UniversalModelRouter
    void setRouter(std::shared_ptr<RawrXD::UniversalModelRouter> router) { m_router = router; }

private:
    bool m_modelLoaded;
    std::shared_ptr<RawrXD::UniversalModelRouter> m_router;
    std::string m_currentModelPath;
    RawrXD::InferenceEngine* m_inferenceEngine;
    GenerationConfig m_genConfig;
    std::unordered_map<std::string, std::string> m_userPreferences;
    
    // Internal helpers
    std::string buildPrompt(const std::string& query);
    void logInteraction(const std::string& query, const std::string& response);

    // Context implementation details
    std::vector<std::pair<std::string, std::string>> m_history;
    std::string m_systemPrompt;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
