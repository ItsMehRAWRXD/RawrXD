#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <chrono>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

// Forward declarations
class AgenticEngine;
class ChatInterface;
class MultiTabEditor;
class TerminalPool;
class AgenticExecutor;

/**
 * @class AgenticCopilotBridge
 * @brief Production-ready Copilot/Cursor-like agent system with thread safety
 * 
 * Features:
 * - Real-time code analysis and generation
 * - Inline code completions (like Copilot)
 * - Multi-turn agent conversations with history
 * - Automatic failure detection and recovery
 * - Model hotpatching for different models
 * - Puppeteer-based response correction
 * - User feedback collection and analysis
 * - Thread-safe concurrent operations
 * - Full IDE integration with all components
 * - On-device model fine-tuning
 */
class AgenticCopilotBridge {
public:
    AgenticCopilotBridge();
    virtual ~AgenticCopilotBridge();
    
    // Initialize with IDE components
    void initialize(AgenticEngine* engine, ChatInterface* chat, 
                   MultiTabEditor* editor, TerminalPool* terminals, AgenticExecutor* executor);
    
    // Core Copilot-like capabilities (thread-safe)
    std::string generateCodeCompletion(const std::string& context, const std::string& prefix = "");
    std::string analyzeActiveFile();
    std::string suggestRefactoring(const std::string& code);
    std::string generateTestsForCode(const std::string& code);
    
    // Multi-turn conversation (like Copilot Chat)
    std::string askAgent(const std::string& question, const json& context = json::object());
    std::string continuePreviousConversation(const std::string& followUp);
    
    // Puppeteering and hotpatching (Cursor IDE style)
    std::string executeWithFailureRecovery(const std::string& prompt);
    std::string hotpatchResponse(const std::string& originalResponse, const json& context);
    bool detectAndCorrectFailure(std::string& response, const json& context);
    
    // Direct agent command execution (full agentic)
    json executeAgentTask(const json& task);
    json planMultiStepTask(const std::string& goal);
    
    // Code transformation (refactoring, generation, analysis)
    json transformCode(const std::string& code, const std::string& transformation);
    std::string explainCode(const std::string& code);
    std::string findBugs(const std::string& code);
    
    // Production features: User feedback mechanism
    void submitFeedback(const std::string& feedback, bool isPositive);
    
    // Production features: Model updates
    void updateModel(const std::string& newModelPath);
    
    // Production features: Model training
    json trainModel(const std::string& datasetPath, const std::string& modelPath, const json& config);
    bool isTrainingModel() const;
    
    // Production features: Enhanced UI integration
    void showResponse(const std::string& response);
    void displayMessage(const std::string& message);
    
    // Callbacks (replaces Qt signals)
    using CompletionCallback = std::function<void(const std::string&)>;
    using AnalysisCallback = std::function<void(const std::string&)>;
    using AgentResponseCallback = std::function<void(const std::string&)>;
    using TaskExecutedCallback = std::function<void(const json&)>;
    using ErrorCallback = std::function<void(const std::string&)>;
    using FeedbackCallback = std::function<void()>;
    using ModelUpdatedCallback = std::function<void()>;
    using TrainingProgressCallback = std::function<void(int, int, float, float)>;
    using TrainingCompletedCallback = std::function<void(const std::string&, float)>;
    
    void setOnCompletionReady(CompletionCallback cb) { m_onCompletionReady = cb; }
    void setOnAnalysisReady(AnalysisCallback cb) { m_onAnalysisReady = cb; }
    void setOnAgentResponseReady(AgentResponseCallback cb) { m_onAgentResponseReady = cb; }
    void setOnTaskExecuted(TaskExecutedCallback cb) { m_onTaskExecuted = cb; }
    void setOnErrorOccurred(ErrorCallback cb) { m_onErrorOccurred = cb; }
    void setOnFeedbackSubmitted(FeedbackCallback cb) { m_onFeedbackSubmitted = cb; }
    void setOnModelUpdated(ModelUpdatedCallback cb) { m_onModelUpdated = cb; }
    void setOnTrainingProgress(TrainingProgressCallback cb) { m_onTrainingProgress = cb; }
    void setOnTrainingCompleted(TrainingCompletedCallback cb) { m_onTrainingCompleted = cb; }
    
private:
    // Response correction and validation
    std::string correctHallucinations(const std::string& response, const json& context);
    std::string enforceResponseFormat(const std::string& response, const std::string& format);
    std::string bypassRefusals(const std::string& response, const std::string& originalPrompt);
    
    // Context building
    json buildExecutionContext();
    json buildCodeContext(const std::string& code);
    json buildFileContext();
    
    // Internal state
    AgenticEngine* m_agenticEngine = nullptr;
    ChatInterface* m_chatInterface = nullptr;
    MultiTabEditor* m_multiTabEditor = nullptr;
    TerminalPool* m_terminalPool = nullptr;
    AgenticExecutor* m_agenticExecutor = nullptr;
    
    std::string m_lastConversationContext;
    json m_conversationHistory;
    bool m_hotpatchingEnabled = true;
    
    std::mutex m_mutex; // Mutex for thread-safe operations
    
    // Callbacks (replaces Qt signals)
    CompletionCallback m_onCompletionReady;
    AnalysisCallback m_onAnalysisReady;
    AgentResponseCallback m_onAgentResponseReady;
    TaskExecutedCallback m_onTaskExecuted;
    ErrorCallback m_onErrorOccurred;
    FeedbackCallback m_onFeedbackSubmitted;
    ModelUpdatedCallback m_onModelUpdated;
    TrainingProgressCallback m_onTrainingProgress;
    TrainingCompletedCallback m_onTrainingCompleted;
};
