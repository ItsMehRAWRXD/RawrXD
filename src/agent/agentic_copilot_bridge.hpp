/**
 * @file agentic_copilot_bridge.hpp
 * @brief Bridge between agentic backend and IDE frontend (Qt-free)
 */
#pragma once

<<<<<<< HEAD
#include <string>
=======
#include <mutex>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <vector>
#include <mutex>
#include <memory>
<<<<<<< HEAD
#include <functional>
#include "json_types.hpp"
=======
#include <string>
#include <nlohmann/json.hpp>
#include "model_invoker.hpp"
#include "agentic_puppeteer.hpp"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class AgenticEngine;
class ChatInterface;
class MultiTabEditor;
class TerminalPool;
class AgenticExecutor;
class AIIntegrationHub; // Forward declare

<<<<<<< HEAD
class AgenticCopilotBridge {
public:
    AgenticCopilotBridge();
    ~AgenticCopilotBridge();
    void initialize(AgenticEngine* engine, ChatInterface* chat, MultiTabEditor* editor,
                   TerminalPool* terminals, AgenticExecutor* executor);
=======
using json = nlohmann::json;

class AgenticCopilotBridge {

public:
    explicit AgenticCopilotBridge();
    ~AgenticCopilotBridge();

    // No copy
    AgenticCopilotBridge(const AgenticCopilotBridge&) = delete;
    AgenticCopilotBridge& operator=(const AgenticCopilotBridge&) = delete;

    // Initialization
    void initialize(AgenticEngine* engine, ChatInterface* chat, MultiTabEditor* editor, 
                   TerminalPool* terminals, AgenticExecutor* executor);
    
    void setIntegrationHub(std::shared_ptr<AIIntegrationHub> hub) { m_integrationHub = hub; }

    // Code Generation & Analysis
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string generateCodeCompletion(const std::string& context, const std::string& prefix);
    std::string analyzeActiveFile();
    std::string suggestRefactoring(const std::string& code);
    std::string generateTestsForCode(const std::string& code);
<<<<<<< HEAD
    std::string askAgent(const std::string& question, const JsonObject& context = JsonObject());
    std::string continuePreviousConversation(const std::string& followUp);
    std::string executeWithFailureRecovery(const std::string& prompt);
    std::string hotpatchResponse(const std::string& originalResponse, const JsonObject& context);
    bool detectAndCorrectFailure(std::string& response, const JsonObject& context);
    JsonObject executeAgentTask(const JsonObject& task);
    JsonArray planMultiStepTask(const std::string& goal);
    JsonObject transformCode(const std::string& code, const std::string& transformation);
    std::string explainCode(const std::string& code);
    std::string findBugs(const std::string& code);
    void submitFeedback(const std::string& feedback, bool isPositive);
    void updateModel(const std::string& newModelPath);
    JsonObject trainModel(const std::string& datasetPath, const std::string& modelPath, const JsonObject& config);
    bool isTrainingModel() const;
    void showResponse(const std::string& response);
    void displayMessage(const std::string& message);

    // Event handlers (replace Qt slots)
    void onChatMessage(const std::string& message);
    void onModelLoaded(const std::string& modelPath);
    void onEditorContentChanged();
    void onTrainingProgress(int epoch, int totalEpochs, float loss, float perplexity);
    void onTrainingCompleted(const std::string& modelPath, float finalPerplexity);

    // Callbacks (replace Qt signals)
    std::function<void(const std::string&)> onCompletionReady;
    std::function<void(const std::string&)> onAnalysisReady;
    std::function<void(const std::string&)> onAgentResponseReady;
    std::function<void(const JsonObject&)> onTaskExecuted;
    std::function<void(const std::string&)> onErrorOccurred;
    std::function<void()> onModelUpdated;
    std::function<void(int, int, float, float)> onTrainingProgressCb;
    std::function<void(const std::string&, float)> onTrainingCompletedCb;
    std::function<void()> onFeedbackSubmitted;
    std::function<void(const std::string&)> onResponseReady;
    std::function<void(const std::string&)> onMessageDisplayed;
    std::function<void(const std::string&, const std::string&)> onChatMessageProcessed;
    std::function<void(const std::string&)> onModelLoadedCb;
    std::function<void(const std::string&)> onEditorAnalysisReady;

private:
    std::string correctHallucinations(const std::string& response, const JsonObject& context);
    std::string enforceResponseFormat(const std::string& response, const std::string& format);
    std::string bypassRefusals(const std::string& response, const std::string& originalPrompt);
    JsonObject buildExecutionContext();
    JsonObject buildCodeContext(const std::string& code);
    JsonObject buildFileContext();

    mutable std::mutex m_mutex;
=======

    // Conversation & Interaction
    std::string askAgent(const std::string& question, const json& context = json::object());
    std::string continuePreviousConversation(const std::string& followUp);

    // Execution & Error Recovery
    std::string executeWithFailureRecovery(const std::string& prompt);
    std::string hotpatchResponse(const std::string& originalResponse, const json& context);
    bool detectAndCorrectFailure(std::string& response, const json& context);

    // Accessors for derived classes and integration
    ModelInvoker* getModelInvoker() const { return m_modelInvoker.get(); } // Expose internal invoker if used as fallback

private:
    std::mutex m_mutex;
    std::shared_ptr<AIIntegrationHub> m_integrationHub;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    AgenticEngine* m_agenticEngine = nullptr;
    ChatInterface* m_chatInterface = nullptr;
    MultiTabEditor* m_multiTabEditor = nullptr;
    TerminalPool* m_terminalPool = nullptr;
    AgenticExecutor* m_agenticExecutor = nullptr;
<<<<<<< HEAD
    JsonArray m_conversationHistory;
    std::string m_lastConversationContext;
    bool m_hotpatchingEnabled = true;
    bool m_isTraining = false;
=======

    // Fallback invoker if engine is missing
    std::unique_ptr<ModelInvoker> m_modelInvoker;
    std::unique_ptr<AgenticPuppeteer> m_puppeteer;

    void completionReady(const std::string& result);
    void analysisReady(const std::string& result);
    void errorOccurred(const std::string& error);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
