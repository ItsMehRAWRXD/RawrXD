// Agentic Copilot Bridge - MIGRATED to Unified Core Interface
// This file demonstrates migration from legacy AgenticEngine to unified Core
// 
// MIGRATION: Legacy AgenticEngine -> RawrXD::Agentic::Core
// BENEFITS: 
//   - Type-safe interface (no void*)
//   - Thread-safe by design
//   - Async task execution
//   - Proper error handling with Result<T>
//   - No Qt dependencies

#include "agentic_copilot_bridge.h"
#include "agentic/Core.h"           // NEW: Unified Core interface
#include "inference/InferenceEngine.h"  // NEW: Unified Inference interface
#include "core/ErrorHandling.h"     // NEW: Production error handling
#include "core/Logger.h"            // NEW: Structured logging

#include <mutex>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <future>

namespace RawrXD {
namespace Agentic {

// Forward declarations for IDE components (Qt-free)
class ChatInterface;
class MultiTabEditor;
class TerminalPool;
class AgenticExecutor;

/**
 * @class AgenticCopilotBridgeMigrated
 * @brief Migrated version using unified Core interface
 * 
 * MIGRATION CHANGES:
 * - Replaced AgenticEngine* with std::shared_ptr<Core>
 * - Replaced void* context with proper Task structs
 * - Replaced Qt signals with std::function callbacks
 * - Added structured error handling
 * - Added async task execution
 */
class AgenticCopilotBridgeMigrated {
public:
    explicit AgenticCopilotBridgeMigrated(const CoreConfig& config = {});
    ~AgenticCopilotBridgeMigrated();

    // Initialize with unified Core
    void Initialize(std::shared_ptr<Core> core);
    bool IsInitialized() const { return m_core != nullptr && m_core->IsInitialized(); }

    // Core Copilot-like capabilities (now async by default)
    std::future<TaskResult> GenerateCodeCompletionAsync(const std::string& context, const std::string& prefix = "");
    std::string GenerateCodeCompletion(const std::string& context, const std::string& prefix);
    
    std::future<TaskResult> AnalyzeActiveFileAsync();
    std::string AnalyzeActiveFile();
    
    std::future<TaskResult> SuggestRefactoringAsync(const std::string& code);
    std::string SuggestRefactoring(const std::string& code);
    
    std::future<TaskResult> GenerateTestsAsync(const std::string& code);
    std::string GenerateTestsForCode(const std::string& code);

    // Multi-turn conversation (async)
    std::future<TaskResult> AskAgentAsync(const std::string& question, const TaskContext& context = {});
    std::string AskAgent(const std::string& question, const TaskContext& context = {});
    
    std::future<TaskResult> ContinueConversationAsync(const std::string& followUp);
    std::string ContinuePreviousConversation(const std::string& followUp);

    // Failure recovery with proper error handling
    Result<std::string> ExecuteWithFailureRecovery(const std::string& prompt);
    
    // Response quality enhancement
    std::string HotpatchResponse(const std::string& original, const TaskContext& context);
    bool DetectAndCorrectFailure(std::string& response, const TaskContext& context);

    // Direct task execution via unified Core
    std::future<TaskResult> ExecuteAgentTaskAsync(const Task& task);
    TaskResult ExecuteAgentTask(const Task& task);
    
    std::future<TaskResult> PlanMultiStepTaskAsync(const std::string& goal);
    TaskResult PlanMultiStepTask(const std::string& goal);

    // Code transformation
    std::future<TaskResult> TransformCodeAsync(const std::string& code, const std::string& transformation);
    std::string TransformCode(const std::string& code, const std::string& transformation);
    
    std::future<TaskResult> ExplainCodeAsync(const std::string& code);
    std::string ExplainCode(const std::string& code);
    
    std::future<TaskResult> FindBugsAsync(const std::string& code);
    std::string FindBugs(const std::string& code);

    // Feedback and training
    void SubmitFeedback(const std::string& feedback, bool isPositive);
    void UpdateModel(const std::string& newModelPath);
    
    // Statistics
    CoreStats GetStats() const { return m_core ? m_core->GetStats() : CoreStats{}; }
    std::string GetLastError() const { return m_core ? m_core->GetLastError() : "Not initialized"; }

    // Callbacks (replacing Qt signals)
    std::function<void(const std::string&)> OnCompletionReady;
    std::function<void(const std::string&)> OnAnalysisReady;
    std::function<void(const std::string&)> OnAgentResponseReady;
    std::function<void(const TaskResult&)> OnTaskExecuted;
    std::function<void(const std::string&)> OnError;

private:
    // Core subsystem (unified interface)
    std::shared_ptr<Core> m_core;
    
    // Legacy component references (for IDE integration)
    ChatInterface* m_chatInterface = nullptr;
    MultiTabEditor* m_multiTabEditor = nullptr;
    TerminalPool* m_terminalPool = nullptr;
    AgenticExecutor* m_agenticExecutor = nullptr;
    
    // Conversation history (properly typed)
    std::vector<ConversationMessage> m_conversationHistory;
    std::string m_lastConversationContext;
    
    // Configuration
    bool m_hotpatchingEnabled = true;
    CoreConfig m_config;
    
    // Thread safety
    mutable std::mutex m_mutex;
    
    // Helper methods
    Task BuildCompletionTask(const std::string& context, const std::string& prefix);
    Task BuildAnalysisTask(const std::string& code);
    Task BuildConversationTask(const std::string& question, const TaskContext& ctx);
    TaskContext BuildExecutionContext();
    TaskContext BuildCodeContext(const std::string& code);
    
    std::string CorrectHallucinations(const std::string& response, const TaskContext& context);
    std::string EnforceResponseFormat(const std::string& response, const std::string& format);
};

// ============================================================================
// Implementation
// ============================================================================

AgenticCopilotBridgeMigrated::AgenticCopilotBridgeMigrated(const CoreConfig& config)
    : m_config(config) {
    Logger::Info("AgenticCopilotBridgeMigrated", "Instance created");
}

AgenticCopilotBridgeMigrated::~AgenticCopilotBridgeMigrated() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_core) {
        m_core->Shutdown(std::chrono::seconds(5));
    }
    
    m_conversationHistory.clear();
    m_lastConversationContext.clear();
    
    Logger::Info("AgenticCopilotBridgeMigrated", "Instance destroyed");
}

void AgenticCopilotBridgeMigrated::Initialize(std::shared_ptr<Core> core) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_core = core;
    
    if (!m_core->Initialize()) {
        Logger::Error("AgenticCopilotBridgeMigrated", "Failed to initialize Core");
        return;
    }
    
    Logger::Info("AgenticCopilotBridgeMigrated", "Initialized with unified Core");
}

// ============================================================================
// Code Completion (Migrated)
// ============================================================================

std::future<TaskResult> AgenticCopilotBridgeMigrated::GenerateCodeCompletionAsync(
    const std::string& context, const std::string& prefix) {
    
    if (!m_core) {
        std::promise<TaskResult> promise;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Core not initialized";
        promise.set_value(result);
        return promise.get_future();
    }
    
    Task task = BuildCompletionTask(context, prefix);
    return m_core->SubmitTask(task);
}

std::string AgenticCopilotBridgeMigrated::GenerateCodeCompletion(
    const std::string& context, const std::string& prefix) {
    
    auto future = GenerateCodeCompletionAsync(context, prefix);
    auto result = future.get();
    
    if (result.success) {
        if (OnCompletionReady) {
            OnCompletionReady(result.output);
        }
        return result.output;
    }
    
    if (OnError) {
        OnError(result.errorMessage);
    }
    return "// " + result.errorMessage;
}

Task AgenticCopilotBridgeMigrated::BuildCompletionTask(
    const std::string& context, const std::string& prefix) {
    
    Task task;
    task.type = TaskType::Inference;
    task.instruction = "Complete code: " + prefix;
    
    InferenceParams params;
    params.prompt = "Based on this context:\n" + context + 
                   "\n\nComplete the following code starting with: " + prefix +
                   "\nProvide ONLY the completion code, no explanation.";
    params.maxTokens = 256;
    params.temperature = 0.2f;  // Low temp for deterministic completion
    
    task.inferenceParams = params;
    return task;
}

// ============================================================================
// Code Analysis (Migrated)
// ============================================================================

std::future<TaskResult> AgenticCopilotBridgeMigrated::AnalyzeActiveFileAsync() {
    if (!m_core) {
        std::promise<TaskResult> promise;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Core not initialized";
        promise.set_value(result);
        return promise.get_future();
    }
    
    // Get code from editor (legacy component)
    std::string code;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_multiTabEditor) {
            // Legacy call - would be replaced with proper interface
            // code = m_multiTabEditor->getCurrentText();
        }
    }
    
    Task task = BuildAnalysisTask(code);
    return m_core->SubmitTask(task);
}

std::string AgenticCopilotBridgeMigrated::AnalyzeActiveFile() {
    auto future = AnalyzeActiveFileAsync();
    auto result = future.get();
    
    if (result.success) {
        std::string enhanced = result.output + "\n\n" +
            "Additional metrics:\n" +
            "- Lines analyzed: " + std::to_string(result.bytesProcessed / 50) + "\n" +
            "- Analysis time: " + std::to_string(result.durationMs) + "ms";
        
        if (OnAnalysisReady) {
            OnAnalysisReady(enhanced);
        }
        return enhanced;
    }
    
    return "Error: " + result.errorMessage;
}

Task AgenticCopilotBridgeMigrated::BuildAnalysisTask(const std::string& code) {
    Task task;
    task.type = TaskType::Inference;
    task.instruction = "Analyze code";
    
    InferenceParams params;
    params.prompt = "Analyze this code for quality, bugs, and improvements:\n" + code;
    params.maxTokens = 512;
    params.temperature = 0.3f;
    
    task.inferenceParams = params;
    return task;
}

// ============================================================================
// Conversation (Migrated)
// ============================================================================

std::future<TaskResult> AgenticCopilotBridgeMigrated::AskAgentAsync(
    const std::string& question, const TaskContext& context) {
    
    if (!m_core) {
        std::promise<TaskResult> promise;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Core not initialized";
        promise.set_value(result);
        return promise.get_future();
    }
    
    Task task = BuildConversationTask(question, context);
    
    // Add progress callback
    return m_core->SubmitTask(task, 
        [](float progress) { Logger::Debug("Agent", "Progress: " + std::to_string(progress)); },
        nullptr);
}

std::string AgenticCopilotBridgeMigrated::AskAgent(
    const std::string& question, const TaskContext& context) {
    
    auto future = AskAgentAsync(question, context);
    auto result = future.get();
    
    if (result.success) {
        // Store in conversation history
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_conversationHistory.push_back({"user", question, 
                std::chrono::system_clock::now()});
            m_conversationHistory.push_back({"assistant", result.output,
                std::chrono::system_clock::now()});
            m_lastConversationContext = result.output;
        }
        
        if (OnAgentResponseReady) {
            OnAgentResponseReady(result.output);
        }
        return result.output;
    }
    
    return "Error: " + result.errorMessage;
}

Task AgenticCopilotBridgeMigrated::BuildConversationTask(
    const std::string& question, const TaskContext& ctx) {
    
    Task task;
    task.type = TaskType::Inference;
    task.instruction = "Answer: " + question;
    
    // Build context from conversation history
    std::string conversationContext;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& msg : m_conversationHistory) {
            conversationContext += msg.role + ": " + msg.content + "\n\n";
        }
    }
    
    InferenceParams params;
    params.prompt = conversationContext + "User: " + question + "\nAssistant:";
    params.maxTokens = 1024;
    params.temperature = 0.7f;
    params.systemPrompt = "You are a helpful coding assistant. Provide clear, accurate, and concise responses.";
    
    task.inferenceParams = params;
    return task;
}

// ============================================================================
// Failure Recovery (Migrated with proper error handling)
// ============================================================================

Result<std::string> AgenticCopilotBridgeMigrated::ExecuteWithFailureRecovery(
    const std::string& prompt) {
    
    if (!m_core) {
        return Result<std::string>::Error("Core not initialized");
    }
    
    // Try primary execution
    Task task;
    task.type = TaskType::Inference;
    task.instruction = prompt;
    
    InferenceParams params;
    params.prompt = prompt;
    params.maxTokens = 512;
    task.inferenceParams = params;
    
    auto result = m_core->ExecuteSync(task);
    
    if (result.success) {
        std::string output = result.output;
        
        // Apply hotpatching if enabled
        if (m_hotpatchingEnabled) {
            TaskContext ctx = BuildExecutionContext();
            output = HotpatchResponse(output, ctx);
        }
        
        return Result<std::string>::Ok(output);
    }
    
    // Retry with different parameters
    params.temperature = 0.5f;  // More deterministic
    params.maxTokens = 1024;    // More room
    task.inferenceParams = params;
    
    auto retryResult = m_core->ExecuteSync(task);
    if (retryResult.success) {
        return Result<std::string>::Ok(retryResult.output);
    }
    
    return Result<std::string>::Error("Failed after retry: " + retryResult.errorMessage);
}

// ============================================================================
// Response Quality (Migrated)
// ============================================================================

std::string AgenticCopilotBridgeMigrated::HotpatchResponse(
    const std::string& original, const TaskContext& context) {
    
    std::string corrected = original;
    
    // Remove first-person phrasing
    corrected = CorrectHallucinations(corrected, context);
    
    // Enforce format
    corrected = EnforceResponseFormat(corrected, "markdown");
    
    return corrected;
}

std::string AgenticCopilotBridgeMigrated::CorrectHallucinations(
    const std::string& response, const TaskContext& context) {
    
    std::string corrected = response;
    
    // Replace common AI-isms
    const std::vector<std::pair<std::string, std::string>> replacements = {
        {"I can help with that. Here's my analysis:\n\n", "Analysis:\n\n"},
        {"I can help with that.", ""},
        {"I'm unable to", "Unable to"},
        {"I am unable to", "Unable to"},
        {"I can't", "Cannot"},
        {"I cannot", "Cannot"},
        {"Agent response to:", "Response:"},
        {"Corrected response:", "Updated response:"}
    };
    
    for (const auto& [from, to] : replacements) {
        size_t pos = 0;
        while ((pos = corrected.find(from, pos)) != std::string::npos) {
            corrected.replace(pos, from.length(), to);
            pos += to.length();
        }
    }
    
    return corrected;
}

std::string AgenticCopilotBridgeMigrated::EnforceResponseFormat(
    const std::string& response, const std::string& format) {
    
    if (format == "markdown") {
        // Ensure code blocks are properly formatted
        std::string formatted = response;
        
        // Add language specifier to code blocks if missing
        size_t pos = 0;
        while ((pos = formatted.find("```\n", pos)) != std::string::npos) {
            formatted.insert(pos + 3, "cpp");
            pos += 7;
        }
        
        return formatted;
    }
    
    return response;
}

// ============================================================================
// Context Building (Migrated)
// ============================================================================

TaskContext AgenticCopilotBridgeMigrated::BuildExecutionContext() {
    TaskContext ctx;
    ctx.workspaceRoot = m_config.workspaceRoot;
    ctx.language = "cpp";
    ctx.framework = "RawrXD";
    return ctx;
}

TaskContext AgenticCopilotBridgeMigrated::BuildCodeContext(const std::string& code) {
    TaskContext ctx = BuildExecutionContext();
    ctx.codeSnippet = code;
    ctx.lineCount = std::count(code.begin(), code.end(), '\n') + 1;
    return ctx;
}

} // namespace Agentic
} // namespace RawrXD

// ============================================================================
// Migration Summary
// ============================================================================
//
// LEGACY -> UNIFIED MAPPING:
//
// AgenticEngine*              -> std::shared_ptr<Core>
// void* context               -> TaskContext (properly typed)
// Qt signals (completionReady) -> std::function callbacks
// m_agenticEngine->generateCode() -> core->SubmitTask(task)
// m_agenticEngine->analyzeCode()  -> core->SubmitTask(task)
// m_agenticEngine->processMessage() -> core->ExecuteSync(task)
//
// BENEFITS ACHIEVED:
// - Type safety: No more void* casting
// - Thread safety: Built into Core interface
// - Async by default: All operations return futures
// - Error handling: Result<T> for explicit error handling
// - Testability: Easy to mock Core interface
// - No Qt: Pure C++17, portable
//
// COMPATIBILITY:
// - Can coexist with legacy code during migration
// - Adapters available for gradual transition
// - LegacyCoreAdapter bridges old -> new
