// ============================================================================
// CLI_SlashRouter.hpp — CLI Integration for 25 Slash Commands
// ============================================================================
// Provides full functionality for all 25 commands in headless/terminal mode.
// Integrates with InteractiveShell for seamless CLI experience.
// ============================================================================

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
    class CPUInferenceEngine;
    class InteractiveShell;
}

class AgenticEngine;

namespace RawrXD {
namespace CLI {

// ============================================================================
// Command Result Structure
// ============================================================================

struct SlashCommandResult {
    bool success = false;
    std::string output;
    std::string error;
};

using SlashCommandHandler = std::function<SlashCommandResult(const std::vector<std::string>&, void*)>;

// ============================================================================
// CLI Context - Provides IDE-like interface for commands
// ============================================================================

class CLIContext
{
public:
    CLIContext() = default;
    
    // File operations
    std::string getCurrentFile() const;
    void setCurrentFile(const std::string& path);
    
    std::string getEditorSelection() const;
    void setEditorSelection(const std::string& sel);
    
    // Model operations
    std::shared_ptr<CPUInferenceEngine> getInferenceEngine() const;
    void setInferenceEngine(std::shared_ptr<CPUInferenceEngine> engine);
    
    std::shared_ptr<AgenticEngine> getAgenticEngine() const;
    void setAgenticEngine(std::shared_ptr<AgenticEngine> engine);
    
    // Model state
    std::string getLoadedModelPath() const;
    void setLoadedModelPath(const std::string& path);
    
    std::vector<std::string> getAvailableModels() const;
    void setAvailableModels(const std::vector<std::string>& models);
    
    // Ollama connection
    bool isOllamaConnected() const;
    void setOllamaConnected(bool connected);
    
    // KV-Cache state
    uint64_t getKVCacheSeqLen() const;
    void setKVCacheSeqLen(uint64_t len);
    
    // Output
    void appendToOutput(const std::string& msg, const std::string& pane = "Output");
    void clearOutput(const std::string& pane = "Output");
    
    // Inference
    std::string sendMessageToModel(const std::string& prompt);
    bool loadModelFromPath(const std::string& path);
    
    // Current File Context Toggle
    bool isCurrentFileContextEnabled() const { return m_currentFileContextEnabled; }
    void setCurrentFileContextEnabled(bool enabled) { m_currentFileContextEnabled = enabled; }
    
    // Feedback tracking
    int markHelpful() { return ++m_helpfulCount; }
    int markUnhelpful() { return ++m_unhelpfulCount; }
    int helpfulCount() const { return m_helpfulCount; }
    int unhelpfulCount() const { return m_unhelpfulCount; }
    const std::string& modelBadge() const { return m_modelBadge; }
    void setModelBadge(const std::string& badge) { m_modelBadge = badge; }
    const std::string& getLastUserPrompt() const { return m_lastUserPrompt; }
    const std::string& getLastAssistantResponse() const { return m_lastAssistantResponse; }
    void setLastUserPrompt(const std::string& prompt) { m_lastUserPrompt = prompt; }
    void setLastAssistantResponse(const std::string& response) { m_lastAssistantResponse = response; }
    
private:
    std::string m_currentFile;
    std::string m_editorSelection;
    std::string m_loadedModelPath;
    std::vector<std::string> m_availableModels;
    std::shared_ptr<CPUInferenceEngine> m_inferenceEngine;
    std::shared_ptr<AgenticEngine> m_agenticEngine;
    bool m_ollamaConnected = false;
    uint64_t m_kvCacheSeqLen = 0;
    bool m_currentFileContextEnabled = true;
    std::string m_lastUserPrompt;
    std::string m_lastAssistantResponse;
    int m_helpfulCount = 0;
    int m_unhelpfulCount = 0;
    std::string m_modelBadge = "GPT-5.3-Codex • 0.9x";
};

// ============================================================================
// Public API
// ============================================================================

/// Initialize the CLI slash router with inference engines
void InitializeCLISlashRouter(
    std::shared_ptr<CPUInferenceEngine> inferenceEngine,
    std::shared_ptr<AgenticEngine> agenticEngine);

/// Get the global CLI context
CLIContext* GetCLIContext();

/// Process a slash command and return the result
std::string ProcessSlashCommand(const std::string& input);

/// Register all slash commands with an InteractiveShell
void RegisterSlashCommands(InteractiveShell& shell);

}  // namespace CLI
}  // namespace RawrXD

// ============================================================================
// C API for external integration
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/// Initialize the CLI slash router
void CLI_InitializeSlashRouter(void* inferenceEngine, void* agenticEngine);

/// Process a slash command
const char* CLI_ProcessSlashCommand(const char* input);

/// Register slash commands with an InteractiveShell
void CLI_RegisterSlashCommands(void* shell);

/// Set the current file context
void CLI_SetCurrentFile(const char* path);

/// Set the editor selection context
void CLI_SetEditorSelection(const char* selection);

#ifdef __cplusplus
}
#endif