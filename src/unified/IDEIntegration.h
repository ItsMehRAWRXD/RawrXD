#pragma once

//==============================================================================
// IDEIntegration.h - IDE Shell Integration
// Phase 15: Complete System Unification
//
// This file provides the integration layer between the existing IDE components
// (Win32IDE, Editor, Monaco) and the unified RawrXDHost.
//
// It replaces the previous external API calls with direct service access.
//==============================================================================

#include "RawrXDHost.h"
#include <functional>
#include <memory>

namespace RawrXD {
namespace Unified {

//==============================================================================
// IDE AI Integration
// Connects IDE editor to unified AI service
//==============================================================================
class IDEAIIntegration {
public:
    static IDEAIIntegration& Instance();
    
    // Initialize with host
    void Initialize(RawrXDHost* host);
    
    // Called by IDE when user requests completion
    void RequestCompletion(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& language,
        std::function<void(const std::string& completion)> callback
    );
    
    // Called by IDE for inline chat
    void RequestInlineChat(
        const std::string& prompt,
        const std::string& context,
        std::function<void(const std::string& response)> callback
    );
    
    // Check if AI is available
    bool IsAIAvailable() const;
    
    // Get model info for UI display
    std::string GetModelName() const;
    
private:
    RawrXDHost* host_ = nullptr;
};

//==============================================================================
// IDE Compiler Integration
// Connects IDE build commands to unified compiler service
//==============================================================================
class IDECompilerIntegration {
public:
    static IDECompilerIntegration& Instance();
    
    void Initialize(RawrXDHost* host);
    
    // Called by IDE to compile current file
    struct CompileResult {
        bool success = false;
        std::string output;
        std::string errors;
        int errorCount = 0;
        int warningCount = 0;
    };
    
    CompileResult CompileFile(
        const std::string& sourcePath,
        const std::string& language
    );
    
    // Called by IDE to build project
    CompileResult BuildProject(
        const std::string& projectPath
    );
    
    // Get supported languages for UI
    std::vector<std::string> GetSupportedLanguages() const;
    
private:
    RawrXDHost* host_ = nullptr;
};

//==============================================================================
// IDE Agent Integration
// Connects IDE agent panel to unified agent service
//==============================================================================
class IDEAgentIntegration {
public:
    static IDEAgentIntegration& Instance();
    
    void Initialize(RawrXDHost* host);
    
    // Execute agent task from IDE
    void ExecuteTask(
        const std::string& task,
        std::function<void(const std::string& output)> onProgress,
        std::function<void(bool success, const std::string& result)> onComplete
    );
    
    // Activate specific agent mode
    void ActivateAgent(const std::string& agentType);
    
    // Get available agents for UI
    std::vector<std::string> GetAvailableAgents() const;
    
private:
    RawrXDHost* host_ = nullptr;
};

//==============================================================================
// IDE Event Integration
// Connects IDE events to unified EventBus
//==============================================================================
class IDEEventIntegration {
public:
    static IDEEventIntegration& Instance();
    
    void Initialize(RawrXDHost* host);
    
    // Fire IDE events
    void FireDocumentOpened(const std::string& path);
    void FireDocumentModified(const std::string& path);
    void FireDocumentSaved(const std::string& path);
    void FireBuildStarted();
    void FireBuildCompleted(bool success);
    void FireAICompletionRequested();
    void FireAICompletionReceived();
    
    // Subscribe to events
    void OnInferenceCompleted(std::function<void()> callback);
    void OnTaskCompleted(std::function<void()> callback);
    
private:
    RawrXDHost* host_ = nullptr;
};

//==============================================================================
// Main IDE Integration Setup
// Call this from IDE main() to wire everything
//==============================================================================
class IDEIntegration {
public:
    // Initialize all IDE integrations with unified host
    // Call this once at IDE startup
    static bool Initialize(RawrXDHost* host);
    
    // Shutdown
    static void Shutdown();
    
    // Check if initialized
    static bool IsInitialized();
};

} // namespace Unified
} // namespace RawrXD

//==============================================================================
// Convenience macros for IDE code
//==============================================================================

// AI completion from IDE
#define IDE_AI_COMPLETE(prefix, suffix, lang, callback) \
    RawrXD::Unified::IDEAIIntegration::Instance().RequestCompletion(prefix, suffix, lang, callback)

// Compile from IDE
#define IDE_COMPILE(file, lang) \
    RawrXD::Unified::IDECompilerIntegration::Instance().CompileFile(file, lang)

// Execute agent from IDE
#define IDE_AGENT_TASK(task, progress, complete) \
    RawrXD::Unified::IDEAgentIntegration::Instance().ExecuteTask(task, progress, complete)

// Fire IDE event
#define IDE_FIRE_EVENT(event_type, ...) \
    RawrXD::Unified::IDEEventIntegration::Instance().Fire##event_type(__VA_ARGS__)
