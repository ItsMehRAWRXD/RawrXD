#pragma once

//==============================================================================
// RawrXDHost.h - Unified IDE Host
// Phase 15: Complete System Unification
// 
// This is the single entry point that binds all IDE components:
// - UI Shells (Win32/Electron/Web)
// - Agent Orchestrator
// - Inference Engine (Deep2)
// - Compiler Stack (69 languages)
// - Runtime Core
// - EventBus, ModelRegistry, ToolRegistry
//==============================================================================

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Forward declarations of existing components
namespace RawrXD {
    class EventBus;
    class ModelRegistry;
    class ToolRegistry;
    class RuntimeCore;
}

namespace Deep2 {
    class InferenceEngine;
    class ModelLoader;
}

namespace Sovereign {
    class CompilerStack;
    class RuntimeABI;
}

namespace RawrXD {
namespace Unified {

//==============================================================================
// Host Configuration
//==============================================================================
struct HostConfig {
    // Mode selection
    enum class Mode {
        IDE,        // Full IDE with GUI
        CLI,        // Command-line interface
        Server,     // API server mode
        Compile,    // Compiler-only mode
        Agent       // Agent-only mode
    };
    
    Mode mode = Mode::IDE;
    
    // Paths
    std::string workspacePath;
    std::string modelPath;      // Path to GGUF models
    std::string configPath;
    
    // Features
    bool enableAI = true;
    bool enableGPU = true;
    bool enableAgents = true;
    bool enableCompiler = true;
    
    // Network
    int serverPort = 11442;
    bool enableMCP = true;
};

//==============================================================================
// Unified AI Service Interface
// This is the single interface that all IDE components use for AI
//==============================================================================
class IAIService {
public:
    virtual ~IAIService() = default;
    
    // Core inference
    virtual bool Initialize(const std::string& modelPath) = 0;
    virtual void Shutdown() = 0;
    
    // Completion API (used by IDE)
    struct CompletionRequest {
        std::string prefix;
        std::string suffix;
        std::string language;
        int maxTokens = 128;
        float temperature = 0.2f;
    };
    
    struct CompletionResponse {
        std::string text;
        bool finished = false;
        float confidence = 0.0f;
    };
    
    virtual CompletionResponse Complete(const CompletionRequest& req) = 0;
    
    // Streaming API
    using TokenCallback = std::function<void(const std::string& token, bool finished)>;
    virtual void CompleteStreaming(const CompletionRequest& req, TokenCallback callback) = 0;
    
    // Chat API
    struct ChatMessage {
        std::string role;    // "user", "assistant", "system"
        std::string content;
    };
    
    struct ChatRequest {
        std::vector<ChatMessage> messages;
        int maxTokens = 1024;
        float temperature = 0.7f;
    };
    
    virtual std::string Chat(const ChatRequest& req) = 0;
    
    // Status
    virtual bool IsModelLoaded() const = 0;
    virtual std::string GetModelName() const = 0;
};

//==============================================================================
// Unified Compiler Service
// Wraps the 69-language compiler stack
//==============================================================================
class ICompilerService {
public:
    virtual ~ICompilerService() = default;
    
    virtual bool Initialize() = 0;
    
    struct CompileRequest {
        std::string sourcePath;
        std::string outputPath;
        std::string language;     // "c", "cpp", "rust", "go", etc.
        std::string targetArch;   // "x64", "arm64", "wasm"
        bool optimize = true;
    };
    
    struct CompileResult {
        bool success = false;
        std::string output;
        std::string errors;
        std::string binaryPath;
    };
    
    virtual CompileResult Compile(const CompileRequest& req) = 0;
    
    // Get list of supported languages
    virtual std::vector<std::string> GetSupportedLanguages() = 0;
};

//==============================================================================
// Unified Agent Service
// Wraps the agentic orchestration system
//==============================================================================
class IAgentService {
public:
    virtual ~IAgentService() = default;
    
    virtual bool Initialize() = 0;
    
    // Task execution
    struct TaskRequest {
        std::string description;
        std::string context;
        std::vector<std::string> tools;
        int maxIterations = 10;
    };
    
    struct TaskResult {
        bool success = false;
        std::string output;
        std::string artifacts;
        int iterationsUsed = 0;
    };
    
    virtual TaskResult ExecuteTask(const TaskRequest& req) = 0;
    
    // Agent types
    enum class AgentType {
        Planner,
        Coder,
        Reviewer,
        Compiler,
        Runtime
    };
    
    virtual bool ActivateAgent(AgentType type) = 0;
    virtual void DeactivateAgent(AgentType type) = 0;
};

//==============================================================================
// THE UNIFIED HOST
// Single class that owns and coordinates all subsystems
//==============================================================================
class RawrXDHost {
public:
    RawrXDHost();
    ~RawrXDHost();
    
    // Lifecycle
    bool Initialize(const HostConfig& config);
    void Shutdown();
    bool IsRunning() const;
    
    // Service accessors - these are the ONLY interfaces IDE components should use
    IAIService* GetAIService() const;
    ICompilerService* GetCompilerService() const;
    IAgentService* GetAgentService() const;
    
    // Event system access
    RawrXD::EventBus* GetEventBus() const;
    RawrXD::ModelRegistry* GetModelRegistry() const;
    RawrXD::ToolRegistry* GetToolRegistry() const;
    
    // Mode-specific runners
    int RunIDE();      // Blocks until IDE closes
    int RunCLI(int argc, char** argv);
    int RunServer();   // Blocks until server stops
    int RunCompile(const std::string& sourceFile, const std::string& outputFile);
    int RunAgent(const std::string& task);
    
    // Singleton access
    static RawrXDHost* Instance();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    static RawrXDHost* s_instance;
};

//==============================================================================
// Convenience macros for service access
//==============================================================================
#define RAWRXD_AI (RawrXD::Unified::RawrXDHost::Instance()->GetAIService())
#define RAWRXD_COMPILER (RawrXD::Unified::RawrXDHost::Instance()->GetCompilerService())
#define RAWRXD_AGENT (RawrXD::Unified::RawrXDHost::Instance()->GetAgentService())
#define RAWRXD_EVENTS (RawrXD::Unified::RawrXDHost::Instance()->GetEventBus())
#define RAWRXD_MODELS (RawrXD::Unified::RawrXDHost::Instance()->GetModelRegistry())
#define RAWRXD_TOOLS (RawrXD::Unified::RawrXDHost::Instance()->GetToolRegistry())

} // namespace Unified
} // namespace RawrXD
