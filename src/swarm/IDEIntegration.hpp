#pragma once

#include "SwarmOrchestrator.hpp"
#include "ArchitectAgent.hpp"
#include "FrontendSquad.hpp"
#include "BackendCore.hpp"
#include "QAHive.hpp"
#include "ReviewerAgents.hpp"
#include <functional>
#include <json/json.h>

namespace rawrxd {
namespace swarm {

// LSP-compatible message types
struct LSPMessage {
    std::string jsonrpc{"2.0"};
    std::string method;
    Json::Value params;
    std::optional<std::string> id;
};

// IDE command types
enum class IDECommand {
    GENERATE_PROJECT,
    GENERATE_COMPONENT,
    GENERATE_API,
    REFACTOR_CODE,
    ADD_FEATURE,
    FIX_BUG,
    WRITE_TESTS,
    REVIEW_CODE,
    OPTIMIZE_PERFORMANCE,
    GENERATE_DOCS
};

// IDE Integration - Connects swarm to VS Code/JetBrains/Cursor
class IDEIntegration {
public:
    struct ProjectRequest {
        std::string name;
        std::string description;
        std::string type;           // "web", "desktop", "mobile", "api"
        std::vector<std::string> features;
        std::string mood;           // "professional", "playful", "minimal", "bold"
        std::string targetPath;
        bool offlineMode{false};
    };
    
    struct GenerationProgress {
        enum Stage {
            DESIGNING = 0,
            GENERATING_FRONTEND = 1,
            GENERATING_BACKEND = 2,
            WRITING_TESTS = 3,
            REVIEWING = 4,
            FINALIZING = 5
        };
        
        Stage currentStage;
        int percentComplete;
        std::string currentTask;
        std::vector<std::string> completedTasks;
        std::vector<std::string> activeAgents;
        std::chrono::seconds elapsedTime;
        std::chrono::seconds estimatedTimeRemaining;
    };
    
    struct GeneratedProject {
        std::string projectPath;
        std::vector<std::string> files;
        std::map<std::string, std::string> fileContents;
        std::string readme;
        std::string architectureDoc;
        std::vector<std::string> setupCommands;
        int totalLines{0};
        int testCoverage{0};
        std::vector<std::string> securityFindings;
    };
    
    // Initialize IDE integration
    void initialize();
    void shutdown();
    
    // Main Vibe Coding entry point
    GeneratedProject generateProject(const ProjectRequest& request);
    
    // Incremental generation
    std::string generateComponent(
        const std::string& description,
        const std::string& existingCode
    );
    
    std::string generateAPIEndpoint(
        const std::string& description,
        const std::vector<ServiceSpec>& existingServices
    );
    
    std::string addFeature(
        const std::string& featureDescription,
        const std::string& codebasePath
    );
    
    // Code modification
    std::string refactorCode(
        const std::string& code,
        const std::string& instructions
    );
    
    std::string fixBug(
        const std::string& code,
        const std::string& errorDescription
    );
    
    std::string optimizePerformance(
        const std::string& code,
        const std::string& metrics
    );
    
    // Testing
    std::string generateTests(
        const std::string& code,
        const std::string& testType
    );
    
    // Code review
    ReviewerAgents::ReviewRequest reviewCode(
        const std::vector<std::string>& files
    );
    
    // Documentation
    std::string generateDocumentation(
        const std::vector<std::string>& files
    );
    
    std::string generateREADME(
        const GeneratedProject& project
    );
    
    // Progress callbacks
    using ProgressCallback = std::function<void(const GenerationProgress&)>;
    void setProgressCallback(ProgressCallback callback);
    
    // LSP integration
    void handleLSPMessage(const LSPMessage& message);
    LSPMessage createLSPResponse(const std::string& id, const Json::Value& result);
    
    // File operations
    void writeFile(const std::string& path, const std::string& content);
    std::string readFile(const std::string& path);
    void createDirectory(const std::string& path);
    bool fileExists(const std::string& path);
    
    // Hot reload
    void enableHotReload(const std::string& projectPath);
    void disableHotReload();
    
    // Legacy refactor
    LegacyRefactorModule::CodebaseAnalysis analyzeLegacyCodebase(
        const std::string& path
    );
    
    std::vector<std::string> generateRefactorPlan(
        const LegacyRefactorModule::CodebaseAnalysis& analysis
    );
    
    bool executeRefactoring(
        const std::vector<std::string>& plan,
        const std::string& codebasePath
    );
    
private:
    SwarmOrchestrator* orchestrator_{nullptr};
    ArchitectAgent architect_;
    FrontendSquad frontend_;
    BackendCore backend_;
    QAHive qa_;
    ReviewerAgents reviewers_;
    CinematicVibeEngine vibeEngine_;
    DeepContextManager contextManager_;
    SafeExecutionSandbox sandbox_;
    
    ProgressCallback progressCallback_;
    GenerationProgress currentProgress_;
    
    void updateProgress(GenerationProgress::Stage stage, const std::string& task);
    void executeInSwarm(const std::vector<Task>& tasks);
    
    // Stage handlers
    ArchitectAgent::SystemDesign runArchitectPhase(const ProjectRequest& request);
    FrontendSquad::ComponentLibrary runFrontendPhase(
        const ArchitectAgent::SystemDesign& design
    );
    BackendCore::GeneratedBackend runBackendPhase(
        const ArchitectAgent::SystemDesign& design
    );
    std::vector<QAHive::TestResults> runQAPhase(
        const GeneratedProject& project
    );
    std::vector<ReviewerAgents::ReviewReport> runReviewPhase(
        const GeneratedProject& project
    );
};

// VS Code extension bridge
class VSCodeBridge {
public:
    void connect();
    void disconnect();
    bool isConnected() const;
    
    void sendMessage(const Json::Value& message);
    void onMessage(std::function<void(const Json::Value&)> handler);
    
    // Command handlers
    void handleGenerateProject(const Json::Value& params);
    void handleGenerateComponent(const Json::Value& params);
    void handleRefactor(const Json::Value& params);
    void handleReview(const Json::Value& params);
    void handleOptimize(const Json::Value& params);
    
private:
    bool connected_{false};
    std::function<void(const Json::Value&)> messageHandler_;
};

// JetBrains plugin bridge
class JetBrainsBridge {
public:
    void connect();
    void disconnect();
    bool isConnected() const;
    
    void sendMessage(const Json::Value& message);
    void onMessage(std::function<void(const Json::Value&)> handler);
};

// Cursor editor bridge
class CursorBridge {
public:
    void connect();
    void disconnect();
    bool isConnected() const;
    
    void sendMessage(const Json::Value& message);
    void onMessage(std::function<void(const Json::Value&)> handler);
};

} // namespace swarm
} // namespace rawrxd
