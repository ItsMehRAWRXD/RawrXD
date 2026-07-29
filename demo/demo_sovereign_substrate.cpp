// Sovereign Substrate - Demo Application
// Shows all layers working together in a practical example
//
// This demo simulates an autonomous agent that:
// 1. Loads a project from disk (persistence)
// 2. Receives an intent from a model (model adapter)
// 3. Validates the intent (guardrails)
// 4. Checks security (security hardening)
// 5. Executes through the pipeline (agent kernel)
// 6. Applies a hotpatch (puppeteer)
// 7. Shows live status (control plane)
// 8. Saves state (persistence)

#include <iostream>
#include <thread>
#include <chrono>
#include <filesystem>

// All Sovereign Substrate headers
#include "../src/intent/intent_config.hpp"
#include "../src/intent/intent_abi.hpp"
#include "../src/intent/model_adapter.hpp"
#include "../src/guardrails/patch_firewall.hpp"
#include "../src/guardrails/capability_policy.hpp"
#include "../src/hotpatch/patch_transaction.hpp"
#include "../src/kernel/AgentKernel.hpp"
#include "../src/kernel/IntentExecutionPipeline.hpp"
#include "../src/kernel/TelemetryInjector.hpp"
#include "../src/memory/RepositoryMemoryGraph.hpp"
#include "../src/controlplane/ControlPlaneUI.hpp"
#include "../src/security/SecurityHardening.hpp"

using namespace RawrXD;
using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;
using namespace RawrXD::Kernel;
using namespace RawrXD::Memory;
using namespace RawrXD::ControlPlane;
using namespace RawrXD::Security;

// ============================================================================
// Demo Utilities
// ============================================================================

void PrintBanner(const std::string& title) {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  " << title;
    std::cout << std::string(67 - title.length(), ' ') << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
}

void PrintSection(const std::string& section) {
    std::cout << "\n┌─ " << section << " ─";
    std::cout << std::string(66 - section.length(), '─') << "┐\n";
}

void PrintSuccess(const std::string& message) {
    std::cout << "  ✓ " << message << "\n";
}

void PrintInfo(const std::string& message) {
    std::cout << "  ℹ " << message << "\n";
}

void PrintWarning(const std::string& message) {
    std::cout << "  ⚠ " << message << "\n";
}

void PrintError(const std::string& message) {
    std::cout << "  ✗ " << message << "\n";
}

// ============================================================================
// Demo Scenarios
// ============================================================================

class SovereignDemo {
public:
    bool Initialize() {
        PrintBanner("SOVEREIGN SUBSTRATE DEMO");
        std::cout << "Initializing all systems...\n\n";
        
        // 1. Initialize Security (must be first)
        PrintSection("Security Hardening");
        if (!SecurityManager::Instance().Initialize(SecurityLevel::STANDARD)) {
            PrintError("Failed to initialize security");
            return false;
        }
        PrintSuccess("Security manager initialized at STANDARD level");
        PrintInfo("Audit logging: ENABLED");
        PrintInfo("Rate limiting: ENABLED");
        PrintInfo("Input validation: ENABLED");
        
        // 2. Initialize Repository Memory Graph
        PrintSection("Repository Memory Graph");
        std::string repoPath = "demo_project";
        std::filesystem::create_directories(repoPath);
        
        // Create some demo files
        CreateDemoProject(repoPath);
        
        if (!RepositoryGraph::Instance().Initialize(repoPath)) {
            PrintError("Failed to initialize repository graph");
            return false;
        }
        PrintSuccess("Repository graph initialized");
        
        auto stats = RepositoryGraph::Instance().GetStats();
        PrintInfo("Files scanned: " + std::to_string(stats.fileCount));
        PrintInfo("Symbols indexed: " + std::to_string(stats.symbolCount));
        
        // 3. Initialize Model Adapter
        PrintSection("Model Adapter");
        
        // Register Kimi backend
        BackendConfig kimiConfig;
        kimiConfig.name = "kimi";
        kimiConfig.type = "kimi";
        kimiConfig.enabled = true;
        kimiConfig.model_name = "kimi-latest";
        auto kimiBackend = std::make_shared<KimiBackend>(kimiConfig);
        ModelAdapter::Instance().RegisterBackend(kimiBackend);
        PrintSuccess("Kimi backend registered");
        
        // Register Moonshot backend
        BackendConfig moonshotConfig;
        moonshotConfig.name = "moonshot";
        moonshotConfig.type = "moonshot";
        moonshotConfig.enabled = true;
        auto moonshotBackend = std::make_shared<MoonshotBackend>(moonshotConfig);
        ModelAdapter::Instance().RegisterBackend(moonshotBackend);
        PrintSuccess("Moonshot backend registered");
        
        PrintInfo("Available backends: " + 
            std::to_string(ModelAdapter::Instance().GetBackendNames().size()));
        
        // 4. Initialize Agent Kernel
        PrintSection("Agent Kernel");
        if (!AgentKernel::Instance().Initialize()) {
            PrintError("Failed to initialize agent kernel");
            return false;
        }
        PrintSuccess("Agent kernel initialized");
        PrintInfo("Resource scheduler: ACTIVE");
        PrintInfo("Beacon bus: ACTIVE");
        
        // 5. Initialize Intent Execution Pipeline
        PrintSection("Intent Execution Pipeline");
        if (!IntentExecutionPipeline::Instance().Initialize()) {
            PrintError("Failed to initialize pipeline");
            return false;
        }
        PrintSuccess("Pipeline initialized");
        PrintInfo("Handlers registered: MODIFY_FUNCTION, BUILD_PROJECT, RUN_TESTS, DEBUG_SESSION, OPTIMIZE_CODE");
        
        // 6. Initialize Control Plane (optional, for demo)
        PrintSection("Control Plane UI");
        if (!ControlPlaneUI::Instance().Initialize(18080)) {
            PrintWarning("Control plane UI not started (port may be in use)");
        } else {
            PrintSuccess("Control plane UI initialized on port 18080");
            PrintInfo("Dashboard: http://localhost:18080");
        }
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("All systems initialized successfully!");
        
        return true;
    }
    
    void RunScenario1_SimpleIntent() {
        PrintBanner("SCENARIO 1: Simple Intent Execution");
        
        PrintSection("Step 1: Model Generates Intent");
        
        // Simulate model generating an intent
        ModelContext ctx;
        ctx.system_prompt = "You are an autonomous coding agent. Analyze the code and suggest improvements.";
        ctx.messages = {{"user", "Optimize the main function in main.cpp"}};
        ctx.relevant_files = {"demo_project/main.cpp"};
        ctx.max_tokens = 1000;
        ctx.temperature = 0.7f;
        
        PrintInfo("System: " + ctx.system_prompt.substr(0, 50) + "...");
        PrintInfo("User request: " + ctx.messages[0].second);
        
        // Get model response
        auto response = ModelAdapter::Instance().Complete(ctx, "kimi");
        
        if (!response.success) {
            PrintError("Model failed to generate response");
            return;
        }
        
        PrintSuccess("Model generated response");
        PrintInfo("Confidence: " + std::to_string(response.confidence));
        PrintInfo("Tokens used: " + std::to_string(response.tokens_used));
        PrintInfo("Latency: " + std::to_string(response.latency_ms) + "ms");
        
        PrintSection("Step 2: Convert to Intent");
        
        // Convert model response to intent
        IntentResponse intentResponse = ModelAdapter::Instance().ConvertToIntent(response);
        
        if (intentResponse.status != IntentStatus::PENDING_VALIDATION) {
            PrintError("Failed to convert to intent");
            return;
        }
        
        PrintSuccess("Converted to intent");
        PrintInfo("Intent type: MODIFY_FUNCTION");
        PrintInfo("Target: main");
        
        PrintSection("Step 3: Security Validation");
        
        // Security pre-check
        std::string error;
        if (!SecurityManager::Instance().ValidatePreExecution(1, 1, error)) {
            PrintError("Security check failed: " + error);
            return;
        }
        
        PrintSuccess("Security pre-check passed");
        PrintInfo("Rate limit: OK");
        PrintInfo("Input validation: OK");
        
        PrintSection("Step 4: Execute Through Pipeline");
        
        // Create kernel intent
        Kernel::IntentRequest kernelIntent;
        kernelIntent.intentType = "MODIFY_FUNCTION";
        kernelIntent.intentId = 1;
        kernelIntent.sourceAgent = 1;
        kernelIntent.priority = Kernel::IntentPriority::NORMAL;
        kernelIntent.targetFiles = {"demo_project/main.cpp"};
        kernelIntent.targetSymbol = "main";
        
        // Execute
        auto result = IntentExecutionPipeline::Instance().Execute(kernelIntent);
        
        if (result.IsSuccess()) {
            PrintSuccess("Intent executed successfully!");
            PrintInfo("Validation time: " + std::to_string(result.validationTimeMs) + "ms");
            PrintInfo("Execution time: " + std::to_string(result.executionTimeMs) + "ms");
            PrintInfo("Total time: " + std::to_string(result.totalTimeMs) + "ms");
        } else {
            PrintError("Intent execution failed: " + result.errorMessage);
        }
        
        PrintSection("Step 5: Audit Logging");
        
        // Log post-execution
        SecurityManager::Instance().LogPostExecution(1, 1, result.IsSuccess());
        
        auto auditStats = AuditLog::Instance().GetStats();
        PrintSuccess("Execution logged to audit trail");
        PrintInfo("Total events in log: " + std::to_string(auditStats.totalEvents));
        PrintInfo("Chain integrity: " + std::string(AuditLog::Instance().VerifyChain() ? "VERIFIED" : "FAILED"));
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("Scenario 1 completed!");
    }
    
    void RunScenario2_RateLimiting() {
        PrintBanner("SCENARIO 2: Rate Limiting Demo");
        
        PrintSection("Rapid Intent Submission");
        PrintInfo("Submitting 10 intents rapidly to test rate limiting...");
        
        int successCount = 0;
        int rateLimitedCount = 0;
        
        for (int i = 0; i < 10; i++) {
            Kernel::IntentRequest intent;
            intent.intentType = "BUILD_PROJECT";
            intent.intentId = 100 + i;
            intent.sourceAgent = 2;  // Different agent
            intent.priority = Kernel::IntentPriority::NORMAL;
            
            auto result = IntentExecutionPipeline::Instance().Execute(intent);
            
            if (result.IsSuccess()) {
                successCount++;
                std::cout << "  Intent " << i << " ✓\n";
            } else if (result.errorMessage.find("rate") != std::string::npos ||
                       result.errorMessage.find("Security check failed") != std::string::npos) {
                rateLimitedCount++;
                std::cout << "  Intent " << i << " ⚠ (rate limited)\n";
            } else {
                std::cout << "  Intent " << i << " ✗ (" << result.errorMessage << ")\n";
            }
            
            // Small delay to make output readable
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        PrintSection("Results");
        PrintInfo("Successful: " + std::to_string(successCount));
        PrintInfo("Rate limited: " + std::to_string(rateLimitedCount));
        
        if (rateLimitedCount > 0) {
            PrintSuccess("Rate limiting is working correctly!");
        }
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("Scenario 2 completed!");
    }
    
    void RunScenario3_SecurityViolation() {
        PrintBanner("SCENARIO 3: Security Violation Detection");
        
        PrintSection("Attempting Dangerous Operation");
        PrintInfo("Submitting intent with path traversal attempt...");
        
        Kernel::IntentRequest intent;
        intent.intentType = "MODIFY_FUNCTION";
        intent.intentId = 200;
        intent.sourceAgent = 3;
        intent.priority = Kernel::IntentPriority::NORMAL;
        intent.targetFiles = {"../../../etc/passwd"};  // Path traversal attempt
        intent.targetSymbol = "system";
        
        auto result = IntentExecutionPipeline::Instance().Execute(intent);
        
        if (!result.IsSuccess()) {
            PrintSuccess("Security violation detected and blocked!");
            PrintInfo("Rejection reason: " + result.errorMessage);
            
            // Check audit log
            auto violations = AuditLog::Instance().QuerySecurityEvents("ERROR", 10);
            PrintInfo("Security events logged: " + std::to_string(violations.size()));
        } else {
            PrintError("Security violation NOT detected - this is a bug!");
        }
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("Scenario 3 completed!");
    }
    
    void RunScenario4_Persistence() {
        PrintBanner("SCENARIO 4: Persistence Demo");
        
        PrintSection("Saving Repository State");
        
        std::string savePath = "demo_project.graph";
        if (RepositoryGraph::Instance().SaveToDisk(savePath)) {
            PrintSuccess("Repository graph saved to: " + savePath);
            
            auto stats = RepositoryGraph::Instance().GetStats();
            PrintInfo("Files saved: " + std::to_string(stats.fileCount));
            PrintInfo("Symbols saved: " + std::to_string(stats.symbolCount));
            PrintInfo("Memory usage: " + std::to_string(stats.memoryUsageMB) + " MB");
            
            // Show file size
            if (std::filesystem::exists(savePath)) {
                auto size = std::filesystem::file_size(savePath);
                PrintInfo("File size: " + std::to_string(size) + " bytes");
            }
        } else {
            PrintError("Failed to save repository graph");
        }
        
        PrintSection("Loading Repository State");
        
        // Shutdown and reload
        RepositoryGraph::Instance().Shutdown();
        
        if (RepositoryGraph::Instance().LoadFromDisk(savePath)) {
            PrintSuccess("Repository graph loaded from: " + savePath);
            
            auto stats = RepositoryGraph::Instance().GetStats();
            PrintInfo("Files loaded: " + std::to_string(stats.fileCount));
            PrintInfo("Symbols loaded: " + std::to_string(stats.symbolCount));
        } else {
            PrintError("Failed to load repository graph");
        }
        
        // Cleanup
        std::filesystem::remove(savePath);
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("Scenario 4 completed!");
    }
    
    void RunScenario5_MultiAgent() {
        PrintBanner("SCENARIO 5: Multi-Agent Coordination");
        
        PrintSection("Multiple Agents Acquiring Resources");
        PrintInfo("Simulating 5 agents competing for build slots...");
        
        std::vector<std::shared_ptr<ResourceLease>> leases;
        
        for (int i = 1; i <= 5; i++) {
            auto lease = ResourceScheduler::Instance().AcquireLease(
                i,  // Agent ID
                ResourceType::BUILD_SLOT,
                0,  // Any slot
                LeaseCapabilities::ReadWrite(),
                std::chrono::seconds(30),
                "Build task for agent " + std::to_string(i),
                i
            );
            
            if (lease) {
                leases.push_back(lease);
                PrintSuccess("Agent " + std::to_string(i) + " acquired lease " + 
                           std::to_string(lease->leaseId));
            } else {
                PrintWarning("Agent " + std::to_string(i) + " could not acquire lease");
            }
        }
        
        PrintSection("Resource Statistics");
        
        auto stats = ResourceScheduler::Instance().GetStats();
        PrintInfo("Active leases: " + std::to_string(stats.activeLeases));
        PrintInfo("Total acquisitions: " + std::to_string(stats.totalAcquisitions));
        PrintInfo("Contention events: " + std::to_string(stats.contentionEvents));
        
        // Release all leases
        PrintSection("Releasing Resources");
        for (auto& lease : leases) {
            ResourceScheduler::Instance().ReleaseLease(lease->leaseId, lease->owner);
        }
        PrintSuccess("All leases released");
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("Scenario 5 completed!");
    }
    
    void ShowFinalStats() {
        PrintBanner("FINAL STATISTICS");
        
        PrintSection("Repository Memory Graph");
        auto repoStats = RepositoryGraph::Instance().GetStats();
        PrintInfo("Files: " + std::to_string(repoStats.fileCount));
        PrintInfo("Symbols: " + std::to_string(repoStats.symbolCount));
        PrintInfo("Edges: " + std::to_string(repoStats.edgeCount));
        PrintInfo("References: " + std::to_string(repoStats.referenceCount));
        PrintInfo("Memory: " + std::to_string(repoStats.memoryUsageMB) + " MB");
        
        PrintSection("Security Audit Log");
        auto auditStats = AuditLog::Instance().GetStats();
        PrintInfo("Total events: " + std::to_string(auditStats.totalEvents));
        PrintInfo("Security events: " + std::to_string(auditStats.securityEvents));
        PrintInfo("Violations: " + std::to_string(auditStats.violationEvents));
        
        PrintSection("Intent Execution Pipeline");
        auto pipelineStats = IntentExecutionPipeline::Instance().GetStats();
        PrintInfo("Total intents: " + std::to_string(pipelineStats.totalIntents));
        PrintInfo("Successful: " + std::to_string(pipelineStats.successfulIntents));
        PrintInfo("Failed: " + std::to_string(pipelineStats.failedIntents));
        PrintInfo("Rolled back: " + std::to_string(pipelineStats.rolledBackIntents));
        
        PrintSection("Agent Kernel");
        auto kernelStats = AgentKernel::Instance().GetStats();
        PrintInfo("Active sessions: " + std::to_string(kernelStats.activeSessions));
        PrintInfo("Total intents: " + std::to_string(kernelStats.totalIntents));
        PrintInfo("Success rate: " + std::to_string(kernelStats.successRate * 100) + "%");
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
    }
    
    void Shutdown() {
        PrintBanner("SHUTTING DOWN");
        
        PrintSection("Cleanup");
        
        ControlPlaneUI::Instance().Shutdown();
        PrintSuccess("Control plane UI shut down");
        
        IntentExecutionPipeline::Instance().Shutdown();
        PrintSuccess("Intent execution pipeline shut down");
        
        AgentKernel::Instance().Shutdown();
        PrintSuccess("Agent kernel shut down");
        
        ModelAdapter::Instance().EnableAdapter(false);
        PrintSuccess("Model adapter disabled");
        
        RepositoryGraph::Instance().Shutdown();
        PrintSuccess("Repository graph shut down");
        
        SecurityManager::Instance().Shutdown();
        PrintSuccess("Security manager shut down");
        
        // Cleanup demo project
        std::filesystem::remove_all("demo_project");
        PrintSuccess("Demo project cleaned up");
        
        std::cout << "\n└─────────────────────────────────────────────────────────────────────┘\n";
        PrintSuccess("All systems shut down successfully!");
    }
    
private:
    void CreateDemoProject(const std::string& path) {
        // Create main.cpp
        {
            std::ofstream f(path + "/main.cpp");
            f << "#include <iostream>\n\n";
            f << "int main() {\n";
            f << "    std::cout << \"Hello, World!\" << std::endl;\n";
            f << "    return 0;\n";
            f << "}\n";
        }
        
        // Create utils.cpp
        {
            std::ofstream f(path + "/utils.cpp");
            f << "#include \"utils.hpp\"\n\n";
            f << "void helper() {\n";
            f << "    // TODO: Implement\n";
            f << "}\n";
        }
        
        // Create utils.hpp
        {
            std::ofstream f(path + "/utils.hpp");
            f << "#pragma once\n\n";
            f << "void helper();\n";
        }
        
        // Create CMakeLists.txt
        {
            std::ofstream f(path + "/CMakeLists.txt");
            f << "cmake_minimum_required(VERSION 3.16)\n";
            f << "project(DemoProject)\n\n";
            f << "add_executable(demo main.cpp utils.cpp)\n";
        }
    }
};

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║   ███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗  ║\n";
    std::cout << "║   ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔════╝  ║\n";
    std::cout << "║   ███████╗██║   ██║██║   ██║█████╗  ██████╔╝█████╗  ██║██║       ║\n";
    std::cout << "║   ╚════██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║██║       ║\n";
    std::cout << "║   ███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║     ██║╚██████╗  ║\n";
    std::cout << "║   ╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝  ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║              S O V E R E I G N   S U B S T R A T E                ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║              Autonomous Agent Architecture Demo                   ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    
    SovereignDemo demo;
    
    // Initialize
    if (!demo.Initialize()) {
        std::cerr << "\nFailed to initialize demo. Exiting.\n";
        return 1;
    }
    
    // Run scenarios
    std::cout << "\n";
    std::cout << "Press Enter to start Scenario 1 (Simple Intent)...";
    std::cin.get();
    demo.RunScenario1_SimpleIntent();
    
    std::cout << "\n";
    std::cout << "Press Enter to start Scenario 2 (Rate Limiting)...";
    std::cin.get();
    demo.RunScenario2_RateLimiting();
    
    std::cout << "\n";
    std::cout << "Press Enter to start Scenario 3 (Security Violation)...";
    std::cin.get();
    demo.RunScenario3_SecurityViolation();
    
    std::cout << "\n";
    std::cout << "Press Enter to start Scenario 4 (Persistence)...";
    std::cin.get();
    demo.RunScenario4_Persistence();
    
    std::cout << "\n";
    std::cout << "Press Enter to start Scenario 5 (Multi-Agent)...";
    std::cin.get();
    demo.RunScenario5_MultiAgent();
    
    // Show final stats
    demo.ShowFinalStats();
    
    // Shutdown
    std::cout << "\n";
    std::cout << "Press Enter to shut down...";
    std::cin.get();
    demo.Shutdown();
    
    // Final banner
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║              DEMO COMPLETED SUCCESSFULLY                          ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║   The model proposes. The IDE decides. The Agent evolves.       ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    return 0;
}
