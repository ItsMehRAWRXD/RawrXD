// Sovereign Substrate - API Integration Example
// Shows how to integrate the Sovereign Substrate into your application

#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

// Include Sovereign Substrate headers
#include "kernel/AgentKernel.hpp"
#include "tools/tool_system.hpp"
#include "security/SecurityHardening.hpp"
#include "intent/model_adapter.hpp"
#include "memory/RepositoryMemoryGraph.hpp"

using namespace RawrXD;

class MyApplication {
private:
    std::unique_ptr<AgentKernel> kernel_;
    std::unique_ptr<Security::SecurityManager> security_;
    bool running_ = false;

public:
    MyApplication() = default;
    ~MyApplication() { Shutdown(); }

    // Initialize the Sovereign Substrate
    bool Initialize() {
        std::cout << "Initializing Sovereign Substrate...\n";

        // Initialize security first
        security_ = std::make_unique<Security::SecurityManager>();
        if (!security_->Initialize()) {
            std::cerr << "Failed to initialize security\n";
            return false;
        }

        // Initialize agent kernel
        kernel_ = std::make_unique<AgentKernel>();
        if (!kernel_->Initialize()) {
            std::cerr << "Failed to initialize agent kernel\n";
            return false;
        }

        // Load repository memory
        auto& memory = RepositoryGraph::Instance();
        if (memory.LoadFromDisk("project.graph")) {
            std::cout << "Loaded repository memory from disk\n";
        }

        // Register custom tools
        RegisterCustomTools();

        // Set up event handlers
        SetupEventHandlers();

        running_ = true;
        std::cout << "Sovereign Substrate initialized successfully\n";
        return true;
    }

    // Shutdown gracefully
    void Shutdown() {
        if (!running_) return;

        std::cout << "Shutting down Sovereign Substrate...\n";

        // Save repository memory
        RepositoryGraph::Instance().SaveToDisk("project.graph");

        // Shutdown kernel
        if (kernel_) {
            kernel_->Shutdown();
        }

        running_ = false;
        std::cout << "Shutdown complete\n";
    }

    // Process a user request through the agent
    void ProcessUserRequest(const std::string& request) {
        if (!running_) {
            std::cerr << "Application not initialized\n";
            return;
        }

        std::cout << "\n=== Processing Request ===\n";
        std::cout << "Request: " << request << "\n";

        // Create intent from request
        Intent intent;
        intent.action = "process_natural_language";
        intent.params["input"] = request;
        intent.params["timestamp"] = std::to_string(
            std::chrono::system_clock::now().time_since_epoch().count()
        );

        // Execute through security validation
        auto security_context = security_->CreateContext();
        if (!security_->ValidatePreExecution(intent, security_context)) {
            std::cerr << "Security validation failed\n";
            return;
        }

        // Execute intent
        auto result = kernel_->ExecuteIntent(intent);

        // Log execution
        security_->LogPostExecution(intent, result, security_context);

        // Display result
        if (result.success) {
            std::cout << "✓ Success: " << result.message << "\n";
        } else {
            std::cout << "✗ Failed: " << result.message << "\n";
        }
    }

    // Execute a tool directly
    void ExecuteTool(const std::string& tool_name, 
                     const std::map<std::string, std::string>& params) {
        if (!running_) {
            std::cerr << "Application not initialized\n";
            return;
        }

        std::cout << "\n=== Executing Tool ===\n";
        std::cout << "Tool: " << tool_name << "\n";

        auto result = Tools::TOOL_REGISTRY.Execute(tool_name, params);

        if (result.status == Tools::ToolStatus::SUCCESS) {
            std::cout << "✓ Success:\n" << result.output << "\n";
        } else {
            std::cout << "✗ Failed: " << result.error_message << "\n";
        }
    }

    // Run the main loop
    void Run() {
        if (!running_) {
            std::cerr << "Application not initialized\n";
            return;
        }

        std::cout << "\n=== Sovereign Substrate Interactive Demo ===\n";
        std::cout << "Commands:\n";
        std::cout << "  tool <name> [params...] - Execute a tool\n";
        std::cout << "  ask <question>          - Ask the agent\n";
        std::cout << "  status                  - Show system status\n";
        std::cout << "  quit                    - Exit\n\n";

        std::string line;
        while (running_) {
            std::cout << "> ";
            std::getline(std::cin, line);

            if (line.empty()) continue;

            // Parse command
            size_t space_pos = line.find(' ');
            std::string cmd = (space_pos == std::string::npos) 
                ? line 
                : line.substr(0, space_pos);
            std::string args = (space_pos == std::string::npos) 
                ? "" 
                : line.substr(space_pos + 1);

            if (cmd == "quit" || cmd == "exit") {
                break;
            } else if (cmd == "ask") {
                ProcessUserRequest(args);
            } else if (cmd == "tool") {
                // Parse tool execution
                size_t tool_space = args.find(' ');
                std::string tool_name = (tool_space == std::string::npos) 
                    ? args 
                    : args.substr(0, tool_space);
                
                std::map<std::string, std::string> params;
                // Simple param parsing (key=value)
                if (tool_space != std::string::npos) {
                    std::string params_str = args.substr(tool_space + 1);
                    // Parse params...
                }
                
                ExecuteTool(tool_name, params);
            } else if (cmd == "status") {
                PrintStatus();
            } else {
                std::cout << "Unknown command: " << cmd << "\n";
            }
        }
    }

private:
    void RegisterCustomTools() {
        // Register a custom tool
        class CustomAnalysisTool : public Tools::ITool {
        public:
            std::string GetName() const override { return "custom_analysis"; }
            std::string GetDescription() const override { 
                return "Perform custom code analysis"; 
            }
            
            Tools::ToolResult Execute(const std::map<std::string, std::string>& params) override {
                Tools::ToolResult result;
                
                auto it = params.find("target");
                if (it == params.end()) {
                    result.status = Tools::ToolStatus::INVALID_PARAMS;
                    result.error_message = "Missing 'target' parameter";
                    return result;
                }
                
                // Perform analysis...
                result.status = Tools::ToolStatus::SUCCESS;
                result.output = "Analysis complete for: " + it->second;
                return result;
            }
        };

        Tools::TOOL_REGISTRY.Register(std::make_unique<CustomAnalysisTool>());
        std::cout << "Custom tools registered\n";
    }

    void SetupEventHandlers() {
        // Set up event handlers for agent events
        // This would connect to your application's event system
        std::cout << "Event handlers configured\n";
    }

    void PrintStatus() {
        std::cout << "\n=== System Status ===\n";
        std::cout << "Running: " << (running_ ? "Yes" : "No") << "\n";
        std::cout << "Kernel: " << (kernel_ ? "Initialized" : "Not initialized") << "\n";
        std::cout << "Security: " << (security_ ? "Active" : "Inactive") << "\n";
        
        auto& memory = RepositoryGraph::Instance();
        std::cout << "Memory Graph: " << memory.GetNodeCount() << " nodes, " 
                  << memory.GetEdgeCount() << " edges\n";
        std::cout << "\n";
    }
};

int main(int argc, char* argv[]) {
    try {
        MyApplication app;
        
        if (!app.Initialize()) {
            std::cerr << "Failed to initialize application\n";
            return 1;
        }

        // Check for command-line mode
        if (argc > 1) {
            // Execute single command
            std::string cmd = argv[1];
            for (int i = 2; i < argc; ++i) {
                cmd += " ";
                cmd += argv[i];
            }
            app.ProcessUserRequest(cmd);
        } else {
            // Interactive mode
            app.Run();
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
