#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <filesystem>
#include "model_registry/model_registry.hpp"
#include "session/session_manager.hpp"
#include "router/model_router.hpp"
#include "cli/runtime_cli.hpp"

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Runtime Initializing..." << std::endl;
    
    // Create core components
    auto modelRegistry = std::make_shared<rawrxd::runtime::ModelRegistry>();
    auto sessionManager = std::make_shared<rawrxd::runtime::SessionManager>();
    auto modelRouter = std::make_shared<rawrxd::runtime::ModelRouter>(modelRegistry);
    
    // Set up the model router with the registry
    modelRouter->setRegistry(modelRegistry);
    
    // Create CLI handler
    rawrxd::runtime::cli::RuntimeCLI cli(modelRegistry, sessionManager, modelRouter);
    
    // Scan for models in the models directory
    std::string modelsPath = "./models";
    if (std::filesystem::exists(modelsPath)) {
        std::cout << "Scanning for models in: " << modelsPath << std::endl;
        if (!modelRegistry->scanDirectory(modelsPath)) {
            std::cerr << "Warning: Failed to scan model directory" << std::endl;
        }
        std::cout << "Model scan completed." << std::endl;
    } else {
        std::cout << "Models directory not found at: " << modelsPath << std::endl;
        std::cout << "Creating models directory..." << std::endl;
        std::filesystem::create_directories(modelsPath);
    }
    
    // Process command line arguments
    if (argc > 1) {
        // Process each argument as a command
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (!cli.processCommand(arg)) {
                std::cerr << "Unknown command: " << arg << std::endl;
                cli.handleHelpCommand();
                return 1;
            }
        }
    } else {
        // No arguments, show help
        cli.handleHelpCommand();
    }
    
    std::cout << "RawrXD Runtime Shutting Down..." << std::endl;
    return 0;
}
