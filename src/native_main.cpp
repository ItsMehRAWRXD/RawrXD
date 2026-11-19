// RawrXD Native Entry Point
// Pure native Win32 application - no Qt dependencies
// Compiles with MSVC, C++20, /MD runtime

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Include native compatibility layer
#include "../include/qt_block.h"
#include "../src/centralized_exception_handler.h"
#include "../src/production_config_manager.h"

// Forward declarations for native components
namespace RawrXD {
class TaskOrchestrator;
class HFHubClient;
}

// ============================================================================
// Native Application Entry Point
// ============================================================================

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                      LPWSTR lpCmdLine, int nCmdShow)
{
    try {
        // Install global exception handler FIRST
        RawrXD::CentralizedExceptionHandler::instance().installHandler();
        RawrXD::CentralizedExceptionHandler::instance().enableAutomaticRecovery(true);
        
        std::cout << "[RawrXD] Starting native application..." << std::endl;
        
        // Create logs directory
        CreateDirectoryA("logs", nullptr);
        
        // Load production configuration
        auto& configManager = RawrXD::ProductionConfigManager::instance();
        if (!configManager.loadConfig()) {
            std::cerr << "[RawrXD] Warning: Failed to load production config, using defaults" << std::endl;
        }
        
        std::cout << "[RawrXD] Configuration environment: " << configManager.getEnvironment() << std::endl;
        
        // Initialize task orchestrator
        RawrXD::TaskOrchestrator orchestrator;
        
        // Initialize HFHubClient
        RawrXD::HFHubClient hfClient;
        
        std::cout << "[RawrXD] Native application initialized successfully" << std::endl;
        std::cout << "[RawrXD] Press any key to exit..." << std::endl;
        
        // Keep console open
        std::cin.get();
        
        // Uninstall exception handler
        RawrXD::CentralizedExceptionHandler::instance().uninstallHandler();
        
        return 0;
    }
    catch (const std::exception& e) {
        RawrXD::CentralizedExceptionHandler::instance().reportException(e);
        std::cerr << "[RawrXD] Fatal error: " << e.what() << std::endl;
        return -1;
    }
    catch (...) {
        RawrXD::CentralizedExceptionHandler::instance().reportError(
            "Unknown exception in wWinMain()",
            "unknown",
            json()
        );
        std::cerr << "[RawrXD] Fatal error: unknown exception" << std::endl;
        return -1;
    }
}