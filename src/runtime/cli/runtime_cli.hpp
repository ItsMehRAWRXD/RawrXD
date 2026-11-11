#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <memory>
#include "../model_registry/model_registry.hpp"
#include "../session/session_manager.hpp"
#include "../router/model_router.hpp"

namespace rawrxd {
namespace runtime {
namespace cli {

class RuntimeCLI {
public:
    RuntimeCLI(
        std::shared_ptr<ModelRegistry> modelRegistry,
        std::shared_ptr<SessionManager> sessionManager,
        std::shared_ptr<ModelRouter> modelRouter
    );
    ~RuntimeCLI();
    
    // CLI command handlers
    void handleModelsCommand();
    void handleSessionTestCommand();
    void handleHelpCommand();
    
    // Main command processor
    bool processCommand(const std::string& command);
    
private:
    std::shared_ptr<ModelRegistry> modelRegistry_;
    std::shared_ptr<SessionManager> sessionManager_;
    std::shared_ptr<ModelRouter> modelRouter_;
    
    // Helper methods
    void printModelInfo(const ModelManifest& model);
};

} // namespace cli
} // namespace runtime
} // namespace rawrxd