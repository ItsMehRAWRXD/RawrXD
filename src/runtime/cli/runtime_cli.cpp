#include "runtime_cli.hpp"
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace rawrxd {
namespace runtime {
namespace cli {

RuntimeCLI::RuntimeCLI(
    std::shared_ptr<ModelRegistry> modelRegistry,
    std::shared_ptr<SessionManager> sessionManager,
    std::shared_ptr<ModelRouter> modelRouter
) : modelRegistry_(modelRegistry),
    sessionManager_(sessionManager),
    modelRouter_(modelRouter) {}

RuntimeCLI::~RuntimeCLI() {}

void RuntimeCLI::handleModelsCommand() {
    if (!modelRegistry_) {
        std::cout << "Error: Model registry not initialized." << std::endl;
        return;
    }

    std::vector<ModelManifest> models = modelRegistry_->list();
    
    if (models.empty()) {
        std::cout << "No models found in the registry." << std::endl;
        return;
    }

    std::cout << "Installed Models" << std::endl;
    std::cout << "========================" << std::endl;
    
    for (const auto& model : models) {
        std::cout << model.name << std::endl;
        std::cout << "  Context: " << model.context_length << std::endl;
        std::cout << "  VRAM: " << model.required_vram << "GB" << std::endl;
        std::cout << "  Backend: ";
        if (model.supports_vulkan) {
            std::cout << "Vulkan";
        } else if (model.supports_hip) {
            std::cout << "HIP";
        } else {
            std::cout << "CPU";
        }
        std::cout << std::endl << std::endl;
    }
}

void RuntimeCLI::handleSessionTestCommand() {
    if (!modelRegistry_ || !sessionManager_) {
        std::cout << "Error: Required components not initialized." << std::endl;
        return;
    }

    std::cout << "Running session test..." << std::endl;

    // Test 1: Model Registry
    std::cout << "Model Registry: ";
    std::vector<ModelManifest> models = modelRegistry_->list();
    if (!models.empty()) {
        std::cout << "PASS (" << models.size() << " models found)" << std::endl;
    } else {
        std::cout << "FAIL (no models found)" << std::endl;
        return;
    }

    // Test 2: Session Creation
    std::cout << "Session Creation: ";
    auto session = sessionManager_->create(models[0].name);
    if (session && session->active) {
        std::cout << "PASS (Session ID: " << session->id << ")" << std::endl;
    } else {
        std::cout << "FAIL" << std::endl;
        return;
    }

    // Test 3: Session Retrieval
    std::cout << "Session Retrieval: ";
    auto retrievedSession = sessionManager_->get(session->id);
    if (retrievedSession && retrievedSession->id == session->id) {
        std::cout << "PASS" << std::endl;
    } else {
        std::cout << "FAIL" << std::endl;
        return;
    }

    // Test 4: Session Destruction
    std::cout << "Session Destruction: ";
    if (sessionManager_->destroy(session->id)) {
        std::cout << "PASS" << std::endl;
    } else {
        std::cout << "FAIL" << std::endl;
        return;
    }

    // Test 5: Session After Destruction
    std::cout << "Session After Destruction: ";
    if (!sessionManager_->get(session->id)) {
        std::cout << "PASS" << std::endl;
    } else {
        std::cout << "FAIL" << std::endl;
        return;
    }

    std::cout << "All session tests passed!" << std::endl;
}

void RuntimeCLI::handleHelpCommand() {
    std::cout << "RawrXD Runtime CLI Commands:" << std::endl;
    std::cout << "  --models          List installed models with their specifications" << std::endl;
    std::cout << "  --session-test    Run a session creation/test/destruction cycle" << std::endl;
    std::cout << "  --help            Show this help message" << std::endl;
}

bool RuntimeCLI::processCommand(const std::string& command) {
    if (command == "--models") {
        handleModelsCommand();
        return true;
    } else if (command == "--session-test") {
        handleSessionTestCommand();
        return true;
    } else if (command == "--help") {
        handleHelpCommand();
        return true;
    } else {
        std::cout << "Unknown command: " << command << std::endl;
        std::cout << "Use --help for available commands." << std::endl;
        return false;
    }
}

void RuntimeCLI::printModelInfo(const ModelManifest& model) {
    // This method is not used in the current implementation but kept for completeness
    std::cout << "Model: " << model.name << std::endl;
    std::cout << "  Path: " << model.path << std::endl;
    std::cout << "  Architecture: " << model.architecture << std::endl;
    std::cout << "  Quantization: " << model.quantization << std::endl;
    std::cout << "  Parameters: " << model.parameter_count << std::endl;
    std::cout << "  Context Length: " << model.context_length << std::endl;
    std::cout << "  File Size: " << model.file_size << " bytes" << std::endl;
    std::cout << "  Required VRAM: " << model.required_vram << " GB" << std::endl;
    std::cout << "  Supports GPU: " << (model.supports_gpu ? "Yes" : "No") << std::endl;
    std::cout << "  Supports Vulkan: " << (model.supports_vulkan ? "Yes" : "No") << std::endl;
    std::cout << "  Supports HIP: " << (model.supports_hip ? "Yes" : "No") << std::endl;
}

} // namespace cli
} // namespace runtime
} // namespace rawrxd
