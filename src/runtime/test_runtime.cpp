#include <iostream>
#include <memory>
#include <string>
#include "model_registry/model_manifest.hpp"
#include "model_registry/model_registry.hpp"
#include "session/session_manager.hpp"
#include "router/task_classifier.hpp"
#include "router/model_router.hpp"

int main() {
    std::cout << "Testing RawrXD Runtime Components..." << std::endl;
    
    // Test Model Registry
    std::cout << "\n1. Testing Model Registry:" << std::endl;
    auto registry = std::make_shared<rawrxd::runtime::ModelRegistry>();
    
    // Create a test model manifest
    rawrxd::runtime::ModelManifest testModel(
        "test-model",
        "/fake/path/to/model.gguf",
        "llama",
        "Q4_0",
        7000000000,  // 7B parameters
        4096,        // context length
        5000000000,  // 5GB file size
        6,           // 6GB VRAM required
        true,        // supports GPU
        true,        // supports Vulkan
        false        // does not support HIP
    );
    
    // Register the model
    bool registered = registry->registerModel(testModel);
    std::cout << "   Model registration: " << (registered ? "PASS" : "FAIL") << std::endl;
    
    // Find the model
    auto foundModel = registry->find("test-model");
    if (foundModel) {
        std::cout << "   Model lookup: PASS" << std::endl;
        std::cout << "   Model name: " << foundModel->name << std::endl;
        std::cout << "   Model context: " << foundModel->context_length << std::endl;
    } else {
        std::cout << "   Model lookup: FAIL" << std::endl;
    }
    
    // List models
    auto models = registry->list();
    std::cout << "   Model listing: " << models.size() << " model(s) found" << std::endl;
    
    // Test Session Manager
    std::cout << "\n2. Testing Session Manager:" << std::endl;
    auto sessionManager = std::make_shared<rawrxd::runtime::SessionManager>();
    
    // Create a session
    auto session = sessionManager->create("test-model");
    if (session && session->id > 0) {
        std::cout << "   Session creation: PASS (ID: " << session->id << ")" << std::endl;
    } else {
        std::cout << "   Session creation: FAIL" << std::endl;
    }
    
    // Retrieve the session
    auto retrievedSession = sessionManager->get(session->id);
    if (retrievedSession && retrievedSession->id == session->id) {
        std::cout << "   Session retrieval: PASS" << std::endl;
    } else {
        std::cout << "   Session retrieval: FAIL" << std::endl;
    }
    
    // Destroy the session
    bool destroyed = sessionManager->destroy(session->id);
    if (destroyed) {
        std::cout << "   Session destruction: PASS" << std::endl;
    } else {
        std::cout << "   Session destruction: FAIL" << std::endl;
    }
    
    // Try to retrieve destroyed session
    auto destroyedSession = sessionManager->get(session->id);
    if (!destroyedSession) {
        std::cout << "   Session cleanup verification: PASS" << std::endl;
    } else {
        std::cout << "   Session cleanup verification: FAIL" << std::endl;
    }
    
    // Test Task Classifier and Model Router
    std::cout << "\n3. Testing Task Classifier and Model Router:" << std::endl;
    auto taskClassifier = std::make_shared<rawrxd::runtime::TaskClassifier>();
    auto modelRouter = std::make_shared<rawrxd::runtime::ModelRouter>();
    modelRouter->setRegistry(registry);
    
    // Create test tasks
    rawrxd::runtime::TaskRequest codeTask("Write a function to sort an array", 1024, false, true);
    rawrxd::runtime::TaskRequest reasoningTask("Explain the theory of relativity", 2048, true, false);
    rawrxd::runtime::TaskRequest generalTask("What is the weather today?", 512, false, false);
    
    // Test code task classification
    auto codeDecision = modelRouter->routeTask(codeTask);
    std::cout << "   Code task routing: " << codeDecision.model.name << " (" << codeDecision.backend << ")" << std::endl;
    
    // Test reasoning task classification
    auto reasoningDecision = modelRouter->routeTask(reasoningTask);
    std::cout << "   Reasoning task routing: " << reasoningDecision.model.name << " (" << reasoningDecision.backend << ")" << std::endl;
    
    // Test general task classification
    auto generalDecision = modelRouter->routeTask(generalTask);
    std::cout << "   General task routing: " << generalDecision.model.name << " (" << generalDecision.backend << ")" << std::endl;
    
    std::cout << "\nAll tests completed!" << std::endl;
    return 0;
}
