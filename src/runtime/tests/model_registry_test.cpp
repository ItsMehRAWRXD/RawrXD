#include <iostream>
#include <string>
#include <vector>
#include "model_registry/model_manifest.hpp"
#include "model_registry/model_registry.hpp"

int main() {
    std::cout << "Testing ModelRegistry..." << std::endl;

    // Create a model registry
    rawrxd::runtime::ModelRegistry registry;

    // Test 1: Register a model
    rawrxd::runtime::ModelManifest manifest1(
        "test-model-1",
        "/path/to/model1.gguf",
        "llama",
        "Q4_0",
        7000000000, // 7B parameters
        2048,       // context length
        5000000000, // 5GB file size
        6,          // 6GB VRAM required
        true,       // supports GPU
        true,       // supports Vulkan
        false       // does not support HIP
    );

    bool regResult = registry.registerModel(manifest1);
    std::cout << "Test 1 - Register model: " << (regResult ? "PASS" : "FAIL") << std::endl;

    // Test 2: Register duplicate model (should fail)
    rawrxd::runtime::ModelManifest manifest2(
        "test-model-1", // same name
        "/path/to/model2.gguf",
        "llama",
        "Q5_0",
        7000000000,
        2048,
        6000000000,
        8,
        true,
        true,
        false
    );

    bool regResult2 = registry.registerModel(manifest2);
    std::cout << "Test 2 - Register duplicate model (should fail): " << (!regResult2 ? "PASS" : "FAIL") << std::endl;

    // Test 3: Find a model
    rawrxd::runtime::ModelManifest* found = registry.find("test-model-1");
    bool findResult = (found != nullptr && found->name == "test-model-1");
    std::cout << "Test 3 - Find model: " << (findResult ? "PASS" : "FAIL") << std::endl;

    // Test 4: Find non-existent model
    rawrxd::runtime::ModelManifest* notFound = registry.find("non-existent");
    bool notFoundResult = (notFound == nullptr);
    std::cout << "Test 4 - Find non-existent model: " << (notFoundResult ? "PASS" : "FAIL") << std::endl;

    // Test 5: List models
    std::vector<rawrxd::runtime::ModelManifest> models = registry.list();
    bool listResult = (models.size() == 1 && models[0].name == "test-model-1");
    std::cout << "Test 5 - List models: " << (listResult ? "PASS" : "FAIL") << std::endl;

    // Test 6: Remove a model
    bool removeResult = registry.remove("test-model-1");
    std::cout << "Test 6 - Remove model: " << (removeResult ? "PASS" : "FAIL") << std::endl;

    // Test 7: Try to find removed model
    rawrxd::runtime::ModelManifest* foundAfterRemove = registry.find("test-model-1");
    bool findAfterRemoveResult = (foundAfterRemove == nullptr);
    std::cout << "Test 7 - Find after removal: " << (findAfterRemoveResult ? "PASS" : "FAIL") << std::endl;

    // Test 8: Remove non-existent model (should fail)
    bool removeNonExist = !registry.remove("non-existent");
    std::cout << "Test 8 - Remove non-existent model (should fail): " << (removeResult ? "PASS" : "FAIL") << std::endl;

    std::cout << "ModelRegistry tests completed." << std::endl;
    return 0;
}
