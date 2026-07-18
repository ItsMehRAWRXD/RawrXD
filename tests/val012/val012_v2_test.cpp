/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-012 V2 Test: Real Build and Test Execution
 * 
 * This test validates that VAL-012 can execute real builds and tests.
 */

#include "val012_controller_v2.h"
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace RawrXD::VAL012;

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "VAL-012 V2: Real Execution Test\n";
    std::cout << "========================================\n\n";
    
    // Determine build directory
    std::string buildDir = "build-val012-simple";
    if (argc > 1) {
        buildDir = argv[1];
    }
    
    std::string testExecutable = buildDir + "/val012_test.exe";
    std::string evidenceDir = "evidence/val-012-v2-" + std::to_string(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    
    std::cout << "Build directory: " << buildDir << "\n";
    std::cout << "Test executable: " << testExecutable << "\n";
    std::cout << "Evidence directory: " << evidenceDir << "\n\n";
    
    // Create V2 controller
    Val012ControllerV2 controller;
    
    // Test 1: Simulated mode (baseline)
    std::cout << "[TEST 1] Simulated execution...\n";
    controller.setRealMode(false);
    auto simResult = controller.executeReal("Add --version command", 
                                               evidenceDir + "-sim",
                                               buildDir, 
                                               testExecutable);
    std::cout << "  Simulated: " << (simResult.success ? "PASS" : "FAIL") << "\n\n";
    
    // Test 2: Real mode (if build directory exists)
    std::cout << "[TEST 2] Real execution...\n";
    if (!std::filesystem::exists(buildDir)) {
        std::cout << "  Build directory not found, skipping real execution\n";
        std::cout << "  Run: g++ -std=c++20 to build first\n\n";
    } else {
        controller.setRealMode(true);
        auto realResult = controller.executeReal("Add --version command",
                                                   evidenceDir + "-real",
                                                   buildDir,
                                                   testExecutable);
        std::cout << "  Real: " << (realResult.success ? "PASS" : "FAIL") << "\n";
        
        // Check for provenance manifest
        std::string manifestPath = evidenceDir + "-real/provenance_manifest.json";
        if (std::filesystem::exists(manifestPath)) {
            std::cout << "  ✓ Provenance manifest created\n";
            std::ifstream ifs(manifestPath);
            if (ifs) {
                std::string content((std::istreambuf_iterator<char>(ifs)),
                                   std::istreambuf_iterator<char>());
                std::cout << "  Manifest preview:\n";
                std::cout << content.substr(0, 500) << "...\n";
            }
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "VAL-012 V2 Test Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
