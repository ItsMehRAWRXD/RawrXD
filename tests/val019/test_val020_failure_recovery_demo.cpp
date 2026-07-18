/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * VAL-020 Failure Recovery Demonstration
 * 
 * Demonstrates the complete autonomous engineering loop:
 *   1. Inject known compiler error
 *   2. VAL-019 executes real build
 *   3. Capture compiler failure
 *   4. Convert to VAL-016 format
 *   5. Diagnose failure
 *   6. Apply repair
 *   7. Rebuild
 *   8. Verify correction
 *   9. Preserve evidence chain
 * 
 * This is the "self-healing codebase" demonstration that validates
 * the entire autonomous engineering loop.
 */

#include "isolated_execution_environment.h"
#include <iostream>
#include <filesystem>

using namespace RawrXD::VAL019;

int main() {
    std::cout << "========================================\n";
    std::cout << "VAL-020 Autonomous Failure Recovery Demo\n";
    std::cout << "========================================\n";
    std::cout << "\nThis demonstration validates the complete\n";
    std::cout << "autonomous engineering loop:\n\n";
    std::cout << "  FAILED → DIAGNOSED → REPAIRED → REBUILT → PASSED\n\n";
    
    // Create demonstrator
    FailureRecoveryDemonstrator demonstrator;
    
    // Run compile error recovery demonstration
    std::cout << "Running compile error recovery...\n\n";
    auto result = demonstrator.demonstrateCompileErrorRecovery();
    
    // Generate and display report
    std::string report = demonstrator.generateReport(result);
    std::cout << report << std::endl;
    
    // Validate the evidence chain
    std::cout << "\n========================================\n";
    std::cout << "Evidence Chain Validation\n";
    std::cout << "========================================\n";
    
    bool evidenceValid = std::filesystem::exists(result.evidenceDir);
    std::cout << "Evidence directory exists: " << (evidenceValid ? "YES" : "NO") << "\n";
    
    if (evidenceValid) {
        int fileCount = 0;
        for (const auto& entry : std::filesystem::directory_iterator(result.evidenceDir)) {
            std::cout << "  " << entry.path().filename().string() << "\n";
            fileCount++;
        }
        std::cout << "\nTotal evidence files: " << fileCount << "\n";
    }
    
    // Validate lifecycle states
    std::cout << "\n========================================\n";
    std::cout << "Lifecycle State Validation\n";
    std::cout << "========================================\n";
    
    std::vector<std::string> expectedStates = {
        "INITIALIZED",
        "WORKSPACE_CREATED",
        "PROJECT_CREATED",
        "FAULT_INJECTED",
        "BUILD_FAILED",
        "DIAGNOSED",
        "REPAIRED",
        "REBUILT",
        "PASSED"
    };
    
    bool lifecycleValid = true;
    std::cout << "Expected lifecycle:\n";
    for (size_t i = 0; i < expectedStates.size(); ++i) {
        bool found = (i < result.lifecycleStates.size() && 
                     result.lifecycleStates[i] == expectedStates[i]);
        std::cout << "  " << (i + 1) << ". " << expectedStates[i] 
                  << " " << (found ? "✓" : "✗") << "\n";
        if (!found) lifecycleValid = false;
    }
    
    // Final validation
    std::cout << "\n========================================\n";
    std::cout << "Final Validation\n";
    std::cout << "========================================\n";
    
    bool success = result.success;
    bool hasEvidence = evidenceValid;
    bool completeLifecycle = lifecycleValid;
    
    std::cout << "Recovery successful: " << (success ? "YES ✓" : "NO ✗") << "\n";
    std::cout << "Evidence generated: " << (hasEvidence ? "YES ✓" : "NO ✗") << "\n";
    std::cout << "Lifecycle complete: " << (completeLifecycle ? "YES ✓" : "NO ✗") << "\n";
    std::cout << "Total duration: " << result.totalDuration.count() << "ms\n";
    
    if (success && hasEvidence && completeLifecycle) {
        std::cout << "\n✓ VAL-020 DEMONSTRATION PASSED\n";
        std::cout << "\nThe autonomous engineering loop is operational.\n";
        std::cout << "The system can:\n";
        std::cout << "  - Detect real build failures\n";
        std::cout << "  - Diagnose failure types\n";
        std::cout << "  - Apply repairs\n";
        std::cout << "  - Verify corrections\n";
        std::cout << "  - Generate complete evidence chains\n";
        return 0;
    } else {
        std::cout << "\n✗ VAL-020 DEMONSTRATION INCOMPLETE\n";
        return 1;
    }
}
