/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-012 Controller v2: Real Build and Test Execution
 * 
 * Enhanced controller that invokes real CMake/Ninja builds
 * and executes actual test binaries with full provenance tracking.
 */

#include "val012_controller.h"
#include "val012_build_executor.h"
#include "val012_test_executor.h"

namespace RawrXD {
namespace VAL012 {

/**
 * @struct Val012EnhancedCompletion
 * Extended completion with real execution provenance
 */
struct Val012EnhancedCompletion : public Val012Completion {
    RealBuildResult buildResult;
    RealTestResult testResult;
    
    val012::json toJson() const {
        val012::json j = Val012Completion::toJson();
        j["build_details"] = buildResult.toJson();
        j["test_details"] = testResult.toJson();
        j["validation_id"] = "VAL-012";
        j["evidence_version"] = 2;
        return j;
    }
};

/**
 * @class Val012ControllerV2
 * Enhanced controller with real build/test execution
 */
class Val012ControllerV2 : public Val012Controller {
public:
    Val012ControllerV2();
    
    /**
     * Execute with real build and test
     * 
     * @param goalDescription Natural language goal
     * @param evidenceDir Where to store evidence
     * @param buildDir Directory containing build.ninja
     * @param testExecutable Path to test binary
     * @return Enhanced completion with provenance
     */
    Val012EnhancedCompletion executeReal(
        const std::string& goalDescription,
        const std::string& evidenceDir = "evidence/val-012",
        const std::string& buildDir = "build",
        const std::string& testExecutable = "");
    
    /**
     * Set execution mode
     */
    void setRealMode(bool real) { realMode_ = real; }
    bool isRealMode() const { return realMode_; }

private:
    bool realMode_ = true;
    
    // Real execution handlers
    bool handleRealBuilding(const std::string& buildDir);
    bool handleRealTesting(const std::string& testExecutable);
    
    // Enhanced evidence collection
    void saveEnhancedEvidence(const std::string& dir, 
                              const Val012EnhancedCompletion& completion);
};

} // namespace VAL012
} // namespace RawrXD
