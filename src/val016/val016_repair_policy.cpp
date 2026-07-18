/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#include "val016_repair_policy.h"
#include <iostream>
#include <regex>

namespace RawrXD {
namespace VAL016 {

// BuildDirectoryMissingPolicy implementation
bool BuildDirectoryMissingPolicy::canHandle(const VAL014::ExecutionResult& result) const {
    if (!result.buildResult.has_value()) return false;
    return result.buildResult->failureReason == VAL012::BuildFailureReason::BuildDirectoryMissing;
}

Diagnosis BuildDirectoryMissingPolicy::diagnose(const VAL014::ExecutionResult& result) {
    Diagnosis diag;
    diag.failureCategory = "BuildDirectoryMissing";
    diag.summary = "Build directory does not exist or is not configured";
    diag.diagnostics.push_back("No CMakeCache.txt found");
    diag.diagnostics.push_back("No build.ninja found");
    diag.affectedFiles.push_back(result.buildResult->workingDirectory);
    diag.suggestedActions.push_back("Create build directory");
    diag.suggestedActions.push_back("Run cmake configuration");
    diag.confidence = 95;
    return diag;
}

RepairPlan BuildDirectoryMissingPolicy::generatePlan(const Diagnosis& diagnosis) {
    RepairPlan plan;
    plan.action = PolicyRepairActionType::CreateBuildDirectory;
    plan.description = "Create build directory and configure with CMake";
    plan.filesToModify = diagnosis.affectedFiles;
    plan.suggestedPatch = "mkdir -p build && cd build && cmake ..";
    plan.confidence = diagnosis.confidence;
    return plan;
}

// CompileFailurePolicy implementation
bool CompileFailurePolicy::canHandle(const VAL014::ExecutionResult& result) const {
    if (!result.buildResult.has_value()) return false;
    return result.buildResult->failureReason == VAL012::BuildFailureReason::CompileFailed;
}

Diagnosis CompileFailurePolicy::diagnose(const VAL014::ExecutionResult& result) {
    Diagnosis diag;
    diag.failureCategory = "CompileFailed";
    diag.summary = "Compilation errors detected";
    
    // Extract compiler errors from stderr
    auto errors = extractCompilerErrors(result.buildResult->stderrLog);
    diag.diagnostics = errors;
    
    // Extract affected files
    diag.affectedFiles = extractAffectedFiles(errors);
    
    // Suggest actions based on error patterns
    for (const auto& error : errors) {
        if (error.find("undefined reference") != std::string::npos) {
            diag.suggestedActions.push_back("Add missing library or definition");
        }
        if (error.find("expected") != std::string::npos || 
            error.find("syntax error") != std::string::npos) {
            diag.suggestedActions.push_back("Fix syntax error");
        }
        if (error.find("not declared") != std::string::npos) {
            diag.suggestedActions.push_back("Add missing include or declaration");
        }
    }
    
    diag.confidence = errors.empty() ? 50 : 85;
    return diag;
}

RepairPlan CompileFailurePolicy::generatePlan(const Diagnosis& diagnosis) {
    RepairPlan plan;
    plan.action = PolicyRepairActionType::FixCompileError;
    plan.description = "Fix compilation errors in affected files";
    plan.filesToModify = diagnosis.affectedFiles;
    
    // Generate patch based on diagnostics
    std::ostringstream patch;
    patch << "// Fix compilation errors\n";
    for (const auto& diag : diagnosis.diagnostics) {
        patch << "// " << diag << "\n";
    }
    plan.suggestedPatch = patch.str();
    plan.confidence = diagnosis.confidence;
    
    return plan;
}

std::vector<std::string> CompileFailurePolicy::extractCompilerErrors(const std::string& stderrLog) {
    std::vector<std::string> errors;
    
    // Pattern: filename:line:column: error: message
    std::regex errorRegex(R"(([^\s:]+):(\d+):(\d+):\s*error:\s*(.+))");
    std::smatch match;
    std::string::const_iterator searchStart(stderrLog.cbegin());
    
    while (std::regex_search(searchStart, stderrLog.cend(), match, errorRegex)) {
        errors.push_back(match[0]);
        searchStart = match.suffix().first;
    }
    
    // Pattern: error: message (generic)
    if (errors.empty()) {
        std::regex genericErrorRegex(R"(error:\s*(.+))");
        searchStart = stderrLog.cbegin();
        while (std::regex_search(searchStart, stderrLog.cend(), match, genericErrorRegex)) {
            errors.push_back(match[0]);
            searchStart = match.suffix().first;
        }
    }
    
    return errors;
}

std::vector<std::string> CompileFailurePolicy::extractAffectedFiles(const std::vector<std::string>& errors) {
    std::vector<std::string> files;
    std::regex fileRegex(R"(([^\s:]+):\d+:\d+:)");
    
    for (const auto& error : errors) {
        std::smatch match;
        if (std::regex_search(error, match, fileRegex)) {
            std::string file = match[1];
            // Avoid duplicates
            if (std::find(files.begin(), files.end(), file) == files.end()) {
                files.push_back(file);
            }
        }
    }
    
    return files;
}

// LinkFailurePolicy implementation
bool LinkFailurePolicy::canHandle(const VAL014::ExecutionResult& result) const {
    if (!result.buildResult.has_value()) return false;
    return result.buildResult->failureReason == VAL012::BuildFailureReason::LinkFailed;
}

Diagnosis LinkFailurePolicy::diagnose(const VAL014::ExecutionResult& result) {
    Diagnosis diag;
    diag.failureCategory = "LinkFailed";
    diag.summary = "Linking errors detected";
    
    // Extract linker errors
    std::regex linkErrorRegex(R"((undefined reference|cannot find|LNK\d+):\s*(.+))");
    std::smatch match;
    std::string::const_iterator searchStart(result.buildResult->stderrLog.cbegin());
    
    while (std::regex_search(searchStart, result.buildResult->stderrLog.cend(), match, linkErrorRegex)) {
        diag.diagnostics.push_back(match[0]);
        searchStart = match.suffix().first;
    }
    
    diag.suggestedActions.push_back("Add missing library to link command");
    diag.suggestedActions.push_back("Check library paths");
    diag.confidence = 80;
    
    return diag;
}

RepairPlan LinkFailurePolicy::generatePlan(const Diagnosis& diagnosis) {
    RepairPlan plan;
    plan.action = PolicyRepairActionType::FixLinkError;
    plan.description = "Fix linking errors by adding missing libraries";
    plan.filesToModify = diagnosis.affectedFiles;
    plan.suggestedPatch = "// Add missing libraries to CMakeLists.txt or link command";
    plan.confidence = diagnosis.confidence;
    return plan;
}

// TestFailurePolicy implementation
bool TestFailurePolicy::canHandle(const VAL014::ExecutionResult& result) const {
    if (!result.testResult.has_value()) return false;
    return result.testResult->failureReason == VAL012::TestFailureReason::TestsFailed;
}

Diagnosis TestFailurePolicy::diagnose(const VAL014::ExecutionResult& result) {
    Diagnosis diag;
    diag.failureCategory = "TestsFailed";
    diag.summary = "Some tests failed";
    
    // Collect failed test names
    for (const auto& tc : result.testResult->testCases) {
        if (!tc.passed) {
            diag.diagnostics.push_back("Failed: " + tc.name + " - " + tc.errorMessage);
            diag.affectedFiles.push_back(tc.name); // Test name as proxy for affected code
        }
    }
    
    diag.suggestedActions.push_back("Debug failed tests");
    diag.suggestedActions.push_back("Check test assertions");
    diag.confidence = 90;
    
    return diag;
}

RepairPlan TestFailurePolicy::generatePlan(const Diagnosis& diagnosis) {
    RepairPlan plan;
    plan.action = PolicyRepairActionType::FixTestFailure;
    plan.description = "Fix failing tests";
    plan.filesToModify = diagnosis.affectedFiles;
    plan.suggestedPatch = "// Review and fix test logic";
    plan.confidence = diagnosis.confidence;
    return plan;
}

// RepairPolicyRegistry implementation
RepairPolicyRegistry::RepairPolicyRegistry() {
    // Register default policies
    registerPolicy(std::make_unique<BuildDirectoryMissingPolicy>());
    registerPolicy(std::make_unique<CompileFailurePolicy>());
    registerPolicy(std::make_unique<LinkFailurePolicy>());
    registerPolicy(std::make_unique<TestFailurePolicy>());
}

RepairPolicy* RepairPolicyRegistry::findPolicy(const VAL014::ExecutionResult& result) {
    for (auto& policy : policies_) {
        if (policy->canHandle(result)) {
            return policy.get();
        }
    }
    return nullptr;
}

void RepairPolicyRegistry::registerPolicy(std::unique_ptr<RepairPolicy> policy) {
    policies_.push_back(std::move(policy));
}

} // namespace VAL016
} // namespace RawrXD
