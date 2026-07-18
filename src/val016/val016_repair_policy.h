/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#pragma once

/**
 * VAL-016 Repair Policy Layer
 * 
 * Separates repair decisions from orchestrator.
 * Each policy handles a specific failure category.
 */

#include "val014_execution_result.h"
#include <vector>
#include <string>
#include <memory>

namespace RawrXD {
namespace VAL016 {

/**
 * @enum PolicyRepairActionType
 * Types of repair actions that can be taken by policies
 */
enum class PolicyRepairActionType {
    None,
    CreateBuildDirectory,
    ConfigureCMake,
    FixCompileError,
    FixLinkError,
    FixTestFailure,
    RetryBuild,
    RetryTest
};

inline std::string policyRepairActionTypeToString(PolicyRepairActionType t) {
    switch(t) {
        case PolicyRepairActionType::None: return "None";
        case PolicyRepairActionType::CreateBuildDirectory: return "CreateBuildDirectory";
        case PolicyRepairActionType::ConfigureCMake: return "ConfigureCMake";
        case PolicyRepairActionType::FixCompileError: return "FixCompileError";
        case PolicyRepairActionType::FixLinkError: return "FixLinkError";
        case PolicyRepairActionType::FixTestFailure: return "FixTestFailure";
        case PolicyRepairActionType::RetryBuild: return "RetryBuild";
        case PolicyRepairActionType::RetryTest: return "RetryTest";
    }
    return "Unknown";
}

/**
 * @struct RepairPlan
 * Generated plan for fixing a failure
 */
struct RepairPlan {
    PolicyRepairActionType action;
    std::string description;
    std::vector<std::string> filesToModify;
    std::string suggestedPatch;
    int confidence = 0;  // 0-100
    
    val012::json toJson() const {
        val012::json j;
        j["action"] = policyRepairActionTypeToString(action);
        j["description"] = description;
        
        val012::json files = val012::json::array();
        for (const auto& f : filesToModify) {
            files.push_back(f);
        }
        j["files_to_modify"] = files;
        
        j["suggested_patch"] = suggestedPatch;
        j["confidence"] = confidence;
        
        return j;
    }
};

/**
 * @enum RepairState
 * Lifecycle states for reproducible repair tracking
 */
enum class RepairState {
    Detected,       // Failure identified
    Diagnosed,      // Root cause analyzed
    Planned,        // Repair plan generated
    Applying,       // Patch being applied
    Applied,        // Patch applied successfully
    Retrying,       // Build/test retry in progress
    Verified,       // Repair confirmed
    Failed          // Repair failed
};

inline std::string repairStateToString(RepairState s) {
    switch(s) {
        case RepairState::Detected: return "Detected";
        case RepairState::Diagnosed: return "Diagnosed";
        case RepairState::Planned: return "Planned";
        case RepairState::Applying: return "Applying";
        case RepairState::Applied: return "Applied";
        case RepairState::Retrying: return "Retrying";
        case RepairState::Verified: return "Verified";
        case RepairState::Failed: return "Failed";
    }
    return "Unknown";
}

/**
 * @struct RepairLifecycle
 * Tracks state transitions for evidence
 */
struct RepairLifecycle {
    std::vector<std::pair<RepairState, std::chrono::system_clock::time_point>> stateHistory;
    
    void transition(RepairState newState) {
        stateHistory.push_back({newState, std::chrono::system_clock::now()});
    }
    
    val012::json toJson() const {
        val012::json j = val012::json::array();
        for (const auto& [state, timestamp] : stateHistory) {
            val012::json entry;
            entry["state"] = repairStateToString(state);
            entry["timestamp"] = static_cast<long long>(
                std::chrono::system_clock::to_time_t(timestamp));
            j.push_back(entry);
        }
        return j;
    }
};

/**
 * @struct Diagnosis
 * Analyzed failure with extracted information
 */
struct Diagnosis {
    std::string failureCategory;
    std::string summary;
    std::vector<std::string> diagnostics;
    std::vector<std::string> affectedFiles;
    std::vector<std::string> suggestedActions;
    int confidence = 0;  // 0-100
    
    val012::json toJson() const {
        val012::json j;
        j["failure_category"] = failureCategory;
        j["summary"] = summary;
        
        val012::json diagArray = val012::json::array();
        for (const auto& d : diagnostics) {
            diagArray.push_back(d);
        }
        j["diagnostics"] = diagArray;
        
        val012::json filesArray = val012::json::array();
        for (const auto& f : affectedFiles) {
            filesArray.push_back(f);
        }
        j["affected_files"] = filesArray;
        
        val012::json actionsArray = val012::json::array();
        for (const auto& a : suggestedActions) {
            actionsArray.push_back(a);
        }
        j["suggested_actions"] = actionsArray;
        
        j["confidence"] = confidence;
        
        return j;
    }
};

/**
 * @class RepairPolicy
 * Abstract base for failure-specific repair policies
 */
class RepairPolicy {
public:
    virtual ~RepairPolicy() = default;
    
    /**
     * Check if this policy can handle the failure
     */
    virtual bool canHandle(const VAL014::ExecutionResult& result) const = 0;
    
    /**
     * Diagnose the failure
     */
    virtual Diagnosis diagnose(const VAL014::ExecutionResult& result) = 0;
    
    /**
     * Generate repair plan
     */
    virtual RepairPlan generatePlan(const Diagnosis& diagnosis) = 0;
    
    /**
     * Get policy name
     */
    virtual std::string getName() const = 0;
};

/**
 * @class BuildDirectoryMissingPolicy
 * Handles BuildDirectoryMissing failures
 */
class BuildDirectoryMissingPolicy : public RepairPolicy {
public:
    bool canHandle(const VAL014::ExecutionResult& result) const override;
    Diagnosis diagnose(const VAL014::ExecutionResult& result) override;
    RepairPlan generatePlan(const Diagnosis& diagnosis) override;
    std::string getName() const override { return "BuildDirectoryMissingPolicy"; }
};

/**
 * @class CompileFailurePolicy
 * Handles CompileFailed failures
 */
class CompileFailurePolicy : public RepairPolicy {
public:
    bool canHandle(const VAL014::ExecutionResult& result) const override;
    Diagnosis diagnose(const VAL014::ExecutionResult& result) override;
    RepairPlan generatePlan(const Diagnosis& diagnosis) override;
    std::string getName() const override { return "CompileFailurePolicy"; }
    
private:
    std::vector<std::string> extractCompilerErrors(const std::string& stderrLog);
    std::vector<std::string> extractAffectedFiles(const std::vector<std::string>& errors);
};

/**
 * @class LinkFailurePolicy
 * Handles LinkFailed failures
 */
class LinkFailurePolicy : public RepairPolicy {
public:
    bool canHandle(const VAL014::ExecutionResult& result) const override;
    Diagnosis diagnose(const VAL014::ExecutionResult& result) override;
    RepairPlan generatePlan(const Diagnosis& diagnosis) override;
    std::string getName() const override { return "LinkFailurePolicy"; }
};

/**
 * @class TestFailurePolicy
 * Handles TestsFailed failures
 */
class TestFailurePolicy : public RepairPolicy {
public:
    bool canHandle(const VAL014::ExecutionResult& result) const override;
    Diagnosis diagnose(const VAL014::ExecutionResult& result) override;
    RepairPlan generatePlan(const Diagnosis& diagnosis) override;
    std::string getName() const override { return "TestFailurePolicy"; }
};

/**
 * @class RepairPolicyRegistry
 * Registry of available repair policies
 */
class RepairPolicyRegistry {
public:
    RepairPolicyRegistry();
    
    /**
     * Find policy for a failure
     */
    RepairPolicy* findPolicy(const VAL014::ExecutionResult& result);
    
    /**
     * Register a policy
     */
    void registerPolicy(std::unique_ptr<RepairPolicy> policy);

private:
    std::vector<std::unique_ptr<RepairPolicy>> policies_;
};

} // namespace VAL016
} // namespace RawrXD
