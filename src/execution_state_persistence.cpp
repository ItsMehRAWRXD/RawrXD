/**
 * ExecutionStatePersistence - Production Implementation
 * Days 1-2: Workflow state persistence and cross-session resumption
 */

#include "execution_state_persistence.h"
#include "agentic_loop_state.h"
#include "agentic_memory_system.h"
#include "agentic_executor.h"

#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <exception>
#include <iostream>

namespace {
std::string makeIsoUtcNow()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&time_t));
    return std::string(buf);
}

std::filesystem::path backupPathFor(const std::filesystem::path& target)
{
    return std::filesystem::path(target.string() + ".bak");
}

std::filesystem::path corruptPathFor(const std::filesystem::path& target)
{
    return std::filesystem::path(target.string() + ".corrupt");
}

bool hasRequiredCheckpointFields(const nlohmann::json& cp)
{
    return cp.is_object() && cp.contains("checkpointId") && cp.contains("label") &&
           cp.contains("sequenceNumber") && cp.contains("timestamp") && cp.contains("stateSnapshot");
}
}

// ===== ExecutionCheckpoint =====

nlohmann::json ExecutionCheckpoint::toJson() const
{
    nlohmann::json j;
    j["checkpointId"] = checkpointId;
    j["label"] = label;
    j["sequenceNumber"] = sequenceNumber;
    j["timestamp"] = timestamp;
    j["stateSnapshot"] = stateSnapshot;
    j["isRecoveryPoint"] = isRecoveryPoint;
    j["recoveryReason"] = recoveryReason;
    return j;
}

void ExecutionCheckpoint::fromJson(const nlohmann::json& j)
{
    checkpointId = j["checkpointId"].get<std::string>();
    label = j["label"].get<std::string>();
    sequenceNumber = j["sequenceNumber"].get<int>();
    timestamp = j["timestamp"].get<std::string>();
    stateSnapshot = j["stateSnapshot"];
    isRecoveryPoint = j.value("isRecoveryPoint", false);
    recoveryReason = j.value("recoveryReason", "");
}

// ===== WorkflowExecution =====

nlohmann::json WorkflowExecution::toJson() const
{
    nlohmann::json j;
    j["executionId"] = executionId;
    j["workflowName"] = workflowName;
    j["goal"] = goal;
    j["status"] = status;
    j["startTime"] = startTime;
    j["lastUpdateTime"] = lastUpdateTime;
    j["completionTime"] = completionTime;
    j["currentCheckpointIndex"] = currentCheckpointIndex;
    
    nlohmann::json checkpointArray = nlohmann::json::array();
    for (const auto& cp : checkpoints) {
        checkpointArray.push_back(cp.toJson());
    }
    j["checkpoints"] = checkpointArray;
    
    j["globalContext"] = globalContext;
    j["metadata"] = metadata;
    j["errorLog"] = errorLog;
    
    return j;
}

void WorkflowExecution::fromJson(const nlohmann::json& j)
{
    executionId = j["executionId"].get<std::string>();
    workflowName = j["workflowName"].get<std::string>();
    goal = j["goal"].get<std::string>();
    status = j["status"].get<std::string>();
    startTime = j["startTime"].get<std::string>();
    lastUpdateTime = j["lastUpdateTime"].get<std::string>();
    completionTime = j.value("completionTime", "");
    currentCheckpointIndex = j.value("currentCheckpointIndex", 0);
    
    checkpoints.clear();
    if (j.contains("checkpoints")) {
        for (const auto& cpJson : j["checkpoints"]) {
            ExecutionCheckpoint cp;
            cp.fromJson(cpJson);
            checkpoints.push_back(cp);
        }
    }
    
    globalContext = j.value("globalContext", nlohmann::json::object());
    metadata = j.value("metadata", nlohmann::json::object());
    
    errorLog.clear();
    if (j.contains("errorLog")) {
        errorLog = j["errorLog"].get<std::vector<std::string>>();
    }
}

// ===== ExecutionStatePersistence =====

ExecutionStatePersistence::ExecutionStatePersistence(
    const std::filesystem::path& persistenceRoot)
    : m_persistenceRoot(persistenceRoot)
{
    ensurePersistenceRoot();
    std::cout << "[ExecutionStatePersistence] Initialized at: "
              << m_persistenceRoot.string() << std::endl;
}

ExecutionStatePersistence::~ExecutionStatePersistence()
{
    // Cleanup handled by automatic file lifecycle
}

bool ExecutionStatePersistence::ensurePersistenceRoot()
{
    try {
        if (!std::filesystem::exists(m_persistenceRoot)) {
            std::filesystem::create_directories(m_persistenceRoot);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Failed to create root: " << e.what() << std::endl;
        return false;
    }
}

std::string ExecutionStatePersistence::generateExecutionId()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << "exec_" << std::put_time(std::gmtime(&time_t), "%Y%m%d_%H%M%S");
    
    // Add microsecond component for uniqueness
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count() % 1000000;
    ss << "_" << std::setfill('0') << std::setw(6) << micros;
    
    return ss.str();
}

std::string ExecutionStatePersistence::getExecutionPath(const std::string& executionId) const
{
    return (m_persistenceRoot / (executionId + ".json")).string();
}

std::string ExecutionStatePersistence::persistWorkflowExecution(
    const WorkflowExecution& execution)
{
    try {
        WorkflowExecution toWrite = execution;
        if (toWrite.executionId.empty()) {
            toWrite.executionId = generateExecutionId();
        }
        if (toWrite.startTime.empty()) {
            toWrite.startTime = makeIsoUtcNow();
        }
        toWrite.lastUpdateTime = makeIsoUtcNow();

        auto execPath = getExecutionPath(toWrite.executionId);
        auto json = execution.toJson();
        json["schemaVersion"] = 1;
        json["lastPersistedAt"] = toWrite.lastUpdateTime;
        json["executionId"] = toWrite.executionId;
        json["startTime"] = toWrite.startTime;
        json["lastUpdateTime"] = toWrite.lastUpdateTime;
        
        if (!atomicWrite(execPath, json.dump(2))) {
            std::cerr << "[ExecutionStatePersistence] Atomic write failed for " 
                      << execution.executionId << std::endl;
            return "";
        }
        
        std::cout << "[ExecutionStatePersistence] Persisted execution: "
                  << toWrite.executionId << " (" << toWrite.goal << ")" << std::endl;
        return toWrite.executionId;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Persist error: " << e.what() << std::endl;
        return "";
    }
}

std::unique_ptr<WorkflowExecution> ExecutionStatePersistence::loadWorkflowExecution(
    const std::string& executionId) const
{
    try {
        auto execPath = std::filesystem::path(getExecutionPath(executionId));
        
        if (!std::filesystem::exists(execPath)) {
            std::cerr << "[ExecutionStatePersistence] Execution not found: " 
                      << executionId << std::endl;
            return nullptr;
        }

        auto readCandidate = [&](const std::filesystem::path& candidate,
                                 nlohmann::json& outJson) -> bool {
            std::ifstream ifs(candidate, std::ios::binary);
            if (!ifs.good()) {
                return false;
            }
            std::stringstream buffer;
            buffer << ifs.rdbuf();
            outJson = nlohmann::json::parse(buffer.str());
            return validateJsonSchema(outJson);
        };

        nlohmann::json j;
        bool loaded = false;
        try {
            loaded = readCandidate(execPath, j);
        } catch (const std::exception&) {
            loaded = false;
        }

        if (!loaded) {
            // Quarantine bad primary and attempt backup fallback.
            try {
                auto corruptPath = corruptPathFor(execPath);
                if (std::filesystem::exists(corruptPath)) {
                    std::filesystem::remove(corruptPath);
                }
                std::filesystem::rename(execPath, corruptPath);
            } catch (const std::exception& e) {
                std::cerr << "[ExecutionStatePersistence] Failed to quarantine corrupt state: "
                          << e.what() << std::endl;
            }

            const auto backupPath = backupPathFor(execPath);
            try {
                loaded = readCandidate(backupPath, j);
            } catch (const std::exception&) {
                loaded = false;
            }

            if (loaded) {
                // Promote backup as active state to restore forward progress.
                atomicWrite(execPath, j.dump(2));
            } else {
                std::cerr << "[ExecutionStatePersistence] Invalid or corrupt state: "
                          << executionId << std::endl;
                return nullptr;
            }
        }
        
        auto execution = std::make_unique<WorkflowExecution>();
        execution->fromJson(j);
        
        std::cout << "[ExecutionStatePersistence] Loaded execution: "
                  << executionId << " with " << execution->checkpoints.size() 
                  << " checkpoints" << std::endl;
        return execution;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Load error: " << e.what() << std::endl;
        return nullptr;
    }
}

std::string ExecutionStatePersistence::createCheckpoint(
    const std::string& executionId,
    const std::string& label,
    const nlohmann::json& stateSnapshot)
{
    try {
        auto execution = loadWorkflowExecution(executionId);
        if (!execution) {
            auto bootstrap = std::make_unique<WorkflowExecution>();
            bootstrap->executionId = executionId.empty() ? generateExecutionId() : executionId;
            bootstrap->workflowName = "RecoveredWorkflow";
            bootstrap->goal = "Recovered from checkpoint bootstrap";
            bootstrap->status = "in-progress";
            bootstrap->startTime = makeIsoUtcNow();
            bootstrap->lastUpdateTime = bootstrap->startTime;
            bootstrap->globalContext = nlohmann::json::object();
            if (persistWorkflowExecution(*bootstrap).empty()) {
                return "";
            }
            execution = loadWorkflowExecution(bootstrap->executionId);
            if (!execution) {
                return "";
            }
        }
        
        ExecutionCheckpoint checkpoint;
        checkpoint.checkpointId = generateExecutionId() + "_cp";
        checkpoint.label = label;
        checkpoint.sequenceNumber = static_cast<int>(execution->checkpoints.size());
        
        checkpoint.timestamp = makeIsoUtcNow();
        
        checkpoint.stateSnapshot = stateSnapshot;
        checkpoint.isRecoveryPoint = true;
        
        execution->checkpoints.push_back(checkpoint);
        execution->currentCheckpointIndex = checkpoint.sequenceNumber;
        
        execution->lastUpdateTime = checkpoint.timestamp;
        
        persistWorkflowExecution(*execution);
        
        std::cout << "[ExecutionStatePersistence] Created checkpoint: " 
                  << checkpoint.checkpointId << " (" << label << ")" << std::endl;
        return checkpoint.checkpointId;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Checkpoint error: " << e.what() << std::endl;
        return "";
    }
}

std::vector<std::string> ExecutionStatePersistence::listExecutions() const
{
    std::vector<std::string> result;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(m_persistenceRoot)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                auto filename = entry.path().stem().string();
                if (filename.substr(0, 5) == "exec_") {
                    result.push_back(filename);
                }
            }
        }
        std::sort(result.rbegin(), result.rend());  // Most recent first
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] List error: " << e.what() << std::endl;
    }
    return result;
}

bool ExecutionStatePersistence::hasValidExecution(const std::string& executionId) const
{
    const auto execPath = std::filesystem::path(getExecutionPath(executionId));
    if (!std::filesystem::exists(execPath)) {
        return false;
    }
    return validateExecution(executionId).empty();
}

std::unique_ptr<WorkflowExecution> ExecutionStatePersistence::getLastIncompleteExecution()
{
    auto executions = listExecutions();
    for (const auto& execId : executions) {
        auto exec = loadWorkflowExecution(execId);
        if (exec && (exec->status == "in-progress" || exec->status == "paused")) {
            return exec;
        }
    }
    return nullptr;
}

std::unique_ptr<WorkflowExecution> ExecutionStatePersistence::resumeFromCheckpoint(
    const std::string& executionId,
    int checkpointIndex)
{
    try {
        auto execution = loadWorkflowExecution(executionId);
        if (!execution || execution->checkpoints.empty()) {
            return nullptr;
        }
        
        int cpIndex = findResumableCheckpointIndex(*execution, checkpointIndex);
        if (cpIndex < 0) {
            execution->errorLog.push_back("No resumable checkpoint available");
            return nullptr;
        }
        
        execution->currentCheckpointIndex = cpIndex;
        execution->status = "in-progress";
        execution->lastUpdateTime = makeIsoUtcNow();
        if (checkpointIndex != cpIndex) {
            execution->errorLog.push_back(
                std::string("Requested checkpoint unavailable; resumed from fallback index ") +
                std::to_string(cpIndex));
        }

        // Persist resumed pointer to guarantee restart continuity after resume.
        persistWorkflowExecution(*execution);
        
        std::cout << "[ExecutionStatePersistence] Resuming from checkpoint "
                  << cpIndex << " in execution " << executionId << std::endl;
        return execution;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Resume error: " << e.what() << std::endl;
        return nullptr;
    }
}

WorkflowExecution ExecutionStatePersistence::captureCurrentExecution(
    const std::string& workflowName,
    const std::string& goal,
    AgenticLoopState* loopState,
    AgenticMemorySystem* memorySystem,
    AgenticExecutor* executor)
{
    WorkflowExecution execution;
    execution.executionId = generateExecutionId();
    execution.workflowName = workflowName;
    execution.goal = goal;
    execution.status = "in-progress";
    
    execution.startTime = makeIsoUtcNow();
    execution.lastUpdateTime = execution.startTime;
    
    // Capture state snapshot
    nlohmann::json snapshot = nlohmann::json::object();
    if (loopState) {
        auto loopJson = nlohmann::json::parse(loopState->serializeState(), nullptr, false);
        if (!loopJson.is_discarded()) {
            snapshot["loopState"] = std::move(loopJson);
        }
    }
    if (memorySystem) {
        snapshot["memorySystem"] = memorySystem->exportState();
    }
    if (executor) {
        snapshot["executorContext"] = {
            {"available", true}
        };
    }
    snapshot["capturedAt"] = execution.lastUpdateTime;
    snapshot["schemaVersion"] = 1;
    
    execution.globalContext = snapshot;
    execution.metadata["capturedSubsystems"] = nlohmann::json::array();
    if (snapshot.contains("loopState")) execution.metadata["capturedSubsystems"].push_back("loopState");
    if (snapshot.contains("memorySystem")) execution.metadata["capturedSubsystems"].push_back("memorySystem");
    if (snapshot.contains("executorContext")) execution.metadata["capturedSubsystems"].push_back("executorContext");
    
    return execution;
}

bool ExecutionStatePersistence::restoreExecutionState(
    const WorkflowExecution& execution,
    AgenticLoopState* loopState,
    AgenticMemorySystem* memorySystem) const
{
    if (restoreStatePayload(execution.globalContext, loopState, memorySystem)) {
        return true;
    }

    const int checkpointIndex = findResumableCheckpointIndex(
        execution,
        execution.currentCheckpointIndex);
    if (checkpointIndex < 0) {
        return false;
    }

    return restoreCheckpointState(execution.checkpoints[checkpointIndex], loopState, memorySystem);
}

bool ExecutionStatePersistence::restoreCheckpointState(
    const ExecutionCheckpoint& checkpoint,
    AgenticLoopState* loopState,
    AgenticMemorySystem* memorySystem) const
{
    return restoreStatePayload(checkpoint.stateSnapshot, loopState, memorySystem);
}

std::string ExecutionStatePersistence::validateExecution(
    const std::string& executionId) const
{
    try {
        auto execution = loadWorkflowExecution(executionId);
        if (!execution) {
            return "Execution not found";
        }
        
        if (execution->executionId.empty()) {
            return "Missing executionId";
        }
        
        if (execution->checkpoints.empty() && execution->status == "completed") {
            return "Completed execution with no checkpoints";
        }
        
        return "";  // Valid
    } catch (const std::exception& e) {
        return std::string("Validation error: ") + e.what();
    }
}

bool ExecutionStatePersistence::recoverFromCorruption(
    const std::string& executionId)
{
    try {
        auto execution = loadWorkflowExecution(executionId);
        if (execution && !execution->checkpoints.empty()) {
            execution->currentCheckpointIndex = std::max(0, execution->currentCheckpointIndex - 1);
            execution->status = "paused";
            execution->lastUpdateTime = makeIsoUtcNow();

            auto& lastCp = execution->checkpoints.back();
            lastCp.isRecoveryPoint = true;
            lastCp.recoveryReason = "Corruption recovery";

            persistWorkflowExecution(*execution);
            std::cout << "[ExecutionStatePersistence] Recovered from checkpoint rollback: "
                      << executionId << std::endl;
            return true;
        }

        // Fallback path: restore from backup if JSON is too corrupt to load.
        const auto execPath = std::filesystem::path(getExecutionPath(executionId));
        const auto backupPath = backupPathFor(execPath);
        if (std::filesystem::exists(backupPath)) {
            nlohmann::json backupJson;
            std::ifstream ifs(backupPath, std::ios::binary);
            if (ifs.good()) {
                std::stringstream buffer;
                buffer << ifs.rdbuf();
                backupJson = nlohmann::json::parse(buffer.str());
                if (validateJsonSchema(backupJson)) {
                    if (atomicWrite(execPath, backupJson.dump(2))) {
                        std::cout << "[ExecutionStatePersistence] Recovered from backup: "
                                  << executionId << std::endl;
                        return true;
                    }
                }
            }
        }

        return false;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Recovery error: " << e.what() << std::endl;
        return false;
    }
}

bool ExecutionStatePersistence::deleteExecution(const std::string& executionId)
{
    try {
        auto execPath = getExecutionPath(executionId);
        if (std::filesystem::exists(execPath)) {
            std::filesystem::remove(execPath);
            std::cout << "[ExecutionStatePersistence] Deleted execution: " 
                      << executionId << std::endl;
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Delete error: " << e.what() << std::endl;
        return false;
    }
}

bool ExecutionStatePersistence::atomicWrite(
    const std::filesystem::path& target,
    const std::string& content) const
{
    try {
        // Write to temporary file first
        auto tempPath = std::filesystem::path(target.string() + ".tmp");
        auto backupPath = backupPathFor(target);
        
        {
            std::ofstream ofs(tempPath, std::ios::binary | std::ios::trunc);
            if (!ofs.good()) {
                return false;
            }
            ofs.write(content.c_str(), content.size());
            ofs.flush();
            ofs.close();
        }

        // Keep a hot backup of last valid state for corruption recovery.
        if (std::filesystem::exists(target)) {
            std::filesystem::copy_file(
                target,
                backupPath,
                std::filesystem::copy_options::overwrite_existing);
            std::filesystem::remove(target);
        }

        // Atomic move to active file name.
        std::filesystem::rename(tempPath, target);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Atomic write failed: " 
                  << e.what() << std::endl;
        return false;
    }
}

bool ExecutionStatePersistence::validateJsonSchema(const nlohmann::json& j) const
{
    if (!j.is_object()) {
        return false;
    }

    if (!j.contains("executionId") || !j["executionId"].is_string() ||
        !j.contains("workflowName") || !j["workflowName"].is_string() ||
        !j.contains("status") || !j["status"].is_string()) {
        return false;
    }

    if (j.contains("checkpoints")) {
        if (!j["checkpoints"].is_array()) {
            return false;
        }
        for (const auto& cp : j["checkpoints"]) {
            if (!hasRequiredCheckpointFields(cp)) {
                return false;
            }
        }
    }

    if (j.contains("currentCheckpointIndex") && !j["currentCheckpointIndex"].is_number_integer()) {
        return false;
    }

    return true;
}

int ExecutionStatePersistence::findResumableCheckpointIndex(
    const WorkflowExecution& execution,
    int requestedIndex) const
{
    if (execution.checkpoints.empty()) {
        return -1;
    }

    int index = requestedIndex;
    if (index < 0 || index >= static_cast<int>(execution.checkpoints.size())) {
        index = static_cast<int>(execution.checkpoints.size()) - 1;
    }

    for (int candidate = index; candidate >= 0; --candidate) {
        if (execution.checkpoints[candidate].stateSnapshot.is_object()) {
            return candidate;
        }
    }

    return -1;
}

bool ExecutionStatePersistence::restoreStatePayload(
    const nlohmann::json& payload,
    AgenticLoopState* loopState,
    AgenticMemorySystem* memorySystem) const
{
    if (!payload.is_object()) {
        return false;
    }

    bool restored = false;

    if (loopState && payload.contains("loopState")) {
        const auto& loopStateJson = payload["loopState"];
        if (loopStateJson.is_object()) {
            restored = loopState->deserializeState(loopStateJson.dump()) || restored;
        }
    }

    if (memorySystem && payload.contains("memorySystem")) {
        restored = memorySystem->importState(payload["memorySystem"]) || restored;
    }

    return restored;
}

ExecutionStatePersistence::PersistenceStats ExecutionStatePersistence::getStatistics() const
{
    PersistenceStats stats;
    try {
        auto executions = listExecutions();
        stats.totalExecutions = executions.size();
        
        for (const auto& execId : executions) {
            auto exec = loadWorkflowExecution(execId);
            if (exec) {
                if (exec->status == "in-progress") stats.activeExecutions++;
                else if (exec->status == "completed") stats.completedExecutions++;
                else if (exec->status == "failed") stats.failedExecutions++;
                
                stats.totalCheckpoints += exec->checkpoints.size();
            }
        }
        
        // Estimate disk usage
        for (const auto& entry : std::filesystem::directory_iterator(m_persistenceRoot)) {
            if (entry.is_regular_file()) {
                stats.diskUsageBytes += std::filesystem::file_size(entry);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Stats error: " << e.what() << std::endl;
    }
    
    return stats;
}

int ExecutionStatePersistence::cleanupOldExecutions(int maxAgeHours)
{
    int deleted = 0;
    try {
        if (maxAgeHours <= 0) return 0;
        
        const auto fileNow = std::filesystem::file_time_type::clock::now();
        const auto maxAge = std::chrono::duration_cast<std::filesystem::file_time_type::duration>(
            std::chrono::hours(maxAgeHours));
        
        for (const auto& execId : listExecutions()) {
            auto exec = loadWorkflowExecution(execId);
            if (!exec) continue;
            
            // Parse timestamp (simplified - assumes ISO format)
            if (exec->completionTime.empty()) continue;
            
            // For production: compare with persistent file modification time
            auto execPath = getExecutionPath(execId);
            auto lastWrite = std::filesystem::last_write_time(execPath);

            if (fileNow - lastWrite > maxAge) {
                if (deleteExecution(execId)) {
                    deleted++;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ExecutionStatePersistence] Cleanup error: " << e.what() << std::endl;
    }
    
    std::cout << "[ExecutionStatePersistence] Cleaned up " << deleted 
              << " old executions" << std::endl;
    return deleted;
}
