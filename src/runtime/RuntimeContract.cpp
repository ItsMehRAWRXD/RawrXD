/**
 * RuntimeContract.cpp
 *
 * Phase C.1 Batch 4/5: Runtime Contract Implementation
 */

#include "RuntimeContract.hpp"
#include <sstream>
#include <fstream>
#include <iostream>

namespace Sovereign {

// StateTransitionValidator implementation
bool StateTransitionValidator::IsValidTransition(RuntimeState from, RuntimeState to) {
    switch (from) {
        case RuntimeState::UNINITIALIZED:
            return to == RuntimeState::INITIALIZING;
        
        case RuntimeState::INITIALIZING:
            return to == RuntimeState::RUNNING || to == RuntimeState::ERROR;
        
        case RuntimeState::RUNNING:
            return to == RuntimeState::CHECKPOINTING || 
                   to == RuntimeState::RESTORING || 
                   to == RuntimeState::SHUTTING_DOWN || 
                   to == RuntimeState::ERROR;
        
        case RuntimeState::CHECKPOINTING:
            return to == RuntimeState::RUNNING || to == RuntimeState::ERROR;
        
        case RuntimeState::RESTORING:
            return to == RuntimeState::RUNNING || to == RuntimeState::ERROR;
        
        case RuntimeState::SHUTTING_DOWN:
            return to == RuntimeState::SHUTDOWN || to == RuntimeState::ERROR;
        
        case RuntimeState::SHUTDOWN:
            return false; // Terminal state
        
        case RuntimeState::ERROR:
            return to == RuntimeState::UNINITIALIZED; // Allow reset
        
        default:
            return false;
    }
}

const char* StateTransitionValidator::StateToString(RuntimeState state) {
    switch (state) {
        case RuntimeState::UNINITIALIZED: return "UNINITIALIZED";
        case RuntimeState::INITIALIZING: return "INITIALIZING";
        case RuntimeState::RUNNING: return "RUNNING";
        case RuntimeState::CHECKPOINTING: return "CHECKPOINTING";
        case RuntimeState::RESTORING: return "RESTORING";
        case RuntimeState::SHUTTING_DOWN: return "SHUTTING_DOWN";
        case RuntimeState::SHUTDOWN: return "SHUTDOWN";
        case RuntimeState::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

// ContractVerifier implementation
bool ContractVerifier::VerifyApiVersion(const std::string& version) {
    // Parse version string (format: major.minor.patch)
    int major = 0, minor = 0, patch = 0;
    if (sscanf(version.c_str(), "%d.%d.%d", &major, &minor, &patch) != 3) {
        return false;
    }
    
    // Check compatibility: same major version, minor >= required
    if (major != RUNTIME_API_MAJOR) {
        return false;
    }
    if (minor < RUNTIME_API_MINOR) {
        return false;
    }
    return true;
}

bool ContractVerifier::VerifyStateTransition(RuntimeState from, RuntimeState to) {
    return StateTransitionValidator::IsValidTransition(from, to);
}

bool ContractVerifier::VerifyLatencyBudget(const std::string& operation, int64_t latencyMs) {
    if (operation == "initialization") {
        return latencyMs <= PerformanceContract::MAX_INIT_LATENCY_MS;
    } else if (operation == "graph_construction") {
        return latencyMs <= PerformanceContract::MAX_GRAPH_BUILD_MS;
    } else if (operation == "workflow_execution") {
        return latencyMs <= PerformanceContract::MAX_WORKFLOW_MS;
    } else if (operation == "checkpoint_save") {
        return latencyMs <= PerformanceContract::MAX_CHECKPOINT_SAVE_MS;
    } else if (operation == "checkpoint_restore") {
        return latencyMs <= PerformanceContract::MAX_CHECKPOINT_RESTORE_MS;
    }
    return true; // Unknown operations pass by default
}

bool ContractVerifier::VerifyMemoryBudget(const std::string& component, size_t memoryBytes) {
    if (component == "runtime") {
        return memoryBytes <= PerformanceContract::MAX_RUNTIME_MEMORY_BYTES;
    } else if (component == "seg") {
        return memoryBytes <= PerformanceContract::MAX_SEG_MEMORY_BYTES;
    } else if (component == "telemetry") {
        return memoryBytes <= PerformanceContract::MAX_TELEMETRY_MEMORY_BYTES;
    } else if (component == "checkpoint") {
        return memoryBytes <= PerformanceContract::MAX_CHECKPOINT_BYTES;
    }
    return true; // Unknown components pass by default
}

bool ContractVerifier::VerifyCheckpointIntegrity(const std::string& checkpointId) {
    // In production, this would verify checksums, signatures, etc.
    // For now, just check that ID is non-empty and well-formed
    if (checkpointId.empty()) {
        return false;
    }
    if (checkpointId.find("cp-") != 0) {
        return false;
    }
    return true;
}

// ContractDocumentation implementation
std::string ContractDocumentation::GenerateApiReference() {
    std::ostringstream doc;
    
    doc << "# Sovereign Runtime API Reference\n\n";
    doc << "Version: " << RUNTIME_API_VERSION << "\n\n";
    
    doc << "## Core Interfaces\n\n";
    
    doc << "### IInitializable\n\n";
    doc << "```cpp\n";
    doc << "class IInitializable {\n";
    doc << "public:\n";
    doc << "    virtual ~IInitializable() = default;\n";
    doc << "    virtual bool Initialize() = 0;\n";
    doc << "    virtual void Shutdown() = 0;\n";
    doc << "    virtual bool IsRunning() const = 0;\n";
    doc << "};\n";
    doc << "```\n\n";
    doc << "**Contract**: Initialize() returns true ONLY if all 7 initialization steps succeed.\n";
    doc << "Shutdown() is idempotent.\n\n";
    
    doc << "### IExecutable\n\n";
    doc << "```cpp\n";
    doc << "class IExecutable {\n";
    doc << "public:\n";
    doc << "    virtual ~IExecutable() = default;\n";
    doc << "    virtual bool ExecuteWorkflow() = 0;\n";
    doc << "    virtual bool RunUntilConvergence(double target, int maxIterations) = 0;\n";
    doc << "};\n";
    doc << "```\n\n";
    doc << "**Contract**: ExecuteWorkflow() returns true only on successful completion.\n";
    doc << "RunUntilConvergence() respects target and maxIterations bounds.\n\n";
    
    doc << "### ICheckpointable\n\n";
    doc << "```cpp\n";
    doc << "class ICheckpointable {\n";
    doc << "public:\n";
    doc << "    virtual ~ICheckpointable() = default;\n";
    doc << "    virtual std::string CreateCheckpoint(const std::string& description) = 0;\n";
    doc << "    virtual bool RestoreCheckpoint(const std::string& checkpointId) = 0;\n";
    doc << "    virtual bool DeleteCheckpoint(const std::string& checkpointId) = 0;\n";
    doc << "};\n";
    doc << "```\n\n";
    doc << "**Contract**: CreateCheckpoint() returns non-empty ID on success.\n";
    doc << "RestoreCheckpoint() returns true only if ALL components deserialize successfully.\n\n";
    
    return doc.str();
}

std::string ContractDocumentation::GenerateStateDiagram() {
    std::ostringstream doc;
    
    doc << "# Runtime State Model\n\n";
    doc << "```\n";
    doc << "                    +----------------+\n";
    doc << "                    | UNINITIALIZED  |\n";
    doc << "                    +--------+-------+\n";
    doc << "                             | Initialize()\n";
    doc << "                             v\n";
    doc << "                    +--------+-------+\n";
    doc << "           +------->|  INITIALIZING  |<-------+\n";
    doc << "           |        +--------+-------+        |\n";
    doc << "           |                 |                  |\n";
    doc << "           |                 v                  |\n";
    doc << "           |        +--------+-------+        |\n";
    doc << "           |   +--->|     RUNNING    |<---+   |\n";
    doc << "           |   |    +--------+-------+    |   |\n";
    doc << "           |   |             |            |   |\n";
    doc << "    Error  |   |    +--------+--------+   |   |  Error\n";
    doc << "           |   +--->|  CHECKPOINTING  |   |   |\n";
    doc << "           |        +--------+--------+   |   |\n";
    doc << "           |   +--->|    RESTORING    |   |   |\n";
    doc << "           |   |    +--------+--------+   |   |\n";
    doc << "           |   |             |            |   |\n";
    doc << "           |   |             v            |   |\n";
    doc << "           |   |    +--------+-------+    |   |\n";
    doc << "           |   +----| SHUTTING_DOWN  |    |   |\n";
    doc << "           |        +--------+-------+    |   |\n";
    doc << "           |                 |            |   |\n";
    doc << "           |                 v            |   |\n";
    doc << "           |        +--------+-------+    |   |\n";
    doc << "           +------->|    SHUTDOWN    |----+   |\n";
    doc << "           |        +----------------+        |\n";
    doc << "           |                                  |\n";
    doc << "           v                                  v\n";
    doc << "    +-------------+                    +-------------+\n";
    doc << "    |    ERROR    |------------------->| UNINITIALIZED|\n";
    doc << "    +-------------+      Reset()       +-------------+\n";
    doc << "```\n\n";
    
    doc << "## Valid Transitions\n\n";
    doc << "| From | To | Trigger |\n";
    doc << "|------|-----|---------|\n";
    doc << "| UNINITIALIZED | INITIALIZING | Initialize() |\n";
    doc << "| INITIALIZING | RUNNING | Success |\n";
    doc << "| INITIALIZING | ERROR | Failure |\n";
    doc << "| RUNNING | CHECKPOINTING | CreateCheckpoint() |\n";
    doc << "| RUNNING | RESTORING | RestoreCheckpoint() |\n";
    doc << "| RUNNING | SHUTTING_DOWN | Shutdown() |\n";
    doc << "| RUNNING | ERROR | Exception |\n";
    doc << "| CHECKPOINTING | RUNNING | Complete |\n";
    doc << "| RESTORING | RUNNING | Complete |\n";
    doc << "| SHUTTING_DOWN | SHUTDOWN | Complete |\n";
    doc << "| ERROR | UNINITIALIZED | Reset() |\n";
    
    return doc.str();
}

std::string ContractDocumentation::GeneratePerformanceBudgets() {
    std::ostringstream doc;
    
    doc << "# Performance Contracts\n\n";
    doc << "## Latency Budgets (milliseconds)\n\n";
    doc << "| Operation | Target | Maximum |\n";
    doc << "|-----------|--------|---------|\n";
    doc << "| Initialization | < 500 | < " << PerformanceContract::MAX_INIT_LATENCY_MS << " |\n";
    doc << "| Graph Construction | < 100 | < " << PerformanceContract::MAX_GRAPH_BUILD_MS << " |\n";
    doc << "| Workflow Execution | < 50 | < " << PerformanceContract::MAX_WORKFLOW_MS << " |\n";
    doc << "| Checkpoint Save | < 100 | < " << PerformanceContract::MAX_CHECKPOINT_SAVE_MS << " |\n";
    doc << "| Checkpoint Restore | < 200 | < " << PerformanceContract::MAX_CHECKPOINT_RESTORE_MS << " |\n";
    
    doc << "\n## Memory Budgets\n\n";
    doc << "| Component | Target | Maximum |\n";
    doc << "|-----------|--------|---------|\n";
    doc << "| Runtime Core | < 10 MB | < " << (PerformanceContract::MAX_RUNTIME_MEMORY_BYTES / (1024 * 1024)) << " MB |\n";
    doc << "| SEG (256 nodes) | < 5 MB | < " << (PerformanceContract::MAX_SEG_MEMORY_BYTES / (1024 * 1024)) << " MB |\n";
    doc << "| Telemetry Buffer | < 50 MB | < " << (PerformanceContract::MAX_TELEMETRY_MEMORY_BYTES / (1024 * 1024)) << " MB |\n";
    doc << "| Full Checkpoint | < 100 MB | < " << (PerformanceContract::MAX_CHECKPOINT_BYTES / (1024 * 1024)) << " MB |\n";
    
    return doc.str();
}

std::string ContractDocumentation::GenerateRecoverySemantics() {
    std::ostringstream doc;
    
    doc << "# Recovery Semantics\n\n";
    
    doc << "## Checkpoint Guarantees\n\n";
    doc << "- Checkpoints capture complete runtime state\n";
    doc << "- Restore returns runtime to equivalent state\n";
    doc << "- Failed restores leave runtime in ERROR state (not corrupt)\n";
    doc << "- Checkpoint IDs are unique and persistent\n\n";
    
    doc << "## Auto-Checkpoint Configuration\n\n";
    doc << "- On Convergence: " << (RecoveryContract::CHECKPOINT_ON_CONVERGENCE ? "ENABLED" : "DISABLED") << "\n";
    doc << "- On Shutdown: " << (RecoveryContract::CHECKPOINT_ON_SHUTDOWN ? "ENABLED" : "DISABLED") << "\n";
    doc << "- Auto-Checkpoint Interval: " << RecoveryContract::DEFAULT_AUTO_CHECKPOINT_MINUTES << " minutes\n";
    doc << "- Max Checkpoints: " << RecoveryContract::MAX_CHECKPOINTS << "\n\n";
    
    doc << "## Recovery Procedures\n\n";
    doc << "### From Shutdown Checkpoint\n";
    doc << "1. Initialize runtime\n";
    doc << "2. Restore from shutdown checkpoint\n";
    doc << "3. Resume from saved state\n\n";
    
    doc << "### From Convergence Checkpoint\n";
    doc << "1. Initialize runtime\n";
    doc << "2. Restore from convergence checkpoint\n";
    doc << "3. Continue from converged state\n\n";
    
    doc << "### From Error State\n";
    doc << "1. Reset runtime to UNINITIALIZED\n";
    doc << "2. Re-initialize from scratch OR\n";
    doc << "3. Restore from last known good checkpoint\n";
    
    return doc.str();
}

bool ContractDocumentation::SaveToFile(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# Sovereign Runtime Contract Documentation\n\n";
    file << "**Version**: " << RUNTIME_API_VERSION << "\n\n";
    file << "**Frozen**: Phase C.1 Qualification\n\n";
    file << "---\n\n";
    
    file << GenerateApiReference() << "\n\n";
    file << GenerateStateDiagram() << "\n\n";
    file << GeneratePerformanceBudgets() << "\n\n";
    file << GenerateRecoverySemantics() << "\n";
    
    return true;
}

} // namespace Sovereign
