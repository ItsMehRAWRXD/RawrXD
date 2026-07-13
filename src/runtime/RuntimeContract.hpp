#pragma once

/**
 * RuntimeContract.hpp
 *
 * Phase C.1 Batch 4/5: Runtime Contract Freeze
 *
 * Defines the frozen API contracts and state model for the Sovereign Runtime.
 * These contracts are guaranteed to remain stable for Phase C and beyond.
 */

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>

namespace Sovereign {

/**
 * API Version
 */
constexpr const char* RUNTIME_API_VERSION = "1.0.0";
constexpr int RUNTIME_API_MAJOR = 1;
constexpr int RUNTIME_API_MINOR = 0;
constexpr int RUNTIME_API_PATCH = 0;

/**
 * Initialization Contract
 *
 * Guarantees:
 * - Initialize() returns true ONLY if all 7 steps succeed
 * - Components initialize in strict order: SEG → Engine → Swarm → Telemetry → Graph → Dashboard → Scheduler
 * - Shutdown() is idempotent and can be called multiple times safely
 * - IsRunning() reflects actual runtime state
 */
class IInitializable {
public:
    virtual ~IInitializable() = default;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsRunning() const = 0;
};

/**
 * Execution Contract
 *
 * Guarantees:
 * - ExecuteWorkflow() returns true only on successful completion
 * - RunUntilConvergence() respects target and maxIterations bounds
 * - Convergence is determined by harmony index >= target
 * - All execution is observable through telemetry
 */
class IExecutable {
public:
    virtual ~IExecutable() = default;
    virtual bool ExecuteWorkflow() = 0;
    virtual bool RunUntilConvergence(double target, int maxIterations) = 0;
};

/**
 * Checkpoint Contract
 *
 * Guarantees:
 * - CreateCheckpoint() returns non-empty ID on success
 * - RestoreCheckpoint() returns true only if ALL components deserialize successfully
 * - Checkpoints are atomic - either fully saved or not saved
 * - Checkpoint IDs are unique and persistent
 */
class ICheckpointable {
public:
    virtual ~ICheckpointable() = default;
    virtual std::string CreateCheckpoint(const std::string& description) = 0;
    virtual bool RestoreCheckpoint(const std::string& checkpointId) = 0;
    virtual bool DeleteCheckpoint(const std::string& checkpointId) = 0;
};

/**
 * Validation Contract
 *
 * Guarantees:
 * - Validation hooks execute in priority order (highest first)
 * - Critical hook failures can abort execution based on configuration
 * - Validation results are recorded and exportable
 * - Continuous validation runs at configured intervals
 */
class IValidatable {
public:
    virtual ~IValidatable() = default;
    virtual void RegisterValidationHook(const struct ValidationHook& hook) = 0;
    virtual bool RunValidationHooks() = 0;
};

/**
 * Observable Contract
 *
 * Guarantees:
 * - GetStatus() returns consistent snapshot of runtime state
 * - ExportStateToJson() produces valid JSON representation
 * - Performance metrics are captured for all operations
 * - Memory usage is tracked per component
 */
class IObservable {
public:
    virtual ~IObservable() = default;
    virtual std::string ExportStateToJson() const = 0;
    virtual struct RuntimeStatus GetStatus() const = 0;
};

/**
 * State Model Contract
 *
 * Defines valid state transitions:
 * UNINITIALIZED → INITIALIZING → RUNNING
 * RUNNING → CHECKPOINTING → RUNNING
 * RUNNING → RESTORING → RUNNING
 * RUNNING → SHUTTING_DOWN → SHUTDOWN
 */
enum class RuntimeState {
    UNINITIALIZED,
    INITIALIZING,
    RUNNING,
    CHECKPOINTING,
    RESTORING,
    SHUTTING_DOWN,
    SHUTDOWN,
    ERROR
};

/**
 * State transition validation
 */
class StateTransitionValidator {
public:
    static bool IsValidTransition(RuntimeState from, RuntimeState to);
    static const char* StateToString(RuntimeState state);
};

/**
 * Extension Point Contract
 *
 * Defines how components can extend the runtime:
 * - Component registration for checkpointing
 * - Validation hook registration
 * - Custom metric registration
 * - Event handler registration
 */
struct ExtensionPoint {
    std::string name;
    std::string description;
    std::vector<std::string> requiredInterfaces;
    std::function<bool()> validateFunc;
};

/**
 * Performance Contract
 *
 * Latency budgets (milliseconds):
 * - Initialization: < 500 (target), < 2000 (max)
 * - Graph Construction: < 100 (target), < 500 (max)
 * - Workflow Execution: < 50 (target), < 200 (max)
 * - Checkpoint Save: < 100 (target), < 500 (max)
 * - Checkpoint Restore: < 200 (target), < 1000 (max)
 *
 * Memory budgets:
 * - Runtime Core: < 10 MB (target), < 50 MB (max)
 * - SEG (256 nodes): < 5 MB (target), < 20 MB (max)
 * - Telemetry Buffer: < 50 MB (target), < 200 MB (max)
 * - Full Checkpoint: < 100 MB (target), < 500 MB (max)
 */
struct PerformanceContract {
    static constexpr int64_t MAX_INIT_LATENCY_MS = 2000;
    static constexpr int64_t MAX_GRAPH_BUILD_MS = 500;
    static constexpr int64_t MAX_WORKFLOW_MS = 200;
    static constexpr int64_t MAX_CHECKPOINT_SAVE_MS = 500;
    static constexpr int64_t MAX_CHECKPOINT_RESTORE_MS = 1000;

    static constexpr size_t MAX_RUNTIME_MEMORY_BYTES = 50 * 1024 * 1024;
    static constexpr size_t MAX_SEG_MEMORY_BYTES = 20 * 1024 * 1024;
    static constexpr size_t MAX_TELEMETRY_MEMORY_BYTES = 200 * 1024 * 1024;
    static constexpr size_t MAX_CHECKPOINT_BYTES = 500 * 1024 * 1024;
};

/**
 * Recovery Contract
 *
 * Guarantees:
 * - Checkpoints can be restored to equivalent runtime state
 * - Failed restores leave runtime in ERROR state (not corrupt state)
 * - Auto-checkpoint on convergence creates recoverable milestone
 * - Shutdown checkpoint enables clean restart
 */
struct RecoveryContract {
    static constexpr bool CHECKPOINT_ON_CONVERGENCE = true;
    static constexpr bool CHECKPOINT_ON_SHUTDOWN = true;
    static constexpr int DEFAULT_AUTO_CHECKPOINT_MINUTES = 30;
    static constexpr int MAX_CHECKPOINTS = 10;
};

/**
 * Contract Verification
 *
 * Runtime verification of contract compliance
 */
class ContractVerifier {
public:
    static bool VerifyApiVersion(const std::string& version);
    static bool VerifyStateTransition(RuntimeState from, RuntimeState to);
    static bool VerifyLatencyBudget(const std::string& operation, int64_t latencyMs);
    static bool VerifyMemoryBudget(const std::string& component, size_t memoryBytes);
    static bool VerifyCheckpointIntegrity(const std::string& checkpointId);
};

/**
 * Contract Documentation
 *
 * Generates contract documentation from code
 */
class ContractDocumentation {
public:
    static std::string GenerateApiReference();
    static std::string GenerateStateDiagram();
    static std::string GeneratePerformanceBudgets();
    static std::string GenerateRecoverySemantics();
    static bool SaveToFile(const std::string& path);
};

} // namespace Sovereign
