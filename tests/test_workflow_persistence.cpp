#include "../src/agentic_loop_state.h"
#include "../src/agentic_memory_system.h"
#include "../src/execution_state_persistence.h"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace {
bool expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "[workflow_persistence_smoke] FAIL: " << message << std::endl;
        return false;
    }
    return true;
}
}

int main()
{
    namespace fs = std::filesystem;

    const auto root = fs::temp_directory_path() / "rawrxd_workflow_persistence_smoke";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
    if (ec) {
        std::cerr << "[workflow_persistence_smoke] temp dir setup failed: " << ec.message() << std::endl;
        return 1;
    }

    bool ok = true;
    ExecutionStatePersistence persistence(root);

    AgenticLoopState originalLoop;
    originalLoop.startIteration("Validate workflow persistence");
    originalLoop.setCurrentPhase(ReasoningPhase::Planning);
    originalLoop.addToMemory("active_file", "TodoManager.cpp");
    originalLoop.addConstraint("sandbox", "workspace-only");
    originalLoop.updateProgress(1, 3);
    originalLoop.recordDecision("capture baseline", nlohmann::json{{"step", 1}}, 0.92f);

    AgenticMemorySystem originalMemory;
    originalMemory.storeMemory(MemoryType::Fact, "critical owner: AgentPolish", "workflow-owner");
    originalMemory.storeMemory(MemoryType::Procedure, "checkpoint before risky task", "recovery");

    auto execution = persistence.captureCurrentExecution(
        "WorkflowPersistenceSmoke",
        "Persist and restore loop state",
        &originalLoop,
        &originalMemory,
        nullptr);
    execution.executionId = "workflow_persistence_smoke";

    const auto executionId = persistence.persistWorkflowExecution(execution);
    ok &= expect(!executionId.empty(), "persisted execution id");

    const auto checkpointA = persistence.createCheckpoint(
        executionId,
        "checkpoint_a",
        nlohmann::json{
            {"loopState", nlohmann::json::parse(originalLoop.serializeState())},
            {"memorySystem", originalMemory.exportState()},
            {"checkpointStage", "baseline"}
        });
    ok &= expect(!checkpointA.empty(), "created checkpoint_a");

    AgenticLoopState resumedLoop;
    AgenticMemorySystem resumedMemory;
    auto loaded = persistence.loadWorkflowExecution(executionId);
    ok &= expect(loaded != nullptr, "load persisted workflow");
    if (loaded) {
        ok &= expect(persistence.restoreExecutionState(*loaded, &resumedLoop, &resumedMemory), "restore execution state");
        ok &= expect(resumedLoop.getFromMemory("active_file") == "TodoManager.cpp", "restored loop memory");
        ok &= expect(resumedMemory.getMemoryCount() == 2, "restored memory system entries");
    }

    auto resumeLoaded = persistence.loadWorkflowExecution(executionId);
    ok &= expect(resumeLoaded != nullptr, "reload execution for checkpoint mutation");
    if (resumeLoaded && !resumeLoaded->checkpoints.empty()) {
        resumeLoaded->checkpoints.back().stateSnapshot = "corrupt_checkpoint_payload";
        ok &= expect(!persistence.persistWorkflowExecution(*resumeLoaded).empty(), "persist checkpoint corruption scenario");
    }

    const auto checkpointB = persistence.createCheckpoint(
        executionId,
        "checkpoint_b",
        nlohmann::json{
            {"loopState", nlohmann::json::parse(originalLoop.serializeState())},
            {"memorySystem", originalMemory.exportState()},
            {"checkpointStage", "recovered"}
        });
    ok &= expect(!checkpointB.empty(), "created checkpoint_b");

    auto resumed = persistence.resumeFromCheckpoint(executionId);
    ok &= expect(resumed != nullptr, "resume from latest valid checkpoint");
    if (resumed) {
        ok &= expect(resumed->currentCheckpointIndex >= 0, "checkpoint index selected");
        ok &= expect(persistence.restoreCheckpointState(
            resumed->checkpoints[resumed->currentCheckpointIndex],
            &resumedLoop,
            &resumedMemory), "restore checkpoint state");
    }

    {
        std::ofstream corrupt(fs::path(root) / (executionId + ".json"), std::ios::binary | std::ios::trunc);
        corrupt << "{ definitely not valid json";
    }

    auto recovered = persistence.loadWorkflowExecution(executionId);
    ok &= expect(recovered != nullptr, "recover from corrupt primary file using backup");
    ok &= expect(fs::exists(fs::path(root) / (executionId + ".json.corrupt")), "quarantined corrupt state");

    fs::remove_all(root, ec);
    if (!ok) {
        return 1;
    }

    std::cout << "[workflow_persistence_smoke] PASS" << std::endl;
    return 0;
}