// =============================================================================
// CommandHandlers.hpp - Unified command handler declarations
// =============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>

namespace RawrXD {

// Command context structure
struct CommandContext {
    std::string command;
    std::vector<std::string> args;
    std::map<std::string, std::string> options;
    void* userData = nullptr;
};

// Command result structure
struct CommandResult {
    bool success = false;
    std::string message;
    int exitCode = 0;
    std::map<std::string, std::string> data;
};

// =============================================================================
// Multi-Response Handlers
// =============================================================================
CommandResult handleMultiRespShowPrefs(const CommandContext& ctx);
CommandResult handleMultiRespShowLatest(const CommandContext& ctx);
CommandResult handleMultiRespShowStatus(const CommandContext& ctx);
CommandResult handleMultiRespClearHistory(const CommandContext& ctx);
CommandResult handleMultiRespApplyPreferred(const CommandContext& ctx);

// =============================================================================
// Governance Handlers
// =============================================================================
CommandResult handleGovStatus(const CommandContext& ctx);
CommandResult handleGovSubmitCommand(const CommandContext& ctx);
CommandResult handleGovKillAll(const CommandContext& ctx);
CommandResult handleGovTaskList(const CommandContext& ctx);

// =============================================================================
// Safety Handlers
// =============================================================================
CommandResult handleSafetyStatus(const CommandContext& ctx);
CommandResult handleSafetyResetBudget(const CommandContext& ctx);
CommandResult handleSafetyShowViolations(const CommandContext& ctx);

// =============================================================================
// Replay Handlers
// =============================================================================
CommandResult handleReplayStatus(const CommandContext& ctx);
CommandResult handleReplayStart(const CommandContext& ctx);
CommandResult handleReplayStop(const CommandContext& ctx);
CommandResult handleReplayPause(const CommandContext& ctx);
CommandResult handleReplayResume(const CommandContext& ctx);

// =============================================================================
// Tier 1 Handlers
// =============================================================================
CommandResult handleTier1Status(const CommandContext& ctx);
CommandResult handleTier1Initialize(const CommandContext& ctx);
CommandResult handleTier1Shutdown(const CommandContext& ctx);

// =============================================================================
// LSP Handlers
// =============================================================================
CommandResult handleLspInitialize(const CommandContext& ctx);
CommandResult handleLspShutdown(const CommandContext& ctx);
CommandResult handleLspStatus(const CommandContext& ctx);

// =============================================================================
// ASM Handlers
// =============================================================================
CommandResult handleAsmAssemble(const CommandContext& ctx);
CommandResult handleAsmDisassemble(const CommandContext& ctx);
CommandResult handleAsmLink(const CommandContext& ctx);

// =============================================================================
// AI Feature Handlers
// =============================================================================
CommandResult handleAIFeatureEnable(const CommandContext& ctx);
CommandResult handleAIFeatureDisable(const CommandContext& ctx);
CommandResult handleAIFeatureStatus(const CommandContext& ctx);

// =============================================================================
// VSCode Extension Handlers
// =============================================================================
CommandResult handleVSCodeExtInstall(const CommandContext& ctx);
CommandResult handleVSCodeExtUninstall(const CommandContext& ctx);
CommandResult handleVSCodeExtUpdate(const CommandContext& ctx);

// =============================================================================
// Model Handlers
// =============================================================================
CommandResult handleModelLoad(const CommandContext& ctx);
CommandResult handleModelUnload(const CommandContext& ctx);
CommandResult handleModelStatus(const CommandContext& ctx);

// =============================================================================
// Inference Handlers
// =============================================================================
CommandResult handleInferenceStart(const CommandContext& ctx);
CommandResult handleInferenceStop(const CommandContext& ctx);
CommandResult handleInferenceStatus(const CommandContext& ctx);

// =============================================================================
// Agentic Handlers
// =============================================================================
CommandResult handleAgenticStart(const CommandContext& ctx);
CommandResult handleAgenticStop(const CommandContext& ctx);
CommandResult handleAgenticStatus(const CommandContext& ctx);

// =============================================================================
// Security Handlers
// =============================================================================
CommandResult handleSecurityAudit(const CommandContext& ctx);
CommandResult handleSecurityValidate(const CommandContext& ctx);
CommandResult handleSecuritySanitize(const CommandContext& ctx);

// =============================================================================
// Telemetry Handlers
// =============================================================================
CommandResult handleTelemetryStart(const CommandContext& ctx);
CommandResult handleTelemetryStop(const CommandContext& ctx);
CommandResult handleTelemetryExport(const CommandContext& ctx);

// =============================================================================
// Debug Handlers
// =============================================================================
CommandResult handleDebugAttach(const CommandContext& ctx);
CommandResult handleDebugDetach(const CommandContext& ctx);
CommandResult handleDebugBreakpoint(const CommandContext& ctx);

// =============================================================================
// Build Handlers
// =============================================================================
CommandResult handleBuildStart(const CommandContext& ctx);
CommandResult handleBuildClean(const CommandContext& ctx);
CommandResult handleBuildStatus(const CommandContext& ctx);

// =============================================================================
// Test Handlers
// =============================================================================
CommandResult handleTestRun(const CommandContext& ctx);
CommandResult handleTestCoverage(const CommandContext& ctx);
CommandResult handleTestBenchmark(const CommandContext& ctx);

// =============================================================================
// System Handlers
// =============================================================================
CommandResult handleSystemInfo(const CommandContext& ctx);
CommandResult handleSystemHealth(const CommandContext& ctx);
CommandResult handleSystemRestart(const CommandContext& ctx);

} // namespace RawrXD
