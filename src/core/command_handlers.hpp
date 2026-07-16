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

// =============================================================================
// Tier1 Split Handlers (Batch 1)
// =============================================================================
CommandResult handleTier1SplitHorizontal(const CommandContext& ctx);
CommandResult handleTier1SplitVertical(const CommandContext& ctx);
CommandResult handleTier1SplitGrid(const CommandContext& ctx);
CommandResult handleTier1SplitClose(const CommandContext& ctx);
CommandResult handleTier1SplitFocusNext(const CommandContext& ctx);
CommandResult handleTier1SplitFocusPrev(const CommandContext& ctx);
CommandResult handleTier1AutoUpdateCheck(const CommandContext& ctx);
CommandResult handleTier1UpdateDismiss(const CommandContext& ctx);

// =============================================================================
// LSP Additional Handlers (Batch 1)
// =============================================================================
CommandResult handleLspStartAll(const CommandContext& ctx);
CommandResult handleLspStopAll(const CommandContext& ctx);
CommandResult handleLspConfigure(const CommandContext& ctx);
CommandResult handleLspSaveConfig(const CommandContext& ctx);

// =============================================================================
// ASM Info Handlers (Batch 1)
// =============================================================================
CommandResult handleAsmInstructionInfo(const CommandContext& ctx);
CommandResult handleAsmRegisterInfo(const CommandContext& ctx);
CommandResult handleAsmMemoryMap(const CommandContext& ctx);

// =============================================================================
// Multi-Response Additional Handlers (Batch 1)
// =============================================================================
CommandResult handleMultiRespShowHistory(const CommandContext& ctx);
CommandResult handleMultiRespExport(const CommandContext& ctx);
CommandResult handleMultiRespImport(const CommandContext& ctx);

// =============================================================================
// Governance Additional Handlers (Batch 1)
// =============================================================================
CommandResult handleGovPause(const CommandContext& ctx);
CommandResult handleGovResume(const CommandContext& ctx);
CommandResult handleGovConfigure(const CommandContext& ctx);

// =============================================================================
// Safety Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleSafetyEnable(const CommandContext& ctx);
CommandResult handleSafetyDisable(const CommandContext& ctx);
CommandResult handleSafetyConfigure(const CommandContext& ctx);

// =============================================================================
// Replay Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleReplayLoad(const CommandContext& ctx);
CommandResult handleReplaySave(const CommandContext& ctx);
CommandResult handleReplaySeek(const CommandContext& ctx);
CommandResult handleReplayStepForward(const CommandContext& ctx);
CommandResult handleReplayStepBack(const CommandContext& ctx);

// =============================================================================
// Tier1 Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleTier1Configure(const CommandContext& ctx);
CommandResult handleTier1Reset(const CommandContext& ctx);
CommandResult handleTier1Optimize(const CommandContext& ctx);

// =============================================================================
// LSP Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleLspRestart(const CommandContext& ctx);
CommandResult handleLspLog(const CommandContext& ctx);

// =============================================================================
// ASM Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleAsmOptimize(const CommandContext& ctx);
CommandResult handleAsmValidate(const CommandContext& ctx);

// =============================================================================
// AI Feature Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleAIFeatureConfigure(const CommandContext& ctx);
CommandResult handleAIFeatureList(const CommandContext& ctx);

// =============================================================================
// VSCode Extension Additional Handlers (Batch 2)
// =============================================================================
CommandResult handleVSCodeExtList(const CommandContext& ctx);
CommandResult handleVSCodeExtEnable(const CommandContext& ctx);
CommandResult handleVSCodeExtDisable(const CommandContext& ctx);

// =============================================================================
// Model Additional Handlers (Batch 3)
// =============================================================================
CommandResult handleModelList(const CommandContext& ctx);
CommandResult handleModelConfigure(const CommandContext& ctx);
CommandResult handleModelValidate(const CommandContext& ctx);

// =============================================================================
// Inference Additional Handlers (Batch 3)
// =============================================================================
CommandResult handleInferenceConfigure(const CommandContext& ctx);
CommandResult handleInferencePause(const CommandContext& ctx);
CommandResult handleInferenceResume(const CommandContext& ctx);

// =============================================================================
// Agentic Additional Handlers (Batch 3)
// =============================================================================
CommandResult handleAgenticConfigure(const CommandContext& ctx);
CommandResult handleAgenticPause(const CommandContext& ctx);
CommandResult handleAgenticResume(const CommandContext& ctx);

// =============================================================================
// Security Additional Handlers (Batch 3)
// =============================================================================
CommandResult handleSecurityConfigure(const CommandContext& ctx);
CommandResult handleSecurityEnable(const CommandContext& ctx);
CommandResult handleSecurityDisable(const CommandContext& ctx);

// =============================================================================
// Telemetry Additional Handlers (Batch 3)
// =============================================================================
CommandResult handleTelemetryConfigure(const CommandContext& ctx);
CommandResult handleTelemetryClear(const CommandContext& ctx);

// =============================================================================
// Debug Additional Handlers (Batch 4)
// =============================================================================
CommandResult handleDebugStepOver(const CommandContext& ctx);
CommandResult handleDebugStepInto(const CommandContext& ctx);
CommandResult handleDebugStepOut(const CommandContext& ctx);
CommandResult handleDebugContinue(const CommandContext& ctx);
CommandResult handleDebugStop(const CommandContext& ctx);

// =============================================================================
// Build Additional Handlers (Batch 4)
// =============================================================================
CommandResult handleBuildConfigure(const CommandContext& ctx);
CommandResult handleBuildCompile(const CommandContext& ctx);
CommandResult handleBuildLink(const CommandContext& ctx);
CommandResult handleBuildPackage(const CommandContext& ctx);
CommandResult handleBuildDeploy(const CommandContext& ctx);

// =============================================================================
// Test Additional Handlers (Batch 4)
// =============================================================================
CommandResult handleTestConfigure(const CommandContext& ctx);
CommandResult handleTestList(const CommandContext& ctx);
CommandResult handleTestDebug(const CommandContext& ctx);
CommandResult handleTestProfile(const CommandContext& ctx);

// =============================================================================
// System Additional Handlers (Batch 4)
// =============================================================================
CommandResult handleSystemConfigure(const CommandContext& ctx);
CommandResult handleSystemShutdown(const CommandContext& ctx);
CommandResult handleSystemUpdate(const CommandContext& ctx);
CommandResult handleSystemBackup(const CommandContext& ctx);
CommandResult handleSystemRestore(const CommandContext& ctx);

// =============================================================================
// Multi-Response Extended Handlers (Batch 5)
// =============================================================================
CommandResult handleMultiRespFilter(const CommandContext& ctx);
CommandResult handleMultiRespSort(const CommandContext& ctx);
CommandResult handleMultiRespSearch(const CommandContext& ctx);
CommandResult handleMultiRespDelete(const CommandContext& ctx);
CommandResult handleMultiRespArchive(const CommandContext& ctx);

// =============================================================================
// Governance Extended Handlers (Batch 5)
// =============================================================================
CommandResult handleGovList(const CommandContext& ctx);
CommandResult handleGovAdd(const CommandContext& ctx);
CommandResult handleGovRemove(const CommandContext& ctx);
CommandResult handleGovUpdate(const CommandContext& ctx);
CommandResult handleGovValidate(const CommandContext& ctx);

// =============================================================================
// Safety Extended Handlers (Batch 5)
// =============================================================================
CommandResult handleSafetyList(const CommandContext& ctx);
CommandResult handleSafetyAdd(const CommandContext& ctx);
CommandResult handleSafetyRemove(const CommandContext& ctx);
CommandResult handleSafetyUpdate(const CommandContext& ctx);
CommandResult handleSafetyAudit(const CommandContext& ctx);

// =============================================================================
// Replay Extended Handlers (Batch 5)
// =============================================================================
CommandResult handleReplayList(const CommandContext& ctx);
CommandResult handleReplayDelete(const CommandContext& ctx);
CommandResult handleReplayRename(const CommandContext& ctx);
CommandResult handleReplayExport(const CommandContext& ctx);
CommandResult handleReplayImport(const CommandContext& ctx);

} // namespace RawrXD
