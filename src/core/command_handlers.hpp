// =============================================================================
// CommandHandlers.hpp - Unified command handler declarations
// =============================================================================

#pragma once

// Use the same CommandContext and CommandResult types as command_registry.hpp
#include "shared_feature_dispatch.h"

// Auto-generated handler declarations (global namespace for command_registry.hpp compatibility)

// =============================================================================
// Missing Tier1 Handler Declarations
// =============================================================================
CommandResult handleTier1SettingsGUI(const CommandContext& ctx);
CommandResult handleTier1WelcomePage(const CommandContext& ctx);
CommandResult handleTier1FileIconTheme(const CommandContext& ctx);
CommandResult handleTier1TabDragToggle(const CommandContext& ctx);
CommandResult handleTier1SplitVertical(const CommandContext& ctx);
CommandResult handleTier1SplitHorizontal(const CommandContext& ctx);
CommandResult handleTier1SplitGrid(const CommandContext& ctx);
CommandResult handleTier1SplitClose(const CommandContext& ctx);
CommandResult handleTier1SplitFocusNext(const CommandContext& ctx);
CommandResult handleTier1AutoUpdateCheck(const CommandContext& ctx);
CommandResult handleTier1UpdateDismiss(const CommandContext& ctx);


// =============================================================================
// Auto-generated Missing Handler Declarations (Batch 1)
// =============================================================================

CommandResult handleAICtx128K(const CommandContext& ctx);
CommandResult handleAICtx1M(const CommandContext& ctx);
CommandResult handleAICtx256K(const CommandContext& ctx);
CommandResult handleAICtx32K(const CommandContext& ctx);
CommandResult handleAICtx4K(const CommandContext& ctx);
CommandResult handleAICtx512K(const CommandContext& ctx);
CommandResult handleAICtx64K(const CommandContext& ctx);
CommandResult handleAINoRefusal(const CommandContext& ctx);
CommandResult handleAsmCallGraph(const CommandContext& ctx);
CommandResult handleAsmDataFlow(const CommandContext& ctx);
CommandResult handleAsmFindRefs(const CommandContext& ctx);
CommandResult handleAsmGoto(const CommandContext& ctx);
CommandResult handleAsmParse(const CommandContext& ctx);
CommandResult handleAsmSections(const CommandContext& ctx);
CommandResult handleAsmSymbolTable(const CommandContext& ctx);
CommandResult handleAuditDashboard(const CommandContext& ctx);
CommandResult handleBackendConfigure(const CommandContext& ctx);
CommandResult handleBackendHealthCheck(const CommandContext& ctx);
CommandResult handleBackendSaveConfigs(const CommandContext& ctx);
CommandResult handleBackendSetApiKey(const CommandContext& ctx);
CommandResult handleBackendShowStatus(const CommandContext& ctx);
CommandResult handleBackendShowSwitcher(const CommandContext& ctx);
CommandResult handleBackendSwitchClaude(const CommandContext& ctx);
CommandResult handleBackendSwitchGemini(const CommandContext& ctx);
CommandResult handleBackendSwitchLocal(const CommandContext& ctx);
CommandResult handleBackendSwitchOllama(const CommandContext& ctx);
CommandResult handleBackendSwitchOpenAI(const CommandContext& ctx);
CommandResult handleBeaconFullBeacon(const CommandContext& ctx);
CommandResult handleBeaconHalfPulse(const CommandContext& ctx);
CommandResult handleBeaconStatus(const CommandContext& ctx);


CommandResult handleDbgAddBp(const CommandContext& ctx);
CommandResult handleDbgAddWatch(const CommandContext& ctx);
CommandResult handleDbgAttach(const CommandContext& ctx);
CommandResult handleDbgBreak(const CommandContext& ctx);
CommandResult handleDbgClearBps(const CommandContext& ctx);
CommandResult handleDbgDetach(const CommandContext& ctx);
CommandResult handleDbgDisasm(const CommandContext& ctx);
CommandResult handleDbgEnableBp(const CommandContext& ctx);
CommandResult handleDbgEvaluate(const CommandContext& ctx);
CommandResult handleDbgGo(const CommandContext& ctx);
CommandResult handleDbgKill(const CommandContext& ctx);
CommandResult handleDbgLaunch(const CommandContext& ctx);
CommandResult handleDbgListBps(const CommandContext& ctx);
CommandResult handleDbgMemory(const CommandContext& ctx);
CommandResult handleDbgModules(const CommandContext& ctx);
CommandResult handleDbgRegisters(const CommandContext& ctx);
CommandResult handleDbgRemoveBp(const CommandContext& ctx);
CommandResult handleDbgRemoveWatch(const CommandContext& ctx);
CommandResult handleDbgSearchMemory(const CommandContext& ctx);
CommandResult handleDbgSetRegister(const CommandContext& ctx);
CommandResult handleDbgStack(const CommandContext& ctx);
CommandResult handleDbgStatus(const CommandContext& ctx);
CommandResult handleDbgStepInto(const CommandContext& ctx);
CommandResult handleDbgStepOut(const CommandContext& ctx);
CommandResult handleDbgStepOver(const CommandContext& ctx);
CommandResult handleDbgSwitchThread(const CommandContext& ctx);
CommandResult handleDbgSymbolPath(const CommandContext& ctx);
CommandResult handleDbgThreads(const CommandContext& ctx);
CommandResult handleDiskListDrives(const CommandContext& ctx);
CommandResult handleDiskScanPartitions(const CommandContext& ctx);
CommandResult handleEditClipboardHist(const CommandContext& ctx);
CommandResult handleEditorCycle(const CommandContext& ctx);
CommandResult handleEditorMonacoCore(const CommandContext& ctx);
CommandResult handleEditorRichEdit(const CommandContext& ctx);
CommandResult handleEditorStatus(const CommandContext& ctx);
CommandResult handleEditorWebView2(const CommandContext& ctx);
CommandResult handleEmbeddingEncode(const CommandContext& ctx);
CommandResult handleFileAutoSave(const CommandContext& ctx);
CommandResult handleGovernorSetPowerLevel(const CommandContext& ctx);
CommandResult handleGovernorStatus(const CommandContext& ctx);
CommandResult handleHelpCmdRef(const CommandContext& ctx);
CommandResult handleHelpPsDocs(const CommandContext& ctx);
CommandResult handleHotpatchEventLog(const CommandContext& ctx);
CommandResult handleHotpatchMemRevert(const CommandContext& ctx);
CommandResult handleHotpatchProxyStats(const CommandContext& ctx);
CommandResult handleLspClearDiag(const CommandContext& ctx);
CommandResult handleLspDiagnostics(const CommandContext& ctx);
CommandResult handleLspFindRefs(const CommandContext& ctx);
CommandResult handleLspGotoDef(const CommandContext& ctx);
CommandResult handleLspHover(const CommandContext& ctx);
CommandResult handleLspRename(const CommandContext& ctx);
CommandResult handleLspRestart(const CommandContext& ctx);
CommandResult handleLspSrvConfig(const CommandContext& ctx);
CommandResult handleLspSrvExportSymbols(const CommandContext& ctx);
CommandResult handleLspSrvLaunchStdio(const CommandContext& ctx);
CommandResult handleLspSrvPublishDiag(const CommandContext& ctx);
CommandResult handleLspSrvReindex(const CommandContext& ctx);
CommandResult handleLspSrvStart(const CommandContext& ctx);
CommandResult handleLspSrvStats(const CommandContext& ctx);
CommandResult handleLspSrvStatus(const CommandContext& ctx);
CommandResult handleLspSrvStop(const CommandContext& ctx);
CommandResult handleLspStatus(const CommandContext& ctx);
CommandResult handleLspSymbolInfo(const CommandContext& ctx);
CommandResult handleMarketplaceInstall(const CommandContext& ctx);
CommandResult handleMarketplaceList(const CommandContext& ctx);
CommandResult handleModelFinetune(const CommandContext& ctx);
CommandResult handleModelList(const CommandContext& ctx);
CommandResult handleModelLoad(const CommandContext& ctx);


// =============================================================================
// Auto-generated Missing Handler Declarations (Batch 2)
// =============================================================================

CommandResult handleModelQuantize(const CommandContext& ctx);
CommandResult handleModelUnload(const CommandContext& ctx);
CommandResult handleMonacoDevtools(const CommandContext& ctx);
CommandResult handleMonacoReload(const CommandContext& ctx);
CommandResult handleMonacoSyncTheme(const CommandContext& ctx);
CommandResult handleMonacoToggle(const CommandContext& ctx);
CommandResult handleMonacoZoomIn(const CommandContext& ctx);
CommandResult handleMonacoZoomOut(const CommandContext& ctx);
CommandResult handleMultiRespSetMax(const CommandContext& ctx);
CommandResult handlePluginConfigure(const CommandContext& ctx);
CommandResult handlePluginLoad(const CommandContext& ctx);
CommandResult handlePluginRefresh(const CommandContext& ctx);
CommandResult handlePluginScanDir(const CommandContext& ctx);
CommandResult handlePluginShowPanel(const CommandContext& ctx);
CommandResult handlePluginShowStatus(const CommandContext& ctx);
CommandResult handlePluginToggleHotload(const CommandContext& ctx);
CommandResult handlePluginUnload(const CommandContext& ctx);
CommandResult handlePluginUnloadAll(const CommandContext& ctx);
CommandResult handlePromptClassifyContext(const CommandContext& ctx);
CommandResult handleQwAlertDismiss(const CommandContext& ctx);
CommandResult handleQwAlertHistory(const CommandContext& ctx);
CommandResult handleQwAlertMonitor(const CommandContext& ctx);
CommandResult handleRECompare(const CommandContext& ctx);
CommandResult handleRECompile(const CommandContext& ctx);
CommandResult handleREDataFlow(const CommandContext& ctx);
CommandResult handleREDecompClose(const CommandContext& ctx);
CommandResult handleREDecompilerView(const CommandContext& ctx);
CommandResult handleREDecompRename(const CommandContext& ctx);
CommandResult handleREDecompSync(const CommandContext& ctx);
CommandResult handleREDemangle(const CommandContext& ctx);
CommandResult handleREDetectVulns(const CommandContext& ctx);
CommandResult handleREExportGhidra(const CommandContext& ctx);
CommandResult handleREExportIDA(const CommandContext& ctx);
CommandResult handleREFunctions(const CommandContext& ctx);
CommandResult handleRELicenseInfo(const CommandContext& ctx);


CommandResult handleReplayShowLast(const CommandContext& ctx);

CommandResult handleRERecursiveDisasm(const CommandContext& ctx);
CommandResult handleRETypeRecovery(const CommandContext& ctx);
CommandResult handleRevengDecompile(const CommandContext& ctx);
CommandResult handleRevengDisassemble(const CommandContext& ctx);
CommandResult handleRevengFindVulnerabilities(const CommandContext& ctx);
CommandResult handleRouterCapabilities(const CommandContext& ctx);
CommandResult handleRouterDecision(const CommandContext& ctx);





CommandResult handleRouterFallbacks(const CommandContext& ctx);









CommandResult handleRouterSimulateLast(const CommandContext& ctx);
CommandResult handleRouterStatus(const CommandContext& ctx);


CommandResult handleSafetyRollbackLast(const CommandContext& ctx);
CommandResult handleSwarmBlacklist(const CommandContext& ctx);
CommandResult handleSwarmConfig(const CommandContext& ctx);
CommandResult handleSwarmDiscovery(const CommandContext& ctx);
CommandResult handleSwarmEvents(const CommandContext& ctx);
CommandResult handleSwarmFitness(const CommandContext& ctx);
CommandResult handleSwarmStats(const CommandContext& ctx);
CommandResult handleSwarmTaskGraph(const CommandContext& ctx);
CommandResult handleTelemetryDashboard(const CommandContext& ctx);
CommandResult handleThemeCatppuccin(const CommandContext& ctx);
CommandResult handleThemeCrimson(const CommandContext& ctx);
CommandResult handleThemeCyberpunk(const CommandContext& ctx);
CommandResult handleThemeGruvbox(const CommandContext& ctx);
CommandResult handleThemeOneDark(const CommandContext& ctx);
CommandResult handleThemeSolDark(const CommandContext& ctx);
CommandResult handleThemeSolLight(const CommandContext& ctx);
CommandResult handleThemeSynthwave(const CommandContext& ctx);
CommandResult handleThemeTokyo(const CommandContext& ctx);
CommandResult handleTier1BreadcrumbsToggle(const CommandContext& ctx);
CommandResult handleTier1FuzzyPalette(const CommandContext& ctx);
CommandResult handleTier1MinimapEnhanced(const CommandContext& ctx);
CommandResult handleTier1SmoothScrollToggle(const CommandContext& ctx);
CommandResult handleTrans100(const CommandContext& ctx);
CommandResult handleTrans40(const CommandContext& ctx);
CommandResult handleTrans50(const CommandContext& ctx);
CommandResult handleTrans60(const CommandContext& ctx);
CommandResult handleTrans70(const CommandContext& ctx);
CommandResult handleTrans80(const CommandContext& ctx);
CommandResult handleTrans90(const CommandContext& ctx);
CommandResult handleTransCustom(const CommandContext& ctx);
CommandResult handleTransToggle(const CommandContext& ctx);
CommandResult handleUnityAttach(const CommandContext& ctx);
CommandResult handleUnityInit(const CommandContext& ctx);
CommandResult handleUnrealAttach(const CommandContext& ctx);
CommandResult handleUnrealInit(const CommandContext& ctx);
CommandResult handleViewStreamingLoader(const CommandContext& ctx);
CommandResult handleViewVulkanRenderer(const CommandContext& ctx);
CommandResult handleVisionAnalyzeImage(const CommandContext& ctx);
CommandResult handleVoicePTT(const CommandContext& ctx);


// =============================================================================
// Final Missing Handler Declarations
// =============================================================================
CommandResult handleViewStreamingLoader(const CommandContext& ctx);
CommandResult handleViewVulkanRenderer(const CommandContext& ctx);
CommandResult handleVoicePTT(const CommandContext& ctx);
CommandResult handleVisionAnalyzeImage(const CommandContext& ctx);


// =============================================================================
// Auto-generated Missing Handler Declarations (Remaining)
// =============================================================================

CommandResult handleAsmAnalyzeBlock(const CommandContext& ctx);
CommandResult handleAsmClearSymbols(const CommandContext& ctx);
CommandResult handleAsmDetectConvention(const CommandContext& ctx);
CommandResult handleAsmInstructionInfo(const CommandContext& ctx);
CommandResult handleAsmRegisterInfo(const CommandContext& ctx);
CommandResult handleConfidenceSetPolicy(const CommandContext& ctx);
CommandResult handleConfidenceStatus(const CommandContext& ctx);
CommandResult handleGovKillAll(const CommandContext& ctx);
CommandResult handleGovStatus(const CommandContext& ctx);
CommandResult handleGovSubmitCommand(const CommandContext& ctx);
CommandResult handleGovTaskList(const CommandContext& ctx);
CommandResult handleHybridAnalyzeFile(const CommandContext& ctx);
CommandResult handleHybridAnnotateDiag(const CommandContext& ctx);
CommandResult handleHybridAutoProfile(const CommandContext& ctx);
CommandResult handleHybridComplete(const CommandContext& ctx);
CommandResult handleHybridCorrectionLoop(const CommandContext& ctx);
CommandResult handleHybridDiagnostics(const CommandContext& ctx);
CommandResult handleHybridExplainSymbol(const CommandContext& ctx);
CommandResult handleHybridSemanticPrefetch(const CommandContext& ctx);
CommandResult handleHybridSmartRename(const CommandContext& ctx);
CommandResult handleHybridStatus(const CommandContext& ctx);
CommandResult handleHybridStreamAnalyze(const CommandContext& ctx);
CommandResult handleHybridSymbolUsage(const CommandContext& ctx);
CommandResult handleLspConfigure(const CommandContext& ctx);
CommandResult handleLspSaveConfig(const CommandContext& ctx);
CommandResult handleLspStartAll(const CommandContext& ctx);
CommandResult handleLspStopAll(const CommandContext& ctx);
CommandResult handleMultiRespApplyPreferred(const CommandContext& ctx);
CommandResult handleMultiRespClearHistory(const CommandContext& ctx);
CommandResult handleMultiRespCompare(const CommandContext& ctx);
CommandResult handleMultiRespGenerate(const CommandContext& ctx);
CommandResult handleMultiRespSelectPreferred(const CommandContext& ctx);
CommandResult handleMultiRespShowLatest(const CommandContext& ctx);
CommandResult handleMultiRespShowPrefs(const CommandContext& ctx);
CommandResult handleMultiRespShowStats(const CommandContext& ctx);
CommandResult handleMultiRespShowStatus(const CommandContext& ctx);
CommandResult handleMultiRespShowTemplates(const CommandContext& ctx);
CommandResult handleMultiRespToggleTemplate(const CommandContext& ctx);
CommandResult handleReplayCheckpoint(const CommandContext& ctx);
CommandResult handleReplayExportSession(const CommandContext& ctx);
CommandResult handleReplayStatus(const CommandContext& ctx);
CommandResult handleRERecursiveDisasm(const CommandContext& ctx);
CommandResult handleRouterDisable(const CommandContext& ctx);
CommandResult handleRouterEnable(const CommandContext& ctx);
CommandResult handleRouterEnsembleDisable(const CommandContext& ctx);
CommandResult handleRouterEnsembleEnable(const CommandContext& ctx);
CommandResult handleRouterEnsembleStatus(const CommandContext& ctx);
CommandResult handleRouterFallbacks(const CommandContext& ctx);
CommandResult handleRouterPinTask(const CommandContext& ctx);
CommandResult handleRouterResetStats(const CommandContext& ctx);
CommandResult handleRouterRoutePrompt(const CommandContext& ctx);
CommandResult handleRouterSaveConfig(const CommandContext& ctx);
CommandResult handleRouterSetPolicy(const CommandContext& ctx);
CommandResult handleRouterShowCostStats(const CommandContext& ctx);
CommandResult handleRouterShowHeatmap(const CommandContext& ctx);
CommandResult handleRouterShowPins(const CommandContext& ctx);
CommandResult handleRouterSimulate(const CommandContext& ctx);
CommandResult handleRouterSimulateLast(const CommandContext& ctx);
CommandResult handleRouterUnpinTask(const CommandContext& ctx);
CommandResult handleRouterWhyBackend(const CommandContext& ctx);
CommandResult handleSafetyResetBudget(const CommandContext& ctx);
CommandResult handleSafetyShowViolations(const CommandContext& ctx);
CommandResult handleSafetyStatus(const CommandContext& ctx);

