// ============================================================================
// Win32IDE_CommandHandlers.cpp — CommandResult overloads for feature handlers
// ============================================================================
#include "Win32IDE.h"
#include "../core/shared_feature_dispatch.h"

void HandleTranscendenceCoordinator(void* idePtr);
void HandleVulkanRenderer(void* idePtr);
void HandleOSExplorerInterceptor(void* idePtr);
void HandleMCPHooks(void* idePtr);
void HandleIOCPFileWatcher(void* idePtr);
void HandleIDEDiagnosticAutoHealer(void* idePtr);
void HandleConsentPrompt(void* idePtr);
void HandleAutonomousAgent(void* idePtr);
void HandleChatMessageRenderer(void* idePtr);
void HandleToolActionStatus(void* idePtr);
void HandleChatPanel(void* idePtr);
void HandlePerfTelemetry(void* idePtr);
void HandleUpdateSignature(void* idePtr);
void HandlePluginSignature(void* idePtr);

static void emitStatus(const CommandContext& ctx, const char* message) {
	if (ctx.outputFn) ctx.outputLine(message);
}

CommandResult HandleTranscendenceCoordinator(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 TranscendenceCoordinator");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 TranscendenceCoordinator", nullptr};
}

CommandResult HandleVulkanRenderer(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 VulkanRenderer");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 VulkanRenderer", nullptr};
}

CommandResult HandleOSExplorerInterceptor(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 OSExplorerInterceptor");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 OSExplorerInterceptor", nullptr};
}

CommandResult HandleMCPHooks(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 MCPHooks");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 MCPHooks", nullptr};
}

CommandResult HandleIOCPFileWatcher(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IOCPFileWatcher");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IOCPFileWatcher", nullptr};
}

CommandResult HandleIDEDiagnosticAutoHealer(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IDEDiagnosticAutoHealer");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IDEDiagnosticAutoHealer", nullptr};
}

CommandResult HandleConsentPrompt(const CommandContext& ctx) {
	HandleConsentPrompt(ctx.idePtr);
	emitStatus(ctx, "Consent Prompt shown");
	return CommandResult::ok("Consent Prompt shown");
}

CommandResult HandleAutonomousAgent(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 AutonomousAgent");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 AutonomousAgent", nullptr};
}

CommandResult HandleChatMessageRenderer(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 ChatMessageRenderer");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 ChatMessageRenderer", nullptr};
}

CommandResult HandleToolActionStatus(const CommandContext& ctx) {
	HandleToolActionStatus(ctx.idePtr);
	emitStatus(ctx, "Tool Action Status invoked");
	return CommandResult::ok("Tool Action Status invoked");
}

CommandResult HandleChatPanel(const CommandContext& ctx) {
	HandleChatPanel(ctx.idePtr);
	emitStatus(ctx, "Chat Panel invoked");
	return CommandResult::ok("Chat Panel invoked");
}

CommandResult HandlePerfTelemetry(const CommandContext& ctx) {
	emitStatus(ctx, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 PerfTelemetry");
	return CommandResult{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 PerfTelemetry", nullptr};
}

CommandResult HandleUpdateSignature(const CommandContext& ctx) {
	HandleUpdateSignature(ctx.idePtr);
	emitStatus(ctx, "Update Signature executed");
	return CommandResult::ok("Update Signature executed");
}

CommandResult HandlePluginSignature(const CommandContext& ctx) {
	HandlePluginSignature(ctx.idePtr);
	emitStatus(ctx, "Plugin Signature executed");
	return CommandResult::ok("Plugin Signature executed");
}
