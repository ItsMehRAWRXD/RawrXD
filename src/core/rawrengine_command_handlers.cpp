#include "shared_feature_dispatch.h"

#include "../../include/cursor_github_parity_bridge.h"
#include "../../include/plugin_signature.h"
#include "../../include/ui/chat_panel.h"
#include "../../include/update_signature.h"
#if RAWR_HAS_VULKAN
#include "../../include/vulkan_compute.h"
#endif
#include "../agentic/ErrorRecoveryManager.h"
#include "../core/ConfigurationValidator.h"
#include "../inference/PerformanceMonitor.h"
#include "../security/InputSanitizer.h"
#include "../ui/chat_message_renderer.h"
#include "../ui/tool_action_status.h"
#include "hardware_synthesizer.hpp"
#include "jsonrpc_parser.hpp"
#include "mesh_brain.hpp"
#include "neural_bridge.hpp"
#include "omega_orchestrator.hpp"
#include "perf_telemetry.hpp"
#include "self_host_engine.hpp"
#include "speciator_engine.hpp"
#include "transcendence_coordinator.hpp"

#include <atomic>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace {

void emit(const CommandContext& ctx, const std::string& line) {
    if (ctx.outputFn) {
        ctx.outputLine(line);
    }
}

CommandResult okResult(const CommandContext& ctx, const std::string& message) {
    static thread_local std::string detail;
    detail = message;
    emit(ctx, detail);
    return CommandResult::ok(detail.c_str());
}

CommandResult errorResult(const CommandContext& ctx, const std::string& message, int code = -1) {
    static thread_local std::string detail;
    detail = message;
    emit(ctx, detail);
    return CommandResult::error(detail.c_str(), code);
}

std::wstring currentModulePath() {
    wchar_t path[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::wstring(path, path + len);
}

} // namespace

CommandResult HandleCursorParityBridge(const CommandContext& ctx) {
    // Headless parity verification checks command space invariants.
    const int span = RawrXD::Parity::CURSOR_PARITY_LAST_ID - RawrXD::Parity::CURSOR_PARITY_FIRST_ID + 1;
    if (span <= 0 || RawrXD::Parity::CURSOR_PARITY_MODULE_COUNT <= 0) {
        return errorResult(ctx, "Cursor parity constants are invalid");
    }
    return okResult(ctx, "Cursor parity bridge verified (command span=" + std::to_string(span) + ")");
}

CommandResult HandleOmegaOrchestrator(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 OmegaOrchestrator",
        /*code=*/1);
}

CommandResult HandleMeshBrain(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 MeshBrain",
        /*code=*/1);
}

CommandResult HandleSpeciatorEngine(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 SpeciatorEngine",
        /*code=*/1);
}

CommandResult HandleNeuralBridge(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 NeuralBridge",
        /*code=*/1);
}

CommandResult HandleSelfHostEngine(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 SelfHostEngine",
        /*code=*/1);
}

CommandResult HandleHardwareSynthesizer(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 HardwareSynthesizer",
        /*code=*/1);
}

CommandResult HandleTranscendenceCoordinator(const CommandContext& ctx) {
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 TranscendenceCoordinator; "
        "product path=Deep2 generateStream",
        /*code=*/1);
}

CommandResult HandleVulkanRenderer(const CommandContext& ctx) {
    // Was: Initialize/Cleanup theater or "CPU fallback" ok — not product Vulkan path.
    // Cite: COMMAND_HANDLERS_FICTION_GATE_001 / WIN32IDE_STUB_GATE_003
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 VulkanRenderer",
        /*code=*/1);
}

CommandResult HandleOSExplorerInterceptor(const CommandContext& ctx) {
    // Was: FindFirstFileW enum labeled "interceptor succeeded" — probe ≠ product owner.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 OSExplorerInterceptor",
        /*code=*/1);
}

CommandResult HandleMCPHooks(const CommandContext& ctx) {
    // Was: local JSON-RPC parse/encode labeled "MCP hook validated" — no live MCP.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 MCPHooks",
        /*code=*/1);
}

CommandResult HandleIOCPFileWatcher(const CommandContext& ctx) {
    // Was: create/associate/close IOCP labeled "initialized" — no persistent watcher.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IOCPFileWatcher",
        /*code=*/1);
}

CommandResult HandleIDEDiagnosticAutoHealer(const CommandContext& ctx) {
    // Was: addRule+validateSection smoke labeled "auto-heal passed" — no healer runtime.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 IDEDiagnosticAutoHealer",
        /*code=*/1);
}

CommandResult HandleConsentPrompt(const CommandContext& ctx) {
    // Headless "available" was fake ok. GUI MessageBox is a real receipt.
    if (!ctx.isGui || ctx.hwnd == nullptr) {
        return errorResult(ctx,
            "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 ConsentPrompt "
            "headless; no GUI consent receipt",
            /*code=*/1);
    }
    const int answer = MessageBoxA(static_cast<HWND>(ctx.hwnd),
                                   "Allow diagnostic and telemetry features?",
                                   "Consent Prompt",
                                   MB_YESNO | MB_ICONQUESTION);
    const bool accepted = (answer == IDYES);
    return accepted
        ? okResult(ctx, "Consent prompt accepted")
        : errorResult(ctx, "Consent prompt declined", ERROR_CANCELLED);
}

CommandResult HandleAutonomousAgent(const CommandContext& ctx) {
    // Was: sanitizePrompt + recordSuccess labeled "cycle executed" — no agent run.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 AutonomousAgent",
        /*code=*/1);
}

CommandResult HandleChatMessageRenderer(const CommandContext& ctx) {
    // Was: in-process smoke render labeled product PASS — not chat product path.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 ChatMessageRenderer",
        /*code=*/1);
}

CommandResult HandleToolActionStatus(const CommandContext& ctx) {
    // Fail-closed DEMO: no synthetic RunTerminal/FinishedAction without real exit.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 SYNTHETIC=1 ToolActionStatus "
        "DEMO gated; FinishedAction forbidden without real process exit",
        /*code=*/1);
}

CommandResult HandleChatPanel(const CommandContext& ctx) {
    // Headless "available" was fake ok. Create+append only when GUI parent exists.
    if (!ctx.isGui || ctx.hwnd == nullptr) {
        return errorResult(ctx,
            "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 ChatPanel "
            "headless; no GUI parent",
            /*code=*/1);
    }
    RawrXD::UI::ChatPanel panel;
    if (!panel.create(static_cast<HWND>(ctx.hwnd), 9100)) {
        return errorResult(ctx, "Chat panel creation failed");
    }
    panel.appendMessage("assistant", "Chat panel initialized");
    return okResult(ctx, "Chat panel initialized");
}

CommandResult HandlePerfTelemetry(const CommandContext& ctx) {
    // Was: initialize+captureBaseline labeled product PASS — not tip telemetry owner.
    return errorResult(ctx,
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 PerfTelemetry",
        /*code=*/1);
}

CommandResult HandleUpdateSignature(const CommandContext& ctx) {
    auto& verifier = RawrXD::Update::UpdateSignatureVerifier::instance();
    const std::wstring modulePath = currentModulePath();
    const auto result = verifier.verifyAuthenticode(modulePath.c_str());
    if (!result.valid) {
        return errorResult(ctx, result.detail, result.errorCode);
    }
    return okResult(ctx, "Update signature verification succeeded");
}

CommandResult HandlePluginSignature(const CommandContext& ctx) {
    auto& verifier = RawrXD::Plugin::PluginSignatureVerifier::instance();
    if (!verifier.isInitialized()) {
        const auto policy = RawrXD::Plugin::PluginSignatureVerifier::createStandardPolicy();
        if (!verifier.initialize(policy)) {
            return errorResult(ctx, "Plugin signature verifier initialization failed");
        }
    }
    const std::wstring modulePath = currentModulePath();
    const auto result = verifier.verify(modulePath.c_str());
    if (!result.valid) {
        return errorResult(ctx, result.detail, result.errorCode);
    }
    return okResult(ctx, "Plugin signature verification succeeded");
}
