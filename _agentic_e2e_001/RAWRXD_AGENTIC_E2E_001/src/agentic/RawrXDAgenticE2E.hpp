#pragma once
// ============================================================================
// RawrXDAgenticE2E.hpp — RAWRXD_WIN32IDE_AGENTIC_001
//
// Source-only, no third-party dependencies.
// Real model -> Tool Authority -> read/edit/build/test -> tool result -> model.
// No synthetic success path. No stub fallback.
// ============================================================================

#include <cstdint>
#include <filesystem>
#include <string>

namespace Deep2 {
class Deep2Engine;
}

namespace RawrXD::Agentic {
class AgentToolRegistry;
}


namespace rawrxd::agentic_e2e {

struct AgenticE2EOptions {
    std::filesystem::path workspaceRoot;
    std::filesystem::path fixtureDir = ".rawr/agentic_gate";
    uint32_t maxSteps = 10;
    uint32_t maxTokensPerStep = 256;
    uint32_t processTimeoutMs = 120000;
    bool keepFixture = false;
};

// Install real mutable coding tools into the same AgentToolRegistry used by
// the IDE/agent runtime. Existing tools are left intact. No shell is used.
// Registered IDs: file.read (if absent), file.write, file.replace, process.run.
void registerRawrXDCodingTools(RawrXD::Agentic::AgentToolRegistry& authority);

// Catalog text suitable for appending to the production coding-agent system
// prompt so the model knows the exact protocol and arguments.
std::string rawrXDCodingToolCatalog();
std::string rawrXDCodingSystemPrompt();

struct AgenticE2EReceipt {
    bool ideLaunch = true;                // caller has already launched the IDE/gate
    bool commandDispatch = true;          // this function was entered by real command dispatch
    bool modelInference = false;          // at least one real generation completed
    bool toolAuthority = false;           // AgentToolRegistry handled real calls
    bool fileRead = false;                // real source file read by a tool
    bool fileEdit = false;                // real source mutation by a tool
    bool buildRan = false;                // compiler/build process really launched
    bool buildPassed = false;             // build process exited 0
    bool testRan = false;                 // produced executable really launched
    bool testPassed = false;              // child exit 0 + marker observed
    bool toolResultFedBack = false;       // a later generation consumed tool output
    bool reachedFinal = false;            // model produced a final answer after tools
    bool syntheticTokenOutput = false;    // always false; no synthetic token branch exists
    uint32_t stubFallbacks = 0;            // hard-coded zero; no fallback implementation exists
    uint32_t steps = 0;
    uint32_t toolCalls = 0;
    uint32_t successfulToolCalls = 0;
    uint32_t failedToolCalls = 0;
    uint64_t generatedTokens = 0;
    int childExitCode = -1;
    std::string firstTool;
    std::string finalText;
    std::string failStage;
    std::string failMessage;

    bool pass() const noexcept {
        return ideLaunch && commandDispatch && modelInference && toolAuthority &&
               fileRead && fileEdit && buildRan && buildPassed && testRan &&
               testPassed && toolResultFedBack && reachedFinal &&
               !syntheticTokenOutput && stubFallbacks == 0;
    }
};

// Preferred shipping-IDE entrypoint: pass the exact already-loaded engine from
// RAWRXD_WIN32IDE_INFERENCE_001. This function never loads or substitutes a model.
AgenticE2EReceipt runAgenticE2EGate(
    Deep2::Deep2Engine& engine,
    const AgenticE2EOptions& options);

// Receipt format intended to sit beside RAWRXD_WIN32IDE_TOOLCHAIN_001 and
// RAWRXD_WIN32IDE_INFERENCE_001 in the Win32 Native Compile Test output.
std::string formatAgenticE2EReceipt(const AgenticE2EReceipt& r);

} // namespace rawrxd::agentic_e2e
