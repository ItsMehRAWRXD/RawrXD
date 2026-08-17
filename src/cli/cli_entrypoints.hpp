//==============================================================================
// cli_entrypoints.hpp
// Unified CLI API boundaries for all RawrXD subsystems
// Phase 15B: Service Architecture - NO standalone mains
//
// Every former executable becomes a callable service behind this API.
// Standalone builds use RAWRXD_STANDALONE_* defines to preserve diagnostic
// binary capability.
//==============================================================================

#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace RawrXD::CLI {

//==============================================================================
// Inference Service
// Extracted from: rawrxd_infer.cpp, cli_headless_systems.cpp
//==============================================================================
int RunInferenceCLI(int argc, char** argv);
int RunBenchmarkCLI(int argc, char** argv);
int RunChatCLI(int argc, char** argv);
int RunServeCLI(int argc, char** argv);

//==============================================================================
// Compiler Service
// Extracted from: rawrxd_cli_compiler.cpp, CLI_CompilerCommands.cpp
//==============================================================================
int RunCompilerCLI(int argc, char** argv);
int RunBuildCLI(int argc, char** argv);
int RunAssembleCLI(int argc, char** argv);

//==============================================================================
// CODEX RE Service
// Extracted from: codex_cli_integration.cpp
//==============================================================================
int RunCodexCLI(int argc, char** argv);

// CODEX sub-commands
int CodexAnalyzePE(const std::filesystem::path& target);
int CodexDisassemble(const std::filesystem::path& target, 
                     const std::string& arch = "x64");
int CodexDecompile(const std::filesystem::path& target);
int CodexGenerateCFG(const std::filesystem::path& target);
int CodexExtractImports(const std::filesystem::path& target);
int CodexExtractExports(const std::filesystem::path& target);
int CodexExtractStrings(const std::filesystem::path& target);
int CodexCalculateEntropy(const std::filesystem::path& target);
int CodexPatternMatch(const std::filesystem::path& target,
                      const std::string& pattern);

//==============================================================================
// Unified Subsystem Router
// Extracted from: SovereignCLI_Unified.cpp, unified_cli.cpp
//==============================================================================
int RunUnifiedCLI(int argc, char** argv);
int RunSubsystemDispatch(const std::string& subsystem,
                         int argc, char** argv);

//==============================================================================
// Agent / Swarm Service
// Extracted from: cli_autonomy_loop.cpp, swarm_orchestrator.cpp
//==============================================================================
int RunAgentCLI(int argc, char** argv);
int RunSwarmCLI(int argc, char** argv);

//==============================================================================
// Slash Command Bridge (IDE → CLI)
// Extracted from: CLI_SlashRouter.cpp
//==============================================================================
int RunSlashRouter(const std::string& command,
                   const std::vector<std::string>& args);

//==============================================================================
// Status / Diagnostics
//==============================================================================
int RunStatusCLI();
int RunDiagnosticsCLI();

} // namespace RawrXD::CLI

//==============================================================================
// C API for MASM64 / external bridges
//==============================================================================
extern "C" {

__declspec(dllexport) int RawrXD_CLI_RunInference(int argc, char** argv);
__declspec(dllexport) int RawrXD_CLI_RunCodex(int argc, char** argv);
__declspec(dllexport) int RawrXD_CLI_RunCompiler(int argc, char** argv);
__declspec(dllexport) int RawrXD_CLI_RunUnified(int argc, char** argv);

} // extern "C"
