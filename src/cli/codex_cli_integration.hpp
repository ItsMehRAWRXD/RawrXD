#pragma once
// ============================================================================
// CODEX Reverse Engineering CLI Integration
// ============================================================================
// Exposes all CODEX Pro v7.0 capabilities through unified CLI
// Commands: /codex, /disasm, /decompile, /pe, /cfg, /rtti, /imports, /exports
// ============================================================================

#include "unified_execution_abi.hpp"
#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace CLI {
namespace CODEX {

// ============================================================================
// CODEX Command Result Extensions
// ============================================================================

struct CODEXResult {
    CLIExecutionResult base;
    
    // PE Analysis
    struct PEInfo {
        std::string architecture;
        std::string subsystem;
        uint64_t image_base;
        uint64_t entry_point;
        uint32_t section_count;
        bool is_dotnet;
        bool is_packed;
    } pe_info;
    
    // Disassembly
    struct DisasmResult {
        uint64_t instruction_count;
        uint64_t basic_block_count;
        std::vector<std::string> functions;
        std::string entry_point_disasm;
    } disasm;
    
    // Decompilation
    struct DecompileResult {
        std::string generated_cpp;
        std::string generated_h;
        std::string cmakelists;
        int recovered_functions;
        int recovered_types;
    } decompile;
    
    // RTTI
    struct RTTIResult {
        int type_count;
        std::vector<std::string> class_hierarchy;
        std::string vtable_layout;
    } rtti;
    
    // CFG
    struct CFGResult {
        int node_count;
        int edge_count;
        std::string graphviz_dot;
        std::vector<std::string> strongly_connected_components;
    } cfg;
    
    // Export to JSON
    nlohmann::json ToJSON() const;
};

// ============================================================================
// CODEX CLI Commands
// ============================================================================

class CODEXCommands {
public:
    // Main CODEX command dispatcher
    static CLIExecutionResult CODEXMain(const ExecutionContext& ctx);
    
    // PE Analysis
    static CLIExecutionResult PEAnalyze(const ExecutionContext& ctx);
    static CLIExecutionResult PEHeaders(const ExecutionContext& ctx);
    static CLIExecutionResult PESections(const ExecutionContext& ctx);
    static CLIExecutionResult PEImports(const ExecutionContext& ctx);
    static CLIExecutionResult PEExports(const ExecutionContext& ctx);
    static CLIExecutionResult PEResources(const ExecutionContext& ctx);
    
    // Disassembly
    static CLIExecutionResult Disassemble(const ExecutionContext& ctx);
    static CLIExecutionResult DisassembleFunction(const ExecutionContext& ctx);
    static CLIExecutionResult DisassembleRange(const ExecutionContext& ctx);
    
    // Decompilation
    static CLIExecutionResult Decompile(const ExecutionContext& ctx);
    static CLIExecutionResult DecompileFunction(const ExecutionContext& ctx);
    static CLIExecutionResult GenerateProject(const ExecutionContext& ctx);
    
    // Control Flow Graph
    static CLIExecutionResult GenerateCFG(const ExecutionContext& ctx);
    static CLIExecutionResult AnalyzeCFG(const ExecutionContext& ctx);
    static CLIExecutionResult ExportCFG(const ExecutionContext& ctx);
    
    // RTTI / Type Recovery
    static CLIExecutionResult RecoverRTTI(const ExecutionContext& ctx);
    static CLIExecutionResult RecoverTypes(const ExecutionContext& ctx);
    static CLIExecutionResult ReconstructVTables(const ExecutionContext& ctx);
    
    // Binary Diff
    static CLIExecutionResult BinaryDiff(const ExecutionContext& ctx);
    static CLIExecutionResult PatchDiff(const ExecutionContext& ctx);
    
    // Signature / Pattern
    static CLIExecutionResult FindPattern(const ExecutionContext& ctx);
    static CLIExecutionResult CreateSignature(const ExecutionContext& ctx);
    static CLIExecutionResult YaraScan(const ExecutionContext& ctx);
    
    // String Analysis
    static CLIExecutionResult ExtractStrings(const ExecutionContext& ctx);
    static CLIExecutionResult AnalyzeStrings(const ExecutionContext& ctx);
    
    // Entropy / Packing
    static CLIExecutionResult EntropyAnalysis(const ExecutionContext& ctx);
    static CLIExecutionResult DetectPacker(const ExecutionContext& ctx);
    static CLIExecutionResult Unpack(const ExecutionContext& ctx);
    
    // Help
    static CLIExecutionResult Help(const ExecutionContext& ctx);
    static std::string GetHelpText();
};

// ============================================================================
// Registration
// ============================================================================

void RegisterCODEXCommands();

} // namespace CODEX
} // namespace CLI
} // namespace RawrXD
