#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace RawrXD::RE {

    struct BinaryAnalysisResult {
        bool success;
        std::string disassembly;
        std::string verificationLog;
        nlohmann::json metadata;
        std::string errorMessage;
    };

    class SovereignREBridge {
    public:
        static SovereignREBridge& Instance();

        // Performs disassembly on a specific range of a binary file.
        BinaryAnalysisResult DisassembleRange(const std::string& binaryPath, uint64_t rvaStart, size_t length);

        // Validates a block of x64 assembly by attempting to assemble it with ml64.
        bool ValidateMasmSyntax(const std::string& asmSource, std::string& compilerOutput);

        // Runs a heuristic scan on a memory block to identify potential logic flaws.
        nlohmann::json RunHeuristicScan(uintptr_t targetBase, size_t range);

        // Batch 4: Advanced Reverse Engineering & Decompilation Bridge
        // Provides higher-level decompilation of identified blocks into pseudocode.
        std::string DecompileBlock(uintptr_t baseAddress, size_t size);
        
        // Identifies function boundaries from a raw byte stream using pattern matching.
        std::vector<uintptr_t> DiscoverFunctions(const uint8_t* buffer, size_t size);

    private:
        SovereignREBridge() = default;
        std::string ExecutePipelineCommand(const std::string& command);
    };

} // namespace RawrXD::RE
