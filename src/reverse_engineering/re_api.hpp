// ============================================================================
// RawrXD Reverse Engineering API Header
// Provides stub declarations for RE classes used by auto_feature_registry.cpp
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace RawrXD {
namespace ReverseEngineering {

// ============================================================================
// NativeDisassembler
// ============================================================================

class NativeDisassembler {
public:
    struct Instruction {
        uint64_t address;
        std::vector<uint8_t> bytes;
        std::string mnemonic;
        std::string operands;
    };
    
    struct Function {
        uint64_t startAddress;
        uint64_t endAddress;
        std::string name;
        size_t instructionCount;
    };

    static std::vector<Instruction> DisassembleX64(
        const uint8_t* data, size_t size, uint64_t baseAddr = 0);

    static std::vector<Function> AnalyzeFunctions(
        const std::vector<Instruction>& instructions);

    static std::vector<std::string> ExtractStrings(
        const uint8_t* data, size_t size);

    static std::unordered_map<std::string, uint64_t> AnalyzeImports(
        const std::string& filePath);

    static std::unordered_map<std::string, uint64_t> AnalyzeExports(
        const std::string& filePath);
};

// ============================================================================
// BinaryAnalyzer
// ============================================================================

class BinaryAnalyzer {
public:
    struct BinaryInfo {
        std::string filePath;
        uint64_t entryPoint;
        uint64_t imageBase;
        bool is64Bit;
        std::vector<std::string> sections;
    };

    static BinaryInfo AnalyzePE(const std::string& filePath);

    static std::string GenerateReport(const BinaryInfo& info);

    static std::vector<uint8_t> ExtractSection(
        const std::string& filePath, const std::string& sectionName);
};

// ============================================================================
// RECodex
// ============================================================================

class RECodex {
public:
    struct Pattern {
        std::string name;
        std::vector<uint8_t> bytes;
        std::string description;
    };

    static std::vector<Pattern> GetMalwarePatterns();

    static std::vector<Pattern> GetCompilerPatterns();

    static std::vector<std::pair<uint64_t, std::string>> ScanForPatterns(
        const uint8_t* data, size_t size, const std::vector<Pattern>& patterns);

    static std::string AnalyzeWithAI(const std::string& query, const std::string& context);
};

// ============================================================================
// NativeCompiler
// ============================================================================

class NativeCompiler {
public:
    struct CompileOptions {
        bool optimize;
        bool debugInfo;
        std::string targetArch;
    };

    struct CompileResult {
        bool success;
        std::vector<uint8_t> code;
        std::string errorMessage;
    };

    static CompileResult CompileToNative(
        const std::string& source, CompileOptions options);
};

} // namespace ReverseEngineering
} // namespace RawrXD
