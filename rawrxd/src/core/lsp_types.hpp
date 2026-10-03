// RAWRXD_LSP_TYPES_001
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace LSPServer {

enum class SymbolKind : uint32_t {
    Function = 1,
    Variable = 2,
    Class = 3,
    Interface = 4,
    Enum = 5,
    Other = 99
};

struct IndexedSymbol {
    std::string name;
    SymbolKind kind = SymbolKind::Other;
    std::string detail;
    std::string containerName;
    std::string filePath;
    int line = 0;
    int startChar = 0;
    int endChar = 0;
    uint64_t hash = 0;
};

struct RawrXDLSPServer {
    static RawrXDLSPServer* instance() { return nullptr; }
};

} // namespace LSPServer

namespace RawrXD {
namespace LSP {

struct SourceRange {
    int startLine = 0, startCol = 0;
    int endLine = 0, endCol = 0;
};

enum class DiagnosticSeverity : uint8_t {
    ERROR = 1,
    WARNING = 2,
    INFORMATION = 3,
    HINT = 4
};

struct Diagnostic {
    std::string file;
    SourceRange range;
    DiagnosticSeverity severity = DiagnosticSeverity::ERROR;
    std::string message;
    std::string code;
    std::string source;
};

enum class DiagnosticSource : uint8_t {
    ASM_LINT = 1,
    GGUF_LINT = 2,
    GENERAL_LINT = 3
};

} // namespace LSP
} // namespace RawrXD

// --- DiagnosticConsumer placed in RawrXD::LSP namespace ---
namespace RawrXD {
namespace LSP {

struct DiagnosticConsumer {
    static DiagnosticConsumer* instance_;
    static DiagnosticConsumer& Global() {
        static DiagnosticConsumer inst;
        instance_ = &inst;
        return inst;
    }
    void publishDiagnostics(const std::string& fileKey,
                            const std::vector<Diagnostic>& diags) {
        (void)fileKey; (void)diags;
    }
};

inline DiagnosticConsumer* DiagnosticConsumer::instance_ = nullptr;

} // namespace LSP
} // namespace RawrXD
