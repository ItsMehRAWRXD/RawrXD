// ============================================================================
// diagnostic_consumer.h — Stub diagnostic consumer for LSP integration
// No real usage found in auto_feature_registry.cpp; declared to satisfy includes.
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace LSP {

struct Diagnostic {
    std::string filePath;
    int         line = 0;
    int         column = 0;
    std::string severity;   // "error", "warning", "info", "hint"
    std::string message;
};

class DiagnosticConsumer {
public:
    static DiagnosticConsumer& instance();

    void consume(const std::vector<Diagnostic>& diagnostics);
    std::vector<Diagnostic> getAll() const;
    void clear();

private:
    DiagnosticConsumer() = default;
    std::vector<Diagnostic> diagnostics_;
};

} // namespace LSP
} // namespace RawrXD
