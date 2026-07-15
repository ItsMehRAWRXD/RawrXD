// ============================================================================
// Diagnostic
// ============================================================================
// Structured diagnostics for RawrXD execution
// ============================================================================

#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Diagnostic Severity
// ============================================================================

enum class DiagnosticSeverity {
    Info = 0,
    Warning = 1,
    Error = 2
};

// ============================================================================
// Diagnostic Structure
// ============================================================================
// Individual diagnostic message with structured metadata
// ============================================================================

struct Diagnostic {
    DiagnosticSeverity severity;
    std::string code;        // Machine-readable code (e.g., "W001", "E042")
    std::string message;     // Human-readable description
    std::string source;      // Component that emitted (e.g., "tokenizer", "vulkan")
    
    Diagnostic(DiagnosticSeverity sev, const std::string& c, 
                 const std::string& msg, const std::string& src = "")
        : severity(sev), code(c), message(msg), source(src) {}
};

// ============================================================================
// Diagnostic Collection
// ============================================================================

class DiagnosticCollection {
public:
    void Add(DiagnosticSeverity severity, const std::string& code,
             const std::string& message, const std::string& source = "") {
        diagnostics_.emplace_back(severity, code, message, source);
    }
    
    void AddInfo(const std::string& code, const std::string& message, 
                 const std::string& source = "") {
        Add(DiagnosticSeverity::Info, code, message, source);
    }
    
    void AddWarning(const std::string& code, const std::string& message,
                    const std::string& source = "") {
        Add(DiagnosticSeverity::Warning, code, message, source);
    }
    
    void AddError(const std::string& code, const std::string& message,
                  const std::string& source = "") {
        Add(DiagnosticSeverity::Error, code, message, source);
    }
    
    const std::vector<Diagnostic>& GetAll() const { return diagnostics_; }
    bool HasErrors() const;
    bool HasWarnings() const;
    void Clear() { diagnostics_.clear(); }
    
private:
    std::vector<Diagnostic> diagnostics_;
};

inline bool DiagnosticCollection::HasErrors() const {
    for (const auto& d : diagnostics_) {
        if (d.severity == DiagnosticSeverity::Error) return true;
    }
    return false;
}

inline bool DiagnosticCollection::HasWarnings() const {
    for (const auto& d : diagnostics_) {
        if (d.severity == DiagnosticSeverity::Warning) return true;
    }
    return false;
}

} // namespace Execution
} // namespace RawrXD
