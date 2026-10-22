// Diagnostics engine for the RawrXD native compiler.
//
// Produces source-anchored, IDE-consumable diagnostics. Every message
// carries the file/line/column it came from, plus the offending source line
// and a caret, so an editor can place a cursor exactly.

#ifndef RAWR_COMPILER_DIAGNOSTICS_H
#define RAWR_COMPILER_DIAGNOSTICS_H

#include "common/SourceManager.h"
#include "rawrstd/string.h"
#include "common/Types.h"
#include "rawrstd/vector.h"

namespace rawr {

enum class DiagnosticSeverity {
    Note,
    Warning,
    Error,
    Fatal,
};

struct Diagnostic {
    DiagnosticSeverity severity = DiagnosticSeverity::Error;
    String message;
    SourceLoc loc;
    String code;              // e.g. "C2100" style, optional
    String file_path;
    uint32 line = 0;
    uint32 column = 0;
    String source_line;
    String caret_line;
};

class DiagnosticEngine {
public:
    explicit DiagnosticEngine(SourceManager* sm) : sources_(sm) {}

    // Reports a diagnostic. Fatal errors abort the current compilation unit.
    void report(DiagnosticSeverity severity, const SourceLoc& loc, const char* code,
                const String& message);

    void error(const SourceLoc& loc, const char* code, const String& message) {
        report(DiagnosticSeverity::Error, loc, code, message);
    }
    void warning(const SourceLoc& loc, const char* code, const String& message) {
        report(DiagnosticSeverity::Warning, loc, code, message);
    }
    void note(const SourceLoc& loc, const char* code, const String& message) {
        report(DiagnosticSeverity::Note, loc, code, message);
    }

    // Emits a diagnostic without a source location (driver-level errors).
    void report_global(DiagnosticSeverity severity, const char* code, const String& message);

    bool has_errors() const { return error_count_ > 0; }
    uint32 error_count() const { return error_count_; }
    uint32 warning_count() const { return warning_count_; }

    const rawrstd::Vector<Diagnostic>& diagnostics() const { return diagnostics_; }

    // Renders the accumulated diagnostics to text (for a log or a receipt).
    String render() const;

    // Writes the accumulated diagnostics to stderr in human-readable form.
    void print_to_stderr() const;

    // Suppresses further output (used when emitting machine-readable output).
    void set_suppressed(bool v) { suppressed_ = v; }

    void reset() {
        diagnostics_.clear();
        error_count_ = 0;
        warning_count_ = 0;
    }

    // Caps the number of reported errors so a pathological file does not
    // produce a megabyte of output.
    static constexpr uint32 kMaxErrors = 200;

private:
    void print_one(const Diagnostic& d);

    SourceManager* sources_ = nullptr;
    rawrstd::Vector<Diagnostic> diagnostics_;
    uint32 error_count_ = 0;
    uint32 warning_count_ = 0;
    bool suppressed_ = false;
};

} // namespace rawr

#endif // RAWR_COMPILER_DIAGNOSTICS_H
