#include "common/Diagnostics.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;

static const char* severity_name(DiagnosticSeverity s) {
    switch (s) {
    case DiagnosticSeverity::Note:    return "note";
    case DiagnosticSeverity::Warning: return "warning";
    case DiagnosticSeverity::Error:   return "error";
    case DiagnosticSeverity::Fatal:   return "fatal error";
    }
    return "error";
}

void DiagnosticEngine::report(DiagnosticSeverity severity, const SourceLoc& loc,
                               const char* code, const String& message) {
    if (severity == DiagnosticSeverity::Error || severity == DiagnosticSeverity::Fatal) {
        if (error_count_ >= kMaxErrors) return;
        ++error_count_;
    } else if (severity == DiagnosticSeverity::Warning) {
        ++warning_count_;
    }

    Diagnostic d;
    d.severity = severity;
    d.message = message;
    d.loc = loc;
    d.code = code ? code : "";

    if (sources_ && loc.valid()) {
        const SourceFile& f = sources_->file(loc.file_id);
        d.file_path = f.path;
        uint32 line = 0, col = 0;
        sources_->locate(loc.file_id, loc.offset, &line, &col);
        d.line = line;
        d.column = col;
        d.source_line = sources_->line_text(loc.file_id, line);

        // Build the caret line: spaces up to the column, then '^'.
        for (uint32 i = 1; i < col; ++i) {
            d.caret_line.push_back(d.source_line[rawrstd::min_of<size_type>(i - 1, d.source_line.size())] == '\t' ? '\t' : ' ');
        }
        d.caret_line.push_back('^');
    }

    diagnostics_.push_back(d);

    if (!suppressed_) {
        print_one(d);
    }
}

void DiagnosticEngine::report_global(DiagnosticSeverity severity, const char* code,
                                      const String& message) {
    report(severity, SourceLoc(), code, message);
}

void DiagnosticEngine::print_one(const Diagnostic& d) {
    String out;
    if (d.loc.valid()) {
        out << d.file_path << "(" << d.line << "," << d.column << "): ";
    } else {
        out << "rawr: ";
    }
    out << severity_name(d.severity) << ": ";
    if (!d.code.empty()) out << "[" << d.code << "] ";
    out << d.message;
    out << "\n";

    if (!d.source_line.empty()) {
        out << "  " << d.source_line << "\n";
        out << "  " << d.caret_line << "\n";
    }

    rawrstd::write_stderr(out.data(), out.size());
}

String DiagnosticEngine::render() const {
    String out;
    for (size_type i = 0; i < diagnostics_.size(); ++i) {
        const Diagnostic& d = diagnostics_[i];
        if (d.loc.valid()) {
            out << d.file_path << "(" << d.line << "," << d.column << "): ";
        } else {
            out << "rawr: ";
        }
        out << severity_name(d.severity) << ": ";
        if (!d.code.empty()) out << "[" << d.code << "] ";
        out << d.message;
        out << "\n";
        if (!d.source_line.empty()) {
            out << "  " << d.source_line << "\n";
            out << "  " << d.caret_line << "\n";
        }
    }
    return out;
}

void DiagnosticEngine::print_to_stderr() const {
    String s = render();
    if (!s.empty()) rawrstd::write_stderr(s.data(), s.size());
}

} // namespace rawr
